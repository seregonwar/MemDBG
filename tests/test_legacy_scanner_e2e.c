/*
 * memDBG - E2E test: legacy ps5debug scanner bridge.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tests the scanner bridge through the legacy ps5debug wire protocol
 * (port 744, magic 0xFFAABBCC, bitswapped status words).
 *
 * Covers:
 *   1. Exact value scan (CMD_SCAN 0xBDAA0009)
 *   2. AOB pattern scan (CMD_SCAN_AOB 0xBDAACC01)
 *   3. Turboscan multi-chunk continuation (CMD_SCAN_CONT 0xBDAACC02)
 *   4. Empty results (scan for a value that doesn't exist)
 *
 * On hosts where kernel scanning (pid=-1) is not available, the scanner
 * bridge returns CMD_ERROR — the test gracefully accepts this and skips.
 *
 * Prerequisites: a MemDBG daemon running with --legacy-compat.
 * Usage: test_legacy_scanner_e2e <host> <legacy_port>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ---- Legacy ps5debug wire constants (mirrors compat_internal.h) ---- */

#define LEGACY_PACKET_MAGIC   0xFFAABBCCU
#define LEGACY_CMD_SUCCESS    0x40000000U
#define LEGACY_CMD_ERROR      0xF0000002U
#define LEGACY_CMD_DATA_NULL  0xF0000003U

#define LEGACY_CMD_SCAN       0xBDAA0009U
#define LEGACY_CMD_SCAN_AOB   0xBDAACC01U
#define LEGACY_CMD_SCAN_CONT  0xBDAACC02U

/* Scanner value types */
#define LEGACY_VALUE_U8      1U
#define LEGACY_VALUE_U32     3U
#define LEGACY_VALUE_U64     4U

/* ---- Bitswap (ps5debug status encoding, its own inverse) ---- */

static uint32_t bitswap32(uint32_t v) {
  return ((v >> 1) & 0x55555555U) | ((v << 1) & 0xAAAAAAAAU);
}

/* ---- Socket helpers ---- */

static int test_socket = -1;
static int test_verbose = 1;
static int scans_available = 1;  /* 0 = kernel scan not available on this host */

static int connect_legacy(const char *host, uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { perror("socket"); return -1; }

  struct timeval tv = { 10, 0 };
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(port);
  if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
    fprintf(stderr, "inet_pton failed\n"); close(fd); return -1;
  }
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("connect"); close(fd); return -1;
  }
  return fd;
}

static int read_all(void *buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t n = recv(test_socket, (uint8_t *)buf + total, len - total, 0);
    if (n <= 0) {
      if (n == 0 && test_verbose)
        fprintf(stderr, "  connection closed by peer\n");
      else if (n < 0 && test_verbose)
        perror("  recv");
      return -1;
    }
    total += (size_t)n;
  }
  return 0;
}

static int send_legacy_command(uint32_t command,
                               const void *body, uint32_t body_len) {
  uint32_t hdr[3];
  hdr[0] = LEGACY_PACKET_MAGIC;
  hdr[1] = command;
  hdr[2] = body_len;

  if (send(test_socket, hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr)) {
    perror("  send header"); return -1;
  }
  if (body_len > 0 &&
      send(test_socket, body, body_len, 0) != (ssize_t)body_len) {
    perror("  send body"); return -1;
  }
  return 0;
}

/* Read the first 4 bytes of a scanner response and classify them.
 * On success (chunk count): sets *count = raw value (0-4096), returns 0.
 * On error (bitswapped status): sets *status = de-bitswapped value, returns 1.
 * On protocol error: returns -1. */
static int read_scanner_first_word(uint32_t *status_or_count) {
  uint32_t raw = 0;
  if (read_all(&raw, sizeof(raw)) != 0) return -1;

  /* Chunk counts are 0..4096.  Bitswapped status words have the top bit set
   * (>= 0x80000000).  Everything in between is a protocol violation. */
  if (raw <= 4096U) {
    *status_or_count = raw;  /* it's a chunk count */
    return 0;
  }

  /* It's a bitswapped status word — de-bitswap it. */
  *status_or_count = bitswap32(raw);
  return 1;
}

/* Collect all scanner results after the first word has been validated as
 * a chunk count.  Issues CMD_SCAN_CONT for each full (4096) chunk.
 * Returns total addresses or UINT32_MAX on protocol error. */
static uint32_t collect_all_results(uint64_t **all_addrs, uint32_t first_count) {
  *all_addrs = NULL;
  uint64_t *buf = NULL;
  uint32_t total = 0U;
  uint32_t n = first_count;

  for (;;) {
    if (n == 0U) break;

    uint64_t *chunk = (uint64_t *)malloc((size_t)n * sizeof(uint64_t));
    if (chunk == NULL) { free(buf); return UINT32_MAX; }
    if (read_all(chunk, (size_t)n * sizeof(uint64_t)) != 0) {
      free(chunk); free(buf); return UINT32_MAX;
    }

    uint64_t *tmp = (uint64_t *)realloc(buf,
        (size_t)(total + n) * sizeof(uint64_t));
    if (tmp == NULL) { free(chunk); free(buf); return UINT32_MAX; }
    memcpy(tmp + total, chunk, (size_t)n * sizeof(uint64_t));
    free(chunk);
    buf = tmp;
    total += n;

    /* Full chunk — request next count via CONT.  Don't use read_scan_chunk
     * here because we only need the count (4 bytes); the addresses belong
     * to the next loop iteration. */
    if (n == 4096U) {
      if (send_legacy_command(LEGACY_CMD_SCAN_CONT, NULL, 0) != 0) {
        free(buf); return UINT32_MAX;
      }
      uint32_t next_count = 0;
      if (read_all(&next_count, sizeof(next_count)) != 0 ||
          next_count > 200000U) {
        free(buf); return UINT32_MAX;
      }
      n = next_count;
      continue;
    }

    /* Partial chunk — zero terminator follows. */
    uint32_t term = 0;
    if (read_all(&term, sizeof(term)) != 0 || term != 0U) {
      free(buf); return UINT32_MAX;
    }
    break;
  }

  *all_addrs = buf;
  return total;
}

/* ---- Test helpers ---- */

static int test_failed = 0;
static int test_passed = 0;
static int test_skipped = 0;

#define TEST(name, cond, ...) do {                               \
  if (!(cond)) {                                                 \
    fprintf(stderr, "FAIL: %s -- ", name);                       \
    fprintf(stderr, __VA_ARGS__);                                \
    fprintf(stderr, "\n");                                       \
    test_failed++;                                               \
  } else {                                                       \
    if (test_verbose) printf("  PASS: %s\n", name);              \
    test_passed++;                                               \
  }                                                              \
} while(0)

#define SKIP(name, ...) do {                                     \
  if (test_verbose) {                                            \
    printf("  SKIP: %s", name);                                  \
    printf(" -- " __VA_ARGS__);                                  \
    printf("\n");                                                \
  }                                                              \
  test_skipped++;                                                \
} while(0)

/* Build an exact-scan request body. Returns malloc'd buffer, sets *len. */
static uint8_t *build_exact_scan(uint8_t value_type, uint8_t value_length,
                                 uint8_t alignment,
                                 const uint8_t *value_bytes,
                                 uint64_t start, uint64_t end,
                                 uint32_t max_results, uint32_t *len) {
  uint32_t header_size = 28U;  /* sizeof(legacy_scan_request_t) */
  *len = header_size + value_length;
  uint8_t *buf = (uint8_t *)calloc(1, *len);
  if (buf == NULL) return NULL;

  buf[0] = value_type;
  buf[1] = value_length;
  buf[2] = alignment;
  memcpy(buf + 8,  &start, 8);
  memcpy(buf + 16, &end, 8);
  memcpy(buf + 24, &max_results, 4);
  if (value_length > 0U)
    memcpy(buf + header_size, value_bytes, value_length);
  return buf;
}

/* Build an AOB scan request body. */
static uint8_t *build_aob_scan(uint64_t start, uint64_t end,
                               const uint8_t *pattern, const uint8_t *mask,
                               uint32_t pat_len, uint32_t *len) {
  *len = 20U + pat_len * 2U;
  uint8_t *buf = (uint8_t *)malloc(*len);
  if (buf == NULL) return NULL;

  memcpy(buf,      &start, 8);
  memcpy(buf + 8,  &end, 8);
  memcpy(buf + 16, &pat_len, 4);
  memcpy(buf + 20, pattern, pat_len);
  memcpy(buf + 20 + pat_len, mask, pat_len);
  return buf;
}

/* Submit an exact scan and read the first-response word.
 * Returns: 0 = chunk count received, 1 = status (error), -1 = protocol error.
 * On success: *first_count contains the first chunk count.
 * On error: *status contains the de-bitswapped legacy status. */
static int submit_scan(uint32_t command, const void *body, uint32_t body_len,
                       uint32_t *first_or_status) {
  if (send_legacy_command(command, body, body_len) != 0) return -1;
  return read_scanner_first_word(first_or_status);
}

/* ---- Tests ---- */

static void test_exact_scan(void) {
  printf("--- Exact scan (CMD_SCAN) ---\n");

  uint32_t value = 0x00000000U;
  uint32_t body_len = 0;
  uint8_t *body = build_exact_scan(
      LEGACY_VALUE_U32, (uint8_t)sizeof(value), 0,
      (const uint8_t *)&value,
      0x0000000000000000ULL, 0x0000000000100000ULL,
      50000U, &body_len);

  TEST("build exact scan body", body != NULL, "malloc failed");
  if (body == NULL) return;

  uint32_t first = 0;
  int rc = submit_scan(LEGACY_CMD_SCAN, body, body_len, &first);
  free(body);

  TEST("scan response received", rc >= 0, "protocol error");
  if (rc < 0) return;

  if (rc == 1) {
    /* Server returned a status word — scan not available (expected on host). */
    TEST("scan error status is CMD_ERROR",
         first == LEGACY_CMD_ERROR || first == LEGACY_CMD_DATA_NULL,
         "expected CMD_ERROR(0xF0000002) or CMD_DATA_NULL(0xF0000003), got 0x%08X", first);
    SKIP("exact scan", "server returned error status (kernel scan not available on this host)");
    scans_available = 0;
    return;
  }

  /* First word is a chunk count — collect all results. */
  uint64_t *all_results = NULL;
  uint32_t total = collect_all_results(&all_results, first);

  TEST("scan chunks received", total != UINT32_MAX, "protocol error during chunk collection");
  if (total == UINT32_MAX) return;

  printf("  Exact scan returned %u total results\n", total);
  TEST("exact scan found results", total > 0U,
       "expected at least 1 null dword, got 0");

  if (total > 0U && test_verbose) {
    printf("  First 5 addresses:");
    for (uint32_t i = 0; i < total && i < 5U; i++)
      printf(" 0x%" PRIx64, all_results[i]);
    printf("\n");
  }
  free(all_results);
}

static void test_aob_scan(void) {
  printf("\n--- AOB scan (CMD_SCAN_AOB) ---\n");

  if (!scans_available) {
    SKIP("AOB scan", "kernel scans unavailable on this host");
    return;
  }

  const uint8_t pattern[] = "MemDBG";
  const uint8_t mask[]    = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint32_t pat_len = (uint32_t)(sizeof(pattern) - 1U);

  uint32_t body_len = 0;
  uint8_t *body = build_aob_scan(
      0x0000000000000000ULL, 0x0000000000200000ULL,
      pattern, mask, pat_len, &body_len);

  TEST("build AOB body", body != NULL, "malloc failed");
  if (body == NULL) return;

  uint32_t first = 0;
  int rc = submit_scan(LEGACY_CMD_SCAN_AOB, body, body_len, &first);
  free(body);

  TEST("AOB response received", rc >= 0, "protocol error");
  if (rc < 0) return;

  if (rc == 1) {
    SKIP("AOB scan results", "server returned error status 0x%08X", first);
    return;
  }

  uint64_t *all_results = NULL;
  uint32_t total = collect_all_results(&all_results, first);

  TEST("AOB chunks received", total != UINT32_MAX, "protocol error");
  if (total == UINT32_MAX) return;

  printf("  AOB scan for \"MemDBG\" returned %u results\n", total);
  TEST("AOB scan found results", total > 0U,
       "expected at least 1 match for 'MemDBG', got 0");

  if (total > 0U && test_verbose) {
    printf("  First 5 addresses:");
    for (uint32_t i = 0; i < total && i < 5U; i++)
      printf(" 0x%" PRIx64, all_results[i]);
    printf("\n");
  }
  free(all_results);
}

static void test_empty_results(void) {
  printf("\n--- Empty results scan ---\n");

  if (!scans_available) {
    SKIP("empty results scan", "kernel scans unavailable on this host");
    return;
  }

  uint64_t needle = 0xDEADBEEFCAFEBABEULL;
  uint32_t body_len = 0;
  uint8_t *body = build_exact_scan(
      LEGACY_VALUE_U64, (uint8_t)sizeof(needle), 0,
      (const uint8_t *)&needle,
      0x0000000000000000ULL, 0x0000000000001000ULL,
      100U, &body_len);

  TEST("build empty-scan body", body != NULL, "malloc failed");
  if (body == NULL) return;

  uint32_t first = 0;
  int rc = submit_scan(LEGACY_CMD_SCAN, body, body_len, &first);
  free(body);

  TEST("empty-scan response received", rc >= 0, "protocol error");
  if (rc < 0) return;

  if (rc == 1) {
    SKIP("empty scan", "server returned status 0x%08X", first);
    return;
  }

  /* First word should be 0 (zero terminator) for empty results. */
  uint64_t *all_results = NULL;
  uint32_t total = collect_all_results(&all_results, first);

  TEST("empty-scan chunks received", total != UINT32_MAX, "protocol error");
  if (total == UINT32_MAX) return;

  printf("  Empty scan returned %u results\n", total);
  TEST("empty scan returns zero results", total == 0U,
       "expected 0 results, got %u", total);

  /* CONT on exhausted session should return a zero terminator without error. */
  TEST("send CMD_SCAN_CONT on exhausted session",
       send_legacy_command(LEGACY_CMD_SCAN_CONT, NULL, 0) == 0,
       "CONT send failed");

  uint32_t cont_first = 0;
  rc = read_scanner_first_word(&cont_first);
  TEST("CONT response received", rc >= 0, "protocol error");
  if (rc == 0) {
    TEST("CONT on exhausted returns zero count",
         cont_first == 0U, "expected 0, got %u", cont_first);
  }
  free(all_results);
}

static void test_turboscan_multi_chunk(void) {
  printf("\n--- Turboscan multi-chunk scan ---\n");

  if (!scans_available) {
    SKIP("turboscan", "kernel scans unavailable on this host");
    return;
  }

  uint8_t zero = 0x00U;
  uint32_t body_len = 0;
  uint8_t *body = build_exact_scan(
      LEGACY_VALUE_U8, 1, 0, &zero,
      0x0000000000000000ULL, 0x0000000000100000ULL,
      200000U, &body_len);

  TEST("build turboscan body", body != NULL, "malloc failed");
  if (body == NULL) return;

  uint32_t first = 0;
  int rc = submit_scan(LEGACY_CMD_SCAN, body, body_len, &first);
  free(body);

  TEST("turboscan response received", rc >= 0, "protocol error");
  if (rc < 0) return;

  if (rc == 1) {
    SKIP("turboscan", "server returned status 0x%08X", first);
    return;
  }

  /* Manual chunk-by-chunk reading to verify CONT flow. */
  uint32_t total = 0U, chunk_count = 0U, cont_calls = 0U;
  uint32_t n = first;

  for (;;) {
    if (n == 0U) break;  /* zero terminator */
    chunk_count++;

    uint64_t *chunk = (uint64_t *)malloc((size_t)n * sizeof(uint64_t));
    if (chunk == NULL) { TEST("chunk malloc", 0, "OOM"); break; }
    if (read_all(chunk, (size_t)n * sizeof(uint64_t)) != 0) {
      free(chunk);
      TEST("chunk data read", 0, "read failed");
      break;
    }

    total += n;
    if (test_verbose)
      printf("  chunk %u: %u addresses (total: %u)\n", chunk_count, n, total);
    free(chunk);

    /* Full chunk — request next count via CONT (don't read addresses
     * here — they belong to the next loop iteration). */
    if (n == 4096U) {
      cont_calls++;
      TEST("send CONT #%u", send_legacy_command(LEGACY_CMD_SCAN_CONT, NULL, 0) == 0,
           "CONT send failed", cont_calls);
      uint32_t next_count = 0;
      if (read_all(&next_count, sizeof(next_count)) != 0 || next_count > 200000U) {
        TEST("CONT #%u read next count", 0, "read failed or bad count %u", cont_calls, next_count);
        break;
      }
      n = next_count;
      continue;
    }

    /* Partial chunk — zero terminator follows. */
    {
      uint32_t term = 0;
      if (read_all(&term, sizeof(term)) != 0)
        TEST("zero terminator read", 0, "read failed");
      else
        TEST("zero terminator", term == 0U, "expected 0, got %u", term);
    }
    break;
  }

  printf("  Turboscan: %u results, %u chunks, %u CONT calls\n",
         total, chunk_count, cont_calls);

  TEST("turboscan found results", total > 0U,
       "expected > 0, got %u", total);

  if (total >= 4096U && cont_calls == 0U)
    printf("  NOTE: %u results in one chunk; multi-chunk not exercised\n", total);
  else if (cont_calls > 0U)
    printf("  Multi-chunk exercised with %u CONT calls\n", cont_calls);
}

/* ---- Main ---- */

int main(int argc, char **argv) {
  const char *host = "127.0.0.1";
  uint16_t port    = 744;
  if (argc >= 2) host = argv[1];
  if (argc >= 3) port = (uint16_t)atoi(argv[2]);

  printf("=== Legacy Scanner E2E test ===\n");
  printf("Connecting to %s:%u...\n", host, port);

  test_socket = connect_legacy(host, port);
  if (test_socket < 0) {
    printf("FAIL: cannot connect to legacy port — is daemon running with --legacy-compat?\n");
    return 1;
  }
  printf("  connected\n\n");

  test_exact_scan();
  test_aob_scan();
  test_empty_results();
  test_turboscan_multi_chunk();

  close(test_socket);

  printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
         test_passed, test_failed, test_skipped);
  return test_failed > 0 ? 1 : 0;
}
