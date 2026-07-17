/*
 * memDBG - E2E test: legacy ps5debug process, memory, and metadata commands.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tests the legacy ps5debug wire protocol (port 744, magic 0xFFAABBCC,
 * bitswapped status words) for:
 *   1. Metadata: VERSION, BRANDING, PLATFORM_ID, FW_VERSION, PROC_NOP, PROC_AUTH
 *   2. Process: PROC_LIST, PROC_MAPS, PROC_INFO, PROC_INSTALL, PROC_FIRST_MAP
 *   3. Memory: PROC_READ, PROC_WRITE, PROC_WRITE_MULTI
 *   4. Memory mgmt: PROC_ALLOC, PROC_ALLOC_HINTED, PROC_FREE, PROC_PROTECT
 *
 * Prerequisites: a MemDBG daemon running with --legacy-compat.
 * Usage: test_legacy_process_e2e <host> <legacy_port>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ---- Legacy ps5debug wire constants ---- */

#define LEGACY_PACKET_MAGIC   0xFFAABBCCU
#define LEGACY_CMD_SUCCESS    0x40000000U
#define LEGACY_CMD_ERROR      0xF0000002U
#define LEGACY_CMD_DATA_NULL  0xF0000003U

#define LEGACY_CMD_VERSION       0xBD000001U
#define LEGACY_CMD_FW_VERSION    0xBD000500U
#define LEGACY_CMD_BRANDING      0xBD000501U
#define LEGACY_CMD_PLATFORM_ID   0xBD000502U
#define LEGACY_CMD_PROC_NOP      0xBDAACC06U
#define LEGACY_CMD_PROC_AUTH     0xBDAACCFFU
#define LEGACY_CMD_PROC_LIST     0xBDAA0001U
#define LEGACY_CMD_PROC_READ     0xBDAA0002U
#define LEGACY_CMD_PROC_WRITE    0xBDAA0003U
#define LEGACY_CMD_PROC_MAPS     0xBDAA0004U
#define LEGACY_CMD_PROC_INSTALL  0xBDAA0005U
#define LEGACY_CMD_PROC_PROTECT  0xBDAA0008U
#define LEGACY_CMD_PROC_INFO     0xBDAA000AU
#define LEGACY_CMD_PROC_ALLOC    0xBDAA000BU
#define LEGACY_CMD_PROC_FREE     0xBDAA000CU
#define LEGACY_CMD_PROC_FIRST_MAP 0xBDAA000DU
#define LEGACY_CMD_PROC_ALLOC_HINTED 0xBDAA000EU
#define LEGACY_CMD_PROC_WRITE_MULTI  0xBDAACC04U

/* ---- Bitswap (ps5debug status encoding, its own inverse) ---- */

static uint32_t bitswap32(uint32_t v) {
  return ((v >> 1) & 0x55555555U) | ((v << 1) & 0xAAAAAAAAU);
}

/* ---- Socket helpers ---- */

static int test_socket = -1;
static int test_verbose = 1;
static int test_failed = 0;
static int test_passed = 0;
static int test_skipped = 0;

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
      if (n == 0 && test_verbose) fprintf(stderr, "  connection closed by peer\n");
      else if (n < 0 && test_verbose) perror("  recv");
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

/* Read a bitswapped status word, return the de-bitswapped value. */
static int read_legacy_status(uint32_t *status) {
  uint32_t raw = 0;
  if (read_all(&raw, sizeof(raw)) != 0) return -1;
  *status = bitswap32(raw);
  return 0;
}

/* Send a command and read the legacy status response. */
static int send_and_check_status(uint32_t command,
                                 const void *body, uint32_t body_len,
                                 uint32_t *status) {
  if (send_legacy_command(command, body, body_len) != 0) return -1;
  return read_legacy_status(status);
}

/* ---- Test macros ---- */

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

/* ---- Wire structs (mirrors legacy wire format) ---- */

typedef struct {
  char name[32];
  int32_t pid;
} legacy_proc_list_entry_t;

typedef struct {
  char name[32];
  uint64_t start;
  uint64_t end;
  uint64_t offset;
  uint16_t protection;
} legacy_proc_maps_entry_t;

typedef struct {
  uint32_t pid;
} legacy_proc_info_packet_t;

typedef struct {
  uint32_t pid;
  uint64_t address;
  uint32_t length;
} legacy_memory_packet_t;

typedef struct {
  uint32_t pid;
  uint32_t length;
} legacy_proc_alloc_packet_t;

typedef struct {
  uint32_t pid;
  uint64_t hint;
  uint32_t length;
} legacy_proc_alloc_hinted_packet_t;

typedef struct {
  uint64_t address;
} legacy_proc_alloc_response_t;

typedef struct {
  uint32_t pid;
  uint64_t address;
  uint32_t length;
} legacy_proc_free_packet_t;

typedef struct {
  uint32_t pid;
  uint64_t address;
  uint32_t length;
  uint32_t protection;
} legacy_proc_protect_packet_t;

typedef struct {
  uint32_t pid;
  uint32_t count;
  uint32_t flags;
} legacy_proc_write_multi_packet_t;

typedef struct {
  uint64_t address;
  uint32_t length;
} legacy_proc_write_multi_entry_t;

/* ---- Helper: find process maps for a PID and pick a readable region ---- */

static int32_t first_valid_pid = -1;
static uint64_t first_readable_addr = 0;
static uint64_t first_readable_size = 0;

static int discover_test_process(void) {
  /* Get process list */
  uint32_t status = 0;
  if (send_and_check_status(LEGACY_CMD_PROC_LIST, NULL, 0, &status) != 0)
    return -1;
  if (status != LEGACY_CMD_SUCCESS) return -1;

  /* Next word is the process count */
  uint32_t count = 0;
  if (read_all(&count, 4) != 0) return -1;
  if (count == 0 || count > 10000) return -1;

  legacy_proc_list_entry_t *entries =
      (legacy_proc_list_entry_t *)malloc(count * sizeof(*entries));
  if (entries == NULL) return -1;
  if (read_all(entries, count * sizeof(*entries)) != 0) {
    free(entries); return -1;
  }

  /* Pick the first PID */
  first_valid_pid = entries[0].pid;
  free(entries);

  if (test_verbose)
    printf("  Discovered PID %d from process list\n", first_valid_pid);

  /* Try to get process maps (may fail on macOS without entitlements) */
  legacy_proc_info_packet_t info_req = { (uint32_t)first_valid_pid };
  uint32_t pstatus = 0;
  if (send_and_check_status(LEGACY_CMD_PROC_MAPS,
        &info_req, sizeof(info_req), &pstatus) == 0 && pstatus == LEGACY_CMD_SUCCESS) {
    uint32_t mcount = 0;
    if (read_all(&mcount, 4) == 0 && mcount > 0 && mcount <= 50000) {
      legacy_proc_maps_entry_t *maps =
          (legacy_proc_maps_entry_t *)malloc(mcount * sizeof(*maps));
      if (maps != NULL) {
        if (read_all(maps, mcount * sizeof(*maps)) == 0) {
          /* Pick the first readable region */
          for (uint32_t i = 0; i < mcount; i++) {
            if ((maps[i].protection & 1U) != 0U && maps[i].end > maps[i].start) {
              first_readable_addr = maps[i].start;
              first_readable_size = (uint32_t)(maps[i].end - maps[i].start);
              if (first_readable_size > 4096U) first_readable_size = 4096U;
              break;
            }
          }
        }
        free(maps);
      }
    }
  }

  /* Fallback: try FIRST_MAP to get a valid address */
  if (first_readable_addr == 0) {
    uint32_t fstatus = 0;
    if (send_and_check_status(LEGACY_CMD_PROC_FIRST_MAP,
          &info_req, sizeof(info_req), &fstatus) == 0 && fstatus == LEGACY_CMD_SUCCESS) {
      int64_t first = 0;
      if (read_all(&first, 8) == 0 && first > 0) {
        first_readable_addr = (uint64_t)first;
        first_readable_size = 4096U;
      }
    }
  }

  if (test_verbose) {
    if (first_readable_addr != 0)
      printf("  Discovered readable region: 0x%" PRIx64 " size %" PRIu64 "\n",
             first_readable_addr, first_readable_size);
    else
      printf("  No readable region discovered (may need entitlements)\n");
  }

  /* Success: we at least have a valid PID */
  return 0;
}

/* ---- Test: Metadata commands ---- */

static void test_metadata(void) {
  printf("--- Metadata commands ---\n");

  /* CMD_VERSION: should return length-prefixed "1.3" */
  {
    if (send_legacy_command(LEGACY_CMD_VERSION, NULL, 0) != 0) return;
    uint32_t len = 0;
    TEST("VERSION: read length", read_all(&len, 4) == 0, "read failed");
    TEST("VERSION: length is 3", len == 3U, "got %u", len);
    char ver[4] = {0};
    if (len <= 4 && read_all(ver, len) == 0) {
      TEST("VERSION: string is \"1.3\"",
           memcmp(ver, "1.3", 3) == 0, "got \"%.3s\"", ver);
    }
  }

  /* CMD_BRANDING: should return "MemDBG legacy-compat\0MDBG-1" */
  {
    if (send_legacy_command(LEGACY_CMD_BRANDING, NULL, 0) != 0) return;
    uint32_t len = 0;
    TEST("BRANDING: read length", read_all(&len, 4) == 0, "read failed");
    TEST("BRANDING: length > 3", len > 3U, "got %u", len);
    char *brand = (char *)malloc(len + 1);
    if (brand != NULL && read_all(brand, len) == 0) {
      brand[len] = '\0';
      TEST("BRANDING: contains MemDBG",
           strstr(brand, "MemDBG") != NULL, "got \"%s\"", brand);
      /* Verify capability suffix after first NUL */
      int has_nul = 0;
      for (uint32_t i = 0; i < len; i++) { if (brand[i] == '\0') { has_nul = 1; break; } }
      TEST("BRANDING: has capability suffix after NUL", has_nul,
           "no NUL byte found in %u bytes", len);
    }
    free(brand);
  }

  /* CMD_PLATFORM_ID: returns uint16 (5=PS5, 4=PS4, 0=host) */
  {
    if (send_legacy_command(LEGACY_CMD_PLATFORM_ID, NULL, 0) != 0) return;
    uint16_t platform = 0;
    TEST("PLATFORM_ID: read response", read_all(&platform, 2) == 0, "read failed");
    /* On host we expect 0, but accept any valid value */
    TEST("PLATFORM_ID: valid value (0,4,5)",
         platform == 0 || platform == 4 || platform == 5,
         "got %u", (unsigned)platform);
    if (test_verbose)
      printf("  Platform ID: %u (0=host, 4=PS4, 5=PS5)\n", (unsigned)platform);
  }

  /* CMD_FW_VERSION: returns uint16 */
  {
    if (send_legacy_command(LEGACY_CMD_FW_VERSION, NULL, 0) != 0) return;
    uint16_t fw = 0xFFFF;
    TEST("FW_VERSION: read response", read_all(&fw, 2) == 0, "read failed");
    TEST("FW_VERSION: valid (0 on host)", fw == 0U || fw != 0xFFFFU,
         "got %u", (unsigned)fw);
    if (test_verbose)
      printf("  FW version: %u\n", (unsigned)fw);
  }

  /* CMD_PROC_NOP: should return CMD_SUCCESS */
  {
    uint32_t status = 0;
    TEST("PROC_NOP: send", send_and_check_status(LEGACY_CMD_PROC_NOP,
          NULL, 0, &status) == 0, "send failed");
    TEST("PROC_NOP: success status",
         status == LEGACY_CMD_SUCCESS, "got 0x%08X", status);
  }

  /* CMD_PROC_AUTH: should return CMD_SUCCESS */
  {
    uint32_t status = 0;
    TEST("PROC_AUTH: send", send_and_check_status(LEGACY_CMD_PROC_AUTH,
          NULL, 0, &status) == 0, "send failed");
    TEST("PROC_AUTH: success status",
         status == LEGACY_CMD_SUCCESS, "got 0x%08X", status);
  }
}

/* ---- Test: Process commands ---- */

static void test_process_commands(void) {
  printf("\n--- Process commands ---\n");

  /* CMD_PROC_LIST */
  {
    uint32_t status = 0;
    TEST("PROC_LIST: send", send_and_check_status(LEGACY_CMD_PROC_LIST,
          NULL, 0, &status) == 0, "send failed");
    TEST("PROC_LIST: success status",
         status == LEGACY_CMD_SUCCESS, "got 0x%08X", status);

    uint32_t count = 0;
    if (status == LEGACY_CMD_SUCCESS) {
      TEST("PROC_LIST: read count", read_all(&count, 4) == 0, "read failed");
      TEST("PROC_LIST: count > 0", count > 0U, "got %u", count);

      if (count > 0) {
        legacy_proc_list_entry_t *entries =
            (legacy_proc_list_entry_t *)malloc(count * sizeof(*entries));
        if (entries != NULL && read_all(entries, count * sizeof(*entries)) == 0) {
          /* Verify entries look reasonable */
          int valid_entries = 0;
          for (uint32_t i = 0; i < count && i < 10; i++) {
            if (entries[i].pid > 0 && entries[i].name[0] != '\0')
              valid_entries++;
          }
          TEST("PROC_LIST: entries look valid",
               valid_entries > 0, "no valid entries in first 10");
          if (test_verbose)
            printf("  Process list: %u processes, first PID=%d name=%s\n",
                   count, entries[0].pid, entries[0].name);
        }
        free(entries);
      }
    }
  }

  /* CMD_PROC_INFO for a known PID */
  if (first_valid_pid > 0) {
    legacy_proc_info_packet_t req = { (uint32_t)first_valid_pid };
    uint32_t status = 0;
    TEST("PROC_INFO: send", send_and_check_status(LEGACY_CMD_PROC_INFO,
          &req, sizeof(req), &status) == 0, "send failed");
    if (status != LEGACY_CMD_SUCCESS) {
      SKIP("PROC_INFO", "daemon returned 0x%08X (expected on restricted host)", status);
    } else {
      /* Response: {uint32 pid, char name[40], char path[64],
       *             char title_id[16], char content_id[64]} = 188 bytes */
      uint8_t info_buf[188];
      TEST("PROC_INFO: read response",
           read_all(info_buf, 188) == 0, "read failed");
      uint32_t pid;
      memcpy(&pid, info_buf, 4);
      TEST("PROC_INFO: PID matches", pid == (uint32_t)first_valid_pid,
           "got %u", pid);
    }
  } else {
    SKIP("PROC_INFO", "no valid PID discovered");
  }

  /* CMD_PROC_MAPS for a known PID */
  if (first_valid_pid > 0) {
    legacy_proc_info_packet_t req = { (uint32_t)first_valid_pid };
    uint32_t status = 0;
    TEST("PROC_MAPS: send", send_and_check_status(LEGACY_CMD_PROC_MAPS,
          &req, sizeof(req), &status) == 0, "send failed");
    if (status != LEGACY_CMD_SUCCESS) {
      SKIP("PROC_MAPS", "daemon returned 0x%08X (expected on restricted host)", status);
    } else {
      uint32_t count = 0;
      TEST("PROC_MAPS: read count", read_all(&count, 4) == 0, "read failed");
      TEST("PROC_MAPS: count > 0", count > 0U, "got %u", count);

      if (count > 0 && count <= 10000) {
        legacy_proc_maps_entry_t *maps =
            (legacy_proc_maps_entry_t *)malloc(count * sizeof(*maps));
        if (maps != NULL && read_all(maps, count * sizeof(*maps)) == 0) {
          /* Verify maps look reasonable */
          int valid = 0;
          for (uint32_t i = 0; i < count && i < 10; i++) {
            if (maps[i].start < maps[i].end && maps[i].end > maps[i].start)
              valid++;
          }
          TEST("PROC_MAPS: entries look valid", valid > 0,
               "no valid maps in first 10");
          if (test_verbose)
            printf("  Process maps: %u entries, first: 0x%" PRIx64 "-0x%" PRIx64 " prot=0x%x\n",
                   count, maps[0].start, maps[0].end, (unsigned)maps[0].protection);
        }
        free(maps);
      }
    }
  } else {
    SKIP("PROC_MAPS", "no valid PID discovered");
  }

  /* CMD_PROC_FIRST_MAP */
  if (first_valid_pid > 0) {
    legacy_proc_info_packet_t req = { (uint32_t)first_valid_pid };
    uint32_t status = 0;
    TEST("PROC_FIRST_MAP: send", send_and_check_status(
          LEGACY_CMD_PROC_FIRST_MAP, &req, sizeof(req), &status) == 0,
          "send failed");
    if (status != LEGACY_CMD_SUCCESS) {
      SKIP("PROC_FIRST_MAP", "daemon returned 0x%08X (expected on restricted host)", status);
    } else {
      int64_t first = 0;
      TEST("PROC_FIRST_MAP: read address",
           read_all(&first, 8) == 0, "read failed");
      TEST("PROC_FIRST_MAP: address > 0", first > 0, "got %" PRId64, first);
    }
  } else {
    SKIP("PROC_FIRST_MAP", "no valid PID discovered");
  }

  /* CMD_PROC_INSTALL: should return success + zero RPC stub */
  {
    uint32_t status = 0;
    TEST("PROC_INSTALL: send", send_and_check_status(LEGACY_CMD_PROC_INSTALL,
          NULL, 0, &status) == 0, "send failed");
    TEST("PROC_INSTALL: success status",
         status == LEGACY_CMD_SUCCESS, "got 0x%08X", status);

    if (status == LEGACY_CMD_SUCCESS) {
      uint64_t rpc_stub = 0;
      TEST("PROC_INSTALL: read RPC stub",
           read_all(&rpc_stub, 8) == 0, "read failed");
      TEST("PROC_INSTALL: RPC stub is zero",
           rpc_stub == 0ULL, "got 0x%" PRIx64, rpc_stub);
    }
  }
}

/* ---- Test: Memory commands ---- */

static void test_memory_commands(void) {
  printf("\n--- Memory commands ---\n");

  if (first_valid_pid <= 0) {
    SKIP("memory tests", "no valid PID discovered");
    return;
  }

  /* PROC_READ: read from a known readable memory region */
  if (first_readable_addr == 0) {
    SKIP("PROC_READ", "no readable region discovered");
  } else {
    legacy_memory_packet_t req;
    req.pid     = (uint32_t)first_valid_pid;
    req.address = first_readable_addr;
    req.length  = 64U; /* read 64 bytes */

    uint32_t status = 0;
    TEST("PROC_READ: send", send_and_check_status(LEGACY_CMD_PROC_READ,
          &req, sizeof(req), &status) == 0, "send failed");
    if (status != LEGACY_CMD_SUCCESS) {
      SKIP("PROC_READ", "daemon returned 0x%08X (expected on restricted host)", status);
    } else {
      uint8_t data[64];
      TEST("PROC_READ: read data", read_all(data, 64) == 0, "read failed");
      /* Verify it's not all zeros or all FFs — should be real code/data */
      int non_zero = 0;
      for (int i = 0; i < 64; i++) { if (data[i] != 0x00 && data[i] != 0xFF) non_zero++; }
      TEST("PROC_READ: data looks real", non_zero > 0,
           "all bytes are 0x00 or 0xFF");
      if (test_verbose) {
        printf("  PROC_READ first 16 bytes:");
        for (int i = 0; i < 16; i++) printf(" %02x", data[i]);
        printf("\n");
      }
    }
  }

  /* PROC_ALLOC: allocate writable/executable memory */
  {
    legacy_proc_alloc_packet_t req;
    req.pid    = (uint32_t)first_valid_pid;
    req.length = 4096U; /* one page */

    uint32_t status = 0;
    TEST("PROC_ALLOC: send", send_and_check_status(LEGACY_CMD_PROC_ALLOC,
          &req, sizeof(req), &status) == 0, "send failed");
    if (status != LEGACY_CMD_SUCCESS) {
      SKIP("PROC_ALLOC + read/write/protect/free",
           "daemon returned 0x%08X (expected on restricted host)", status);
    } else {
      legacy_proc_alloc_response_t resp;
      memset(&resp, 0, sizeof(resp));
      TEST("PROC_ALLOC: read address",
           read_all(&resp, sizeof(resp)) == 0, "read failed");
      TEST("PROC_ALLOC: address > 0",
           resp.address > 0ULL, "got 0x%" PRIx64, resp.address);

      if (resp.address > 0) {
        uint64_t alloc_addr = resp.address;

        /* PROC_WRITE: write to the allocated memory */
        {
          legacy_memory_packet_t wreq;
          wreq.pid     = (uint32_t)first_valid_pid;
          wreq.address = alloc_addr;
          wreq.length  = 8U;

          if (send_and_check_status(LEGACY_CMD_PROC_WRITE,
                &wreq, sizeof(wreq), &status) != 0) return;
          TEST("PROC_WRITE: ack status",
               status == LEGACY_CMD_SUCCESS, "got 0x%08X", status);

          if (status == LEGACY_CMD_SUCCESS) {
            uint64_t test_val = 0xDEADBEEFCAFEBABEULL;
            TEST("PROC_WRITE: send data",
                 send(test_socket, &test_val, 8, 0) == 8, "send failed");

            uint32_t final_status = 0;
            TEST("PROC_WRITE: final status",
                 read_legacy_status(&final_status) == 0, "read failed");
            TEST("PROC_WRITE: final status success",
                 final_status == LEGACY_CMD_SUCCESS,
                 "got 0x%08X", final_status);

            /* Read back what we wrote */
            legacy_memory_packet_t rreq;
            rreq.pid     = (uint32_t)first_valid_pid;
            rreq.address = alloc_addr;
            rreq.length  = 8U;

            if (send_and_check_status(LEGACY_CMD_PROC_READ,
                  &rreq, sizeof(rreq), &status) != 0) return;
            if (status == LEGACY_CMD_SUCCESS) {
              uint64_t readback = 0;
              if (read_all(&readback, 8) == 0) {
                TEST("PROC_READ/WRITE roundtrip",
                     readback == test_val,
                     "wrote 0x%" PRIx64 ", read 0x%" PRIx64,
                     test_val, readback);
              }
            }
          }
        }

        /* PROC_PROTECT: change protection on allocated memory */
        {
          legacy_proc_protect_packet_t preq;
          preq.pid        = (uint32_t)first_valid_pid;
          preq.address    = alloc_addr;
          preq.length     = 4096U;
          preq.protection = 1U; /* read-only */

          uint32_t pstatus = 0;
          TEST("PROC_PROTECT: send",
               send_and_check_status(LEGACY_CMD_PROC_PROTECT,
                 &preq, sizeof(preq), &pstatus) == 0, "send failed");
          TEST("PROC_PROTECT: success status",
               pstatus == LEGACY_CMD_SUCCESS, "got 0x%08X", pstatus);
        }

        /* PROC_FREE: free the allocated memory */
        {
          legacy_proc_free_packet_t freq;
          freq.pid     = (uint32_t)first_valid_pid;
          freq.address = alloc_addr;
          freq.length  = 4096U;

          uint32_t fstatus = 0;
          TEST("PROC_FREE: send",
               send_and_check_status(LEGACY_CMD_PROC_FREE,
                 &freq, sizeof(freq), &fstatus) == 0, "send failed");
          TEST("PROC_FREE: success status",
               fstatus == LEGACY_CMD_SUCCESS, "got 0x%08X", fstatus);
        }
      }
    }
  }

  /* PROC_ALLOC_HINTED: allocate with a hint address */
  {
    legacy_proc_alloc_hinted_packet_t req;
    req.pid    = (uint32_t)first_valid_pid;
    req.hint   = 0ULL; /* no hint, but use the hinted path */
    req.length = 4096U;

    uint32_t status = 0;
    TEST("PROC_ALLOC_HINTED: send",
         send_and_check_status(LEGACY_CMD_PROC_ALLOC_HINTED,
           &req, sizeof(req), &status) == 0, "send failed");
    if (status != LEGACY_CMD_SUCCESS) {
      SKIP("PROC_ALLOC_HINTED + free",
           "daemon returned 0x%08X (expected on restricted host)", status);
    } else {
      legacy_proc_alloc_response_t resp;
      memset(&resp, 0, sizeof(resp));
      TEST("PROC_ALLOC_HINTED: read response",
           read_all(&resp, sizeof(resp)) == 0, "read failed");
      TEST("PROC_ALLOC_HINTED: address > 0",
           resp.address > 0ULL, "got 0x%" PRIx64, resp.address);

      if (resp.address > 0) {
        /* Free it */
        legacy_proc_free_packet_t freq;
        freq.pid     = (uint32_t)first_valid_pid;
        freq.address = resp.address;
        freq.length  = 4096U;
        uint32_t fstatus = 0;
        send_and_check_status(LEGACY_CMD_PROC_FREE,
            &freq, sizeof(freq), &fstatus);
      }
    }
  }

  /* PROC_WRITE_MULTI: write multiple regions at once */
  {
    /* Allocate memory first */
    legacy_proc_alloc_packet_t areq;
    areq.pid    = (uint32_t)first_valid_pid;
    areq.length = 4096U;

    uint32_t astatus = 0;
    if (send_and_check_status(LEGACY_CMD_PROC_ALLOC,
          &areq, sizeof(areq), &astatus) != 0) return;
    if (astatus != LEGACY_CMD_SUCCESS) {
      SKIP("PROC_WRITE_MULTI", "alloc failed (status 0x%08X)", astatus);
      return;
    }

    legacy_proc_alloc_response_t aresp;
    if (read_all(&aresp, sizeof(aresp)) != 0) return;
    uint64_t alloc_addr = aresp.address;

    /* Build write-multi request: 2 entries */
    uint32_t flags = 1U; /* request per-entry status */
    legacy_proc_write_multi_packet_t wmreq;
    wmreq.pid   = (uint32_t)first_valid_pid;
    wmreq.count = 2U;
    wmreq.flags = flags;

    if (send_legacy_command(LEGACY_CMD_PROC_WRITE_MULTI,
          &wmreq, sizeof(wmreq)) != 0) return;

    uint32_t wmstatus = 0;
    TEST("PROC_WRITE_MULTI: ack", read_legacy_status(&wmstatus) == 0,
         "read failed");
    TEST("PROC_WRITE_MULTI: ack status",
         wmstatus == LEGACY_CMD_SUCCESS, "got 0x%08X", wmstatus);

    if (wmstatus == LEGACY_CMD_SUCCESS) {
      /* Entry 1 */
      legacy_proc_write_multi_entry_t e1;
      e1.address = alloc_addr;
      e1.length  = 4U;
      uint32_t v1 = 0xCAFEBABE;

      if (send(test_socket, &e1, sizeof(e1), 0) != (ssize_t)sizeof(e1))
        return;
      if (send(test_socket, &v1, 4, 0) != 4) return;

      /* Entry 2 */
      legacy_proc_write_multi_entry_t e2;
      e2.address = alloc_addr + 8;
      e2.length  = 4U;
      uint32_t v2 = 0xDEADBEEF;

      if (send(test_socket, &e2, sizeof(e2), 0) != (ssize_t)sizeof(e2))
        return;
      if (send(test_socket, &v2, 4, 0) != 4) return;

      /* Read per-entry status bytes */
      uint8_t status_bytes[2];
      TEST("PROC_WRITE_MULTI: read status bytes",
           read_all(status_bytes, 2) == 0, "read failed");
      TEST("PROC_WRITE_MULTI: entry 0 ok", status_bytes[0] == 0,
           "status=%u", (unsigned)status_bytes[0]);
      TEST("PROC_WRITE_MULTI: entry 1 ok", status_bytes[1] == 0,
           "status=%u", (unsigned)status_bytes[1]);

      /* Final status */
      uint32_t final_status = 0;
      TEST("PROC_WRITE_MULTI: final status",
           read_legacy_status(&final_status) == 0, "read failed");
      TEST("PROC_WRITE_MULTI: final success",
           final_status == LEGACY_CMD_SUCCESS, "got 0x%08X", final_status);

      /* Read back both values */
      legacy_memory_packet_t rreq;
      rreq.pid     = (uint32_t)first_valid_pid;
      rreq.address = alloc_addr;
      rreq.length  = 16U;

      uint32_t rstatus = 0;
      if (send_and_check_status(LEGACY_CMD_PROC_READ,
            &rreq, sizeof(rreq), &rstatus) == 0 && rstatus == LEGACY_CMD_SUCCESS) {
        uint8_t data[16];
        if (read_all(data, 16) == 0) {
          uint32_t rv1, rv2;
          memcpy(&rv1, data, 4);
          memcpy(&rv2, data + 8, 4);
          TEST("PROC_WRITE_MULTI: readback entry 0",
               rv1 == v1, "wrote 0x%08X, read 0x%08X", v1, rv1);
          TEST("PROC_WRITE_MULTI: readback entry 1",
               rv2 == v2, "wrote 0x%08X, read 0x%08X", v2, rv2);
        }
      }
    }

    /* Cleanup: free allocated memory */
    {
      legacy_proc_free_packet_t freq;
      freq.pid     = (uint32_t)first_valid_pid;
      freq.address = alloc_addr;
      freq.length  = 4096U;
      uint32_t fstatus = 0;
      send_and_check_status(LEGACY_CMD_PROC_FREE, &freq, sizeof(freq), &fstatus);
    }
  }
}

/* ---- Test: Error handling ---- */

static void test_error_handling(void) {
  printf("\n--- Error handling ---\n");

  /* Invalid command */
  uint32_t status = 0;
  TEST("bad command: send", send_and_check_status(0xDEADBEEFU,
        NULL, 0, &status) == 0, "send failed");
  TEST("bad command: error status",
       status == LEGACY_CMD_ERROR, "got 0x%08X", status);

  /* Bad magic */
  {
    uint32_t bad_hdr[3] = { 0x12345678U, LEGACY_CMD_PROC_NOP, 0U };
    if (send(test_socket, bad_hdr, sizeof(bad_hdr), 0) == (ssize_t)sizeof(bad_hdr)) {
      uint32_t estatus = 0;
      TEST("bad magic: status", read_legacy_status(&estatus) == 0,
           "read failed or connection closed");
      if (read_legacy_status(&estatus) == 0)
        TEST("bad magic: error status",
             estatus == LEGACY_CMD_ERROR, "got 0x%08X", estatus);
    } else {
      /* Connection was closed — that's also acceptable behavior */
      SKIP("bad magic", "connection closed by server (acceptable)");
    }
  }

  /* PROC_READ with invalid PID */
  {
    legacy_memory_packet_t req;
    req.pid     = (uint32_t)-999;
    req.address = 0x1000;
    req.length  = 4U;

    uint32_t estatus = 0;
    if (send_and_check_status(LEGACY_CMD_PROC_READ,
          &req, sizeof(req), &estatus) == 0) {
      TEST("bad PID read: error status",
           estatus != LEGACY_CMD_SUCCESS, "unexpected success");
    }
  }

  /* PROC_ALLOC with PID=0 */
  {
    legacy_proc_alloc_packet_t req;
    req.pid    = 0U;
    req.length = 4096U;

    uint32_t estatus = 0;
    if (send_and_check_status(LEGACY_CMD_PROC_ALLOC,
          &req, sizeof(req), &estatus) == 0) {
      TEST("zero PID alloc: error status",
           estatus != LEGACY_CMD_SUCCESS, "unexpected success");
    }
  }

  /* PROC_FREE with PID=0, address=0 */
  {
    legacy_proc_free_packet_t req;
    req.pid     = 0U;
    req.address = 0ULL;
    req.length  = 4096U;

    uint32_t estatus = 0;
    if (send_and_check_status(LEGACY_CMD_PROC_FREE,
          &req, sizeof(req), &estatus) == 0) {
      TEST("zero free: error status",
           estatus != LEGACY_CMD_SUCCESS, "got 0x%08X", estatus);
    }
  }
}

/* ---- Main ---- */

int main(int argc, char **argv) {
#ifdef SIGPIPE
  (void)signal(SIGPIPE, SIG_IGN);
#endif
  const char *host = "127.0.0.1";
  uint16_t port    = 744;
  if (argc >= 2) host = argv[1];
  if (argc >= 3) port = (uint16_t)atoi(argv[2]);

  printf("=== Legacy Process/Memory E2E test ===\n");
  printf("Connecting to %s:%u...\n", host, port);

  test_socket = connect_legacy(host, port);
  if (test_socket < 0) {
    printf("FAIL: cannot connect to legacy port — is daemon running with --legacy-compat?\n");
    return 1;
  }
  printf("  connected\n\n");

  /* Discover test PID and readable memory region */
  if (discover_test_process() != 0) {
    printf("WARNING: could not discover test process, some tests will be skipped\n");
  }

  test_metadata();
  test_process_commands();
  test_memory_commands();

  /* Error handling tests run last since some close the connection */
  /* Reconnect if needed */
  close(test_socket);
  test_socket = connect_legacy(host, port);
  if (test_socket >= 0) {
    test_error_handling();
    close(test_socket);
  } else {
    SKIP("error handling", "could not reconnect to server");
  }

  printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
         test_passed, test_failed, test_skipped);
  return test_failed > 0 ? 1 : 0;
}
