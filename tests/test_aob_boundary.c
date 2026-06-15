/*
 * memDBG - AOB boundary scan test harness.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Verifies that the AOB scanner's carry/overlap mechanism correctly detects
 * patterns that cross the 1 MiB chunk boundary, as well as patterns contained
 * entirely within a single chunk.
 */

#include "memdbg/scanner/memdbg_scan.h"
#include "memdbg/debug/memdbg_process.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Mock: controlled memory buffer served to the scanner ---- */

static const unsigned char *g_mock_buffer = NULL;
static size_t g_mock_size = 0;

memdbg_status_t memdbg_memory_read(int pid, uint64_t address, void *buffer,
                                   size_t length, size_t *read_out) {
  (void)pid;
  size_t offset = (size_t)address;
  if (offset >= g_mock_size) {
    if (read_out != NULL) *read_out = 0U;
    return MEMDBG_OK;
  }
  size_t available = g_mock_size - offset;
  size_t to_copy   = length < available ? length : available;
  memcpy(buffer, g_mock_buffer + offset, to_copy);
  if (read_out != NULL) *read_out = to_copy;
  return MEMDBG_OK;
}

/* ---- Stubs: unused by AOB scan but needed to link memdbg_scan.o ---- */

memdbg_status_t memdbg_process_maps_cached(int pid, memdbg_map_list_t *maps) {
  (void)pid;
  memset(maps, 0, sizeof(*maps));
  return MEMDBG_ERR_UNSUPPORTED;
}

void memdbg_process_maps_free(memdbg_map_list_t *maps) {
  (void)maps;
}

/* ---- Helpers ---- */

static int test_aob_scan(const unsigned char *buf, size_t buf_size,
                         const unsigned char *pattern, const unsigned char *mask,
                         size_t pat_len, uint64_t expected_addr,
                         const char *test_name) {
  g_mock_buffer = buf;
  g_mock_size   = buf_size;

  memdbg_scan_aob_request_t request;
  memset(&request, 0, sizeof(request));
  request.pid             = 1;
  request.start           = 0U;
  request.length          = buf_size;
  request.max_results     = 4U;
  request.pattern_length  = (uint32_t)pat_len;

  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_aob(&request, pattern, mask, &result);

  if (status != MEMDBG_OK) {
    printf("FAIL [%s]: scan returned status %d\n", test_name, (int)status);
    return 1;
  }

  int failures = 0;

  if (result.count == 0U || result.entries == NULL) {
    printf("FAIL [%s]: no results — expected address 0x%llx\n",
           test_name, (unsigned long long)expected_addr);
    failures++;
  } else {
    int found = 0;
    for (size_t i = 0U; i < result.count; ++i) {
      if (result.entries[i].address == expected_addr) { found = 1; break; }
    }
    if (!found) {
      printf("FAIL [%s]: expected 0x%llx, got %zu result(s):",
             test_name, (unsigned long long)expected_addr, result.count);
      for (size_t i = 0U; i < result.count; ++i)
        printf(" 0x%llx", (unsigned long long)result.entries[i].address);
      printf("\n");
      failures++;
    }
  }

  memdbg_scan_result_free(&result);
  return failures;
}

/* ---- Main ---- */

int main(void) {
  int failures = 0;

  /* Two full chunks (2 MiB) — enough for patterns to cross the 1 MiB
     boundary and for before/after comparison tests. */
  size_t buf_size = 2U * 1024U * 1024U;
  unsigned char *buf = (unsigned char *)malloc(buf_size);
  if (buf == NULL) { printf("FATAL: malloc failed\n"); return 1; }

  /* Test 1 — Pattern crossing the exact 1 MiB chunk boundary.
     Boundary is at byte 1048576.  Place 6-byte pattern {DE,AD,BE,EF,CA,FE}
     so it starts 3 bytes BEFORE the boundary and ends 3 bytes AFTER. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    unsigned char mask[6]   = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 1048576U - 3U; /* 3 bytes before boundary */
    memcpy(buf + pos, pattern, pat_len);
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "cross-boundary (3 before + 3 after)");
  }

  /* Test 2 — Pattern entirely in first chunk (well before boundary). */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0x11, 0x22, 0x33, 0x44};
    unsigned char mask[4]   = {0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 100U; /* deep in chunk 0 */
    memcpy(buf + pos, pattern, pat_len);
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "inside chunk 0");
  }

  /* Test 3 — Pattern entirely in second chunk (well after boundary). */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    unsigned char mask[5]   = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    /* Place in chunk 1, well past the 1 MiB mark */
    uint64_t pos = 1048576U + 50000U;
    memcpy(buf + pos, pattern, pat_len);
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "inside chunk 1");
  }

  /* Test 4 — Pattern crossing boundary with wildcard bytes in mask.
     Pattern {CA,FE,??,BA,BE} where ?? matches anything. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xCA, 0xFE, 0x00, 0xBA, 0xBE};
    unsigned char mask[5]   = {0xFF, 0xFF, 0x00, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 1048576U - 2U; /* 2 bytes before boundary */
    memcpy(buf + pos, pattern, pat_len);
    /* Overwrite the wildcard byte with a different value to verify mask works */
    buf[pos + 2] = 0x77;
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "cross-boundary with wildcard");
  }

  /* Test 5 — Short 2-byte pattern exactly on the boundary.
     Boundary at 1048576, pattern starts at 1048575, ends at 1048576. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xED, 0xFE};
    unsigned char mask[2]   = {0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 1048576U - 1U; /* 1 byte before boundary */
    memcpy(buf + pos, pattern, pat_len);
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "cross-boundary 2-byte");
  }

  /* Test 6 — Negative: pattern not present at all. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xFF, 0xFF, 0xFF, 0xFF};
    unsigned char mask[4]   = {0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);

    g_mock_buffer = buf;
    g_mock_size   = buf_size;
    memdbg_scan_aob_request_t request;
    memset(&request, 0, sizeof(request));
    request.pid            = 1;
    request.start          = 0U;
    request.length         = buf_size;
    request.max_results    = 4U;
    request.pattern_length = (uint32_t)pat_len;

    memdbg_scan_result_t result;
    memdbg_status_t status = memdbg_scan_aob(&request, pattern, mask, &result);

    if (status != MEMDBG_OK) {
      printf("FAIL [no-match]: scan returned status %d\n", (int)status);
      failures++;
    } else if (result.count != 0U) {
      printf("FAIL [no-match]: expected 0 results, got %zu\n", result.count);
      failures++;
    }
    memdbg_scan_result_free(&result);
  }

  /* Test 7 — Multiple matches: same pattern at two different offsets. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xBA, 0xDC, 0x0F, 0xFE};
    unsigned char mask[4]   = {0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos1 = 500U;
    uint64_t pos2 = 1048576U + 70000U;
    memcpy(buf + pos1, pattern, pat_len);
    memcpy(buf + pos2, pattern, pat_len);

    g_mock_buffer = buf;
    g_mock_size   = buf_size;
    memdbg_scan_aob_request_t request;
    memset(&request, 0, sizeof(request));
    request.pid            = 1;
    request.start          = 0U;
    request.length         = buf_size;
    request.max_results    = 4U;
    request.pattern_length = (uint32_t)pat_len;

    memdbg_scan_result_t result;
    memdbg_status_t status = memdbg_scan_aob(&request, pattern, mask, &result);

    if (status != MEMDBG_OK) {
      printf("FAIL [multi-match]: scan returned status %d\n", (int)status);
      failures++;
    } else if (result.count != 2U) {
      printf("FAIL [multi-match]: expected 2 results, got %zu\n", result.count);
      failures++;
    } else {
      int f0 = (result.entries[0].address == pos1 && result.entries[1].address == pos2) ||
               (result.entries[0].address == pos2 && result.entries[1].address == pos1);
      if (!f0) {
        printf("FAIL [multi-match]: expected {%" PRIx64 ", %" PRIx64 "}, got {%" PRIx64 ", %" PRIx64 "}\n",
               pos1, pos2,
               result.entries[0].address, result.entries[1].address);
        failures++;
      }
    }
    memdbg_scan_result_free(&result);
  }

  /* ---- Summary ---- */
  if (failures == 0) {
    printf("\nAll AOB boundary tests PASSED (7/7).\n");
  } else {
    printf("\n%d test(s) FAILED out of 7.\n", failures);
  }

  free(buf);
  return failures > 0 ? 1 : 0;
}
