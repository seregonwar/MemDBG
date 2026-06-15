/*
 * memDBG - AOB boundary scan test harness.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Verifies:
 *   - Single-range AOB scanner: carry/overlap across chunk boundaries,
 *     wildcard patterns, good-suffix shift.
 *   - Process-wide AOB scanner: map iteration, protection filtering,
 *     start/end range filtering, multi-map results.
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

/* ---- Mock maps: controllable map list for process-wide AOB scans ---- */

static memdbg_map_list_t g_mock_maps;
static memdbg_map_entry_t *g_mock_map_entries = NULL;
static size_t g_mock_map_capacity = 0;

static void mock_maps_init(void) {
  memset(&g_mock_maps, 0, sizeof(g_mock_maps));
}

static void mock_maps_reset(void) {
  free(g_mock_map_entries);
  g_mock_map_entries = NULL;
  g_mock_map_capacity = 0;
  mock_maps_init();
}

static void mock_maps_add(uint64_t start, uint64_t end, uint32_t prot) {
  if (g_mock_maps.count >= g_mock_map_capacity) {
    size_t new_cap = g_mock_map_capacity == 0 ? 4 : g_mock_map_capacity * 2;
    memdbg_map_entry_t *new_entries = (memdbg_map_entry_t *)realloc(
        g_mock_map_entries, new_cap * sizeof(memdbg_map_entry_t));
    if (new_entries == NULL) return;
    g_mock_map_entries = new_entries;
    g_mock_map_capacity = new_cap;
  }
  memset(&g_mock_map_entries[g_mock_maps.count], 0, sizeof(memdbg_map_entry_t));
  g_mock_map_entries[g_mock_maps.count].start      = start;
  g_mock_map_entries[g_mock_maps.count].end        = end;
  g_mock_map_entries[g_mock_maps.count].protection = prot;
  g_mock_maps.count++;
  g_mock_maps.entries = g_mock_map_entries;
}

memdbg_status_t memdbg_process_maps_cached(int pid, memdbg_map_list_t *maps) {
  (void)pid;
  if (maps == NULL) return MEMDBG_ERR_PARAM;
  /* Return a copy of the mock maps */
  memset(maps, 0, sizeof(*maps));
  if (g_mock_maps.count == 0) return MEMDBG_OK;
  maps->count = g_mock_maps.count;
  maps->entries = (memdbg_map_entry_t *)malloc(
      g_mock_maps.count * sizeof(memdbg_map_entry_t));
  if (maps->entries == NULL) return MEMDBG_ERR_NOMEM;
  memcpy(maps->entries, g_mock_maps.entries,
         g_mock_maps.count * sizeof(memdbg_map_entry_t));
  return MEMDBG_OK;
}

void memdbg_process_maps_free(memdbg_map_list_t *maps) {
  if (maps == NULL) return;
  free(maps->entries);
  memset(maps, 0, sizeof(*maps));
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

static int test_process_aob_scan(
    const unsigned char *buf, size_t buf_size,
    const unsigned char *pattern, const unsigned char *mask,
    size_t pat_len,
    uint64_t expected_count, const uint64_t *expected_addrs,
    uint32_t protection_mask, uint64_t start_filter, uint64_t end_filter,
    const char *test_name) {
  g_mock_buffer = buf;
  g_mock_size   = buf_size;

  memdbg_scan_process_aob_request_t request;
  memset(&request, 0, sizeof(request));
  request.pid              = 1;
  request.protection_mask  = protection_mask;
  request.max_results      = 16U;
  request.pattern_length   = (uint32_t)pat_len;
  request.start            = start_filter;
  request.end              = end_filter;

  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_process_aob(&request, pattern, mask,
      &result);

  if (status != MEMDBG_OK) {
    printf("FAIL [%s]: scan returned status %d\n", test_name, (int)status);
    return 1;
  }

  int failures = 0;

  if (result.count != expected_count) {
    printf("FAIL [%s]: expected %llu results, got %zu\n",
           test_name, (unsigned long long)expected_count, result.count);
    failures++;
  }

  if (expected_addrs != NULL) {
    for (uint64_t ei = 0; ei < expected_count; ++ei) {
      int found = 0;
      for (size_t ri = 0; ri < result.count; ++ri) {
        if (result.entries[ri].address == expected_addrs[ei]) {
          found = 1; break;
        }
      }
      if (!found) {
        printf("FAIL [%s]: missing expected address 0x%llx\n",
               test_name, (unsigned long long)expected_addrs[ei]);
        failures++;
      }
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

  /* ======== Tests 1-11: single-range AOB (existing) ======== */

  /* Test 1 — Pattern crossing the exact 1 MiB chunk boundary. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    unsigned char mask[6]   = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 1048576U - 3U;
    memcpy(buf + pos, pattern, pat_len);
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "cross-boundary (3 before + 3 after)");
  }

  /* Test 2 — Pattern entirely in first chunk. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0x11, 0x22, 0x33, 0x44};
    unsigned char mask[4]   = {0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 100U;
    memcpy(buf + pos, pattern, pat_len);
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "inside chunk 0");
  }

  /* Test 3 — Pattern entirely in second chunk. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    unsigned char mask[5]   = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 1048576U + 50000U;
    memcpy(buf + pos, pattern, pat_len);
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "inside chunk 1");
  }

  /* Test 4 — Pattern crossing boundary with wildcard. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xCA, 0xFE, 0x00, 0xBA, 0xBE};
    unsigned char mask[5]   = {0xFF, 0xFF, 0x00, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 1048576U - 2U;
    memcpy(buf + pos, pattern, pat_len);
    buf[pos + 2] = 0x77;
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "cross-boundary with wildcard");
  }

  /* Test 5 — Short 2-byte pattern exactly on the boundary. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xED, 0xFE};
    unsigned char mask[2]   = {0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 1048576U - 1U;
    memcpy(buf + pos, pattern, pat_len);
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "cross-boundary 2-byte");
  }

  /* Test 6 — Negative: pattern not present. */
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

  /* Test 8 — GS: repeated suffix ABCD in ABCDEFABCD. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {'A','B','C','D','E','F','A','B','C','D'};
    unsigned char mask[10]   = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 1048576U + 12345U;
    memcpy(buf + pos, pattern, pat_len);
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "GS: repeated suffix ABCD in ABCDEFABCD");
  }

  /* Test 9 — GS: repeated A's with B in middle. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {'A','A','A','A','A','A','B','A','A','A'};
    unsigned char mask[10]   = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 500000U;
    memcpy(buf + pos, pattern, pat_len);
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "GS: repeated A's with B in middle");
  }

  /* Test 10 — Wildcard (no GS) cross-boundary. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xDE, 0xAD, 0x00, 0xBE, 0xEF, 0x00, 0xCA, 0xFE};
    unsigned char mask[8]   = {0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 1048576U - 4U;
    memcpy(buf + pos, pattern, pat_len);
    buf[pos + 2] = 0x42;
    buf[pos + 5] = 0x99;
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "wildcard (no GS) cross-boundary");
  }

  /* Test 11 — Short pattern (no GS) cross-boundary. */
  {
    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xAB, 0xCD, 0xEF};
    unsigned char mask[3]   = {0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 1048576U - 2U;
    memcpy(buf + pos, pattern, pat_len);
    failures += test_aob_scan(buf, buf_size, pattern, mask, pat_len, pos,
                              "short pattern (no GS) cross-boundary");
  }

  /* ======== Tests 12-16: process-wide AOB (new) ======== */

  /* Test 12 — Process-wide: pattern in one map only.
     Three maps: [0, 64k), [64k, 128k), [128k, 256k).
     Pattern at offset 1000 (map 0). Only map 0 should produce a hit. */
  {
    mock_maps_init();
    mock_maps_add(0U, 65536U, 1U);           /* 0-64k,  READ */
    mock_maps_add(65536U, 131072U, 1U);       /* 64-128k, READ */
    mock_maps_add(131072U, 262144U, 1U);      /* 128-256k,READ */

    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xDE, 0xAD, 0xBE, 0xEF};
    unsigned char mask[4]   = {0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 1000U;
    memcpy(buf + pos, pattern, pat_len);

    uint64_t expected[] = {1000U};
    failures += test_process_aob_scan(buf, buf_size,
        pattern, mask, pat_len, 1U, expected, 0U, 0U, 0U,
        "PW: pattern in single map");
  }

  /* Test 13 — Process-wide: pattern crossing map boundary is NOT found.
     Map 0: [0, 65536), Map 1: [65536, 131072).
     Pattern at offset 65534 (starts 2 bytes before map 0 end, ends in map 1).
     Each map is scanned independently, so cross-map patterns are missed. */
  {
    mock_maps_reset();
    mock_maps_add(0U, 65536U, 1U);
    mock_maps_add(65536U, 131072U, 1U);

    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xCA, 0xFE, 0xBA, 0xBE};
    unsigned char mask[4]   = {0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos = 65536U - 2U;  /* 2 bytes before map boundary */
    memcpy(buf + pos, pattern, pat_len);

    failures += test_process_aob_scan(buf, buf_size,
        pattern, mask, pat_len, 0U, NULL, 0U, 0U, 0U,
        "PW: cross-map boundary (no hit)");
  }

  /* Test 14 — Process-wide: pattern in two different maps.
     Same pattern at offset 100 (map 0) and offset 66000 (map 1). */
  {
    mock_maps_reset();
    mock_maps_add(0U, 65536U, 1U);
    mock_maps_add(65536U, 131072U, 1U);

    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xBE, 0xEF, 0xCA, 0xFE};
    unsigned char mask[4]   = {0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos1 = 100U;
    uint64_t pos2 = 66000U;
    memcpy(buf + pos1, pattern, pat_len);
    memcpy(buf + pos2, pattern, pat_len);

    uint64_t expected[] = {100U, 66000U};
    failures += test_process_aob_scan(buf, buf_size,
        pattern, mask, pat_len, 2U, expected, 0U, 0U, 0U,
        "PW: pattern in two maps");
  }

  /* Test 15 — Process-wide: protection filtering skips non-readable map.
     Map 0: [0, 64k) protection=0 (none) — should be skipped.
     Map 1: [64k, 128k) protection=1 (READ) — should be scanned.
     Pattern at offset 1000 (map 0, not readable) and 70000 (map 1, readable).
     Only map 1 hit should be returned. */
  {
    mock_maps_reset();
    mock_maps_add(0U, 65536U, 0U);       /* no protection → skipped */
    mock_maps_add(65536U, 131072U, 1U);   /* READ */

    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0x11, 0x22, 0x33, 0x44};
    unsigned char mask[4]   = {0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos_skip = 1000U;
    uint64_t pos_hit  = 70000U;
    memcpy(buf + pos_skip, pattern, pat_len);
    memcpy(buf + pos_hit, pattern, pat_len);

    uint64_t expected[] = {70000U};
    failures += test_process_aob_scan(buf, buf_size,
        pattern, mask, pat_len, 1U, expected, 0U, 0U, 0U,
        "PW: protection filter skips non-readable");
  }

  /* Test 16 — Process-wide: start/end range filtering.
     Map: [0, 256k) READ.
     Pattern at offset 50000 and 150000.
     With filter start=100000, end=200000, only the second hit should appear. */
  {
    mock_maps_reset();
    mock_maps_add(0U, 262144U, 1U);

    memset(buf, 0x00, buf_size);
    unsigned char pattern[] = {0xAA, 0xBB, 0xCC, 0xDD};
    unsigned char mask[4]   = {0xFF, 0xFF, 0xFF, 0xFF};
    size_t pat_len = sizeof(pattern);
    uint64_t pos_outside = 50000U;
    uint64_t pos_inside  = 150000U;
    memcpy(buf + pos_outside, pattern, pat_len);
    memcpy(buf + pos_inside, pattern, pat_len);

    uint64_t expected[] = {150000U};
    failures += test_process_aob_scan(buf, buf_size,
        pattern, mask, pat_len, 1U, expected, 0U, 100000U, 200000U,
        "PW: start/end range filter");
  }

  /* ---- Summary ---- */
  mock_maps_reset();

  if (failures == 0) {
    printf("\nAll AOB boundary tests PASSED (16/16).\n");
  } else {
    printf("\n%d test(s) FAILED out of 16.\n", failures);
  }

  free(buf);
  return failures > 0 ? 1 : 0;
}
