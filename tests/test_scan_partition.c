/*
 * memDBG - Size-weighted scan partition test.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Verifies that partition_maps_by_bytes() correctly distributes maps by
 * byte budget rather than by map count.  Synthetic maps exercise:
 *   - several large maps + many tiny maps (balance check)
 *   - one huge map + many tiny maps (map-atomic boundary behaviour)
 *   - all maps roughly equal size
 *   - single map (single-thread fallback)
 *   - min_map_len / prot_mask filtering edge cases
 *
 * Links directly against scan_partition.o — no duplicated algorithm. */

#include "memdbg/core/memdbg_protocol.h"

#include "scanner/scan_partition.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAP_PROT_READ 1U

/* ---- Test harness ---- */

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s\n", name);                                            \
    }                                                                          \
  } while (0)

#define TEST_EQ(name, actual, expected)                                        \
  do {                                                                         \
    unsigned long long _a = (unsigned long long)(actual);                      \
    unsigned long long _e = (unsigned long long)(expected);                    \
    if (_a == _e) {                                                            \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s  (got %llu, expected %llu)\n", name, _a, _e);        \
    }                                                                          \
  } while (0)

static memdbg_map_entry_t *make_maps(size_t count, uint64_t start_base) {
  memdbg_map_entry_t *maps = (memdbg_map_entry_t *)calloc(count, sizeof(memdbg_map_entry_t));
  if (maps == NULL) { printf("FATAL: out of memory\n"); exit(1); }
  for (size_t i = 0U; i < count; ++i) {
    maps[i].start      = start_base;
    maps[i].protection  = MAP_PROT_READ;
  }
  return maps;
}

/* ---- Format helper ---- */
static const char *fmt_bytes(uint64_t b) {
  static char buf[64];
  if (b >= 1024ULL*1024ULL*1024ULL)
    snprintf(buf, sizeof(buf), "%.2f GiB",
             (double)b / (1024.0*1024.0*1024.0));
  else if (b >= 1024ULL*1024ULL)
    snprintf(buf, sizeof(buf), "%.2f MiB",
             (double)b / (1024.0*1024.0));
  else if (b >= 1024ULL)
    snprintf(buf, sizeof(buf), "%.2f KiB",
             (double)b / 1024.0);
  else
    snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)b);
  return buf;
}

/* Compute per-slot byte + map-count totals.  Applies the same filters
 * as partition_maps_by_bytes so only qualifying maps are counted. */
static void compute_slot_totals(const memdbg_map_entry_t *maps,
                                const scan_partition_slot_t *slots,
                                size_t num_slots,
                                uint32_t prot_mask,
                                uint64_t start_filter,
                                uint64_t end_filter,
                                size_t min_map_len,
                                uint64_t *out_bytes,
                                size_t *out_counts) {
  memset(out_bytes, 0, num_slots * sizeof(uint64_t));
  memset(out_counts, 0, num_slots * sizeof(size_t));
  for (size_t s = 0U; s < num_slots; ++s) {
    for (size_t i = slots[s].map_start; i < slots[s].map_end; ++i) {
      const memdbg_map_entry_t *m = &maps[i];
      if ((m->protection & prot_mask) != prot_mask || m->end <= m->start)
        continue;
      uint64_t ms = m->start, me = m->end;
      if (start_filter != 0U && ms < start_filter) ms = start_filter;
      if (end_filter   != 0U && me > end_filter)   me = end_filter;
      if (me <= ms) continue;
      uint64_t mbytes = me - ms;
      if (mbytes < (uint64_t)min_map_len) continue;
      out_bytes[s] += mbytes;
      out_counts[s]++;
    }
  }
}

/* ======================================================================
 * Test cases
 * ====================================================================== */

/* ---- Test 1: 4 large maps (2 GiB each) + 200 tiny maps (1 KiB each) ---- */
static void test_large_plus_tiny(void) {
  printf("\n--- 4 large maps (2 GiB each) + 200 tiny maps (4 slots) ---\n");

  const size_t n_large = 4U;
  const size_t n_tiny  = 200U;
  const size_t total_maps = n_large + n_tiny;
  const uint64_t large_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
  const uint64_t tiny_bytes  = 1024ULL;
  const size_t num_slots = 4U;

  memdbg_map_entry_t *maps = make_maps(total_maps, 0);

  uint64_t base = 0;
  for (size_t i = 0U; i < n_large; ++i) {
    maps[i].start = base;
    maps[i].end   = base + large_bytes;
    base += large_bytes + 0x10000ULL;
  }
  for (size_t i = 0U; i < n_tiny; ++i) {
    maps[n_large + i].start = base;
    maps[n_large + i].end   = base + tiny_bytes;
    base += tiny_bytes + 0x1000ULL;
  }

  scan_partition_slot_t slots[4];
  size_t used = 0U;
  memdbg_status_t st = partition_maps_by_bytes(
      maps, total_maps, MAP_PROT_READ, 0U, 0U, 0U, num_slots, slots, &used);
  TEST_EQ("partition_maps_by_bytes returns OK", st, MEMDBG_OK);
  TEST_EQ("slots used = 4", used, 4U);

  uint64_t slot_bytes[4];
  size_t   slot_counts[4];
  compute_slot_totals(maps, slots, num_slots, MAP_PROT_READ, 0U, 0U, 0U,
                      slot_bytes, slot_counts);

  uint64_t total_bytes = 0;
  for (size_t s = 0U; s < num_slots; ++s) {
    printf("  slot %zu: maps %zu-%zu  bytes=%s  count=%zu\n",
           s, slots[s].map_start, slots[s].map_end,
           fmt_bytes(slot_bytes[s]), slot_counts[s]);
    total_bytes += slot_bytes[s];
  }

  /* Each slot should have ~1 large map (2 GiB). */
  uint64_t max_b = 0, min_b = UINT64_MAX;
  for (size_t s = 0U; s < num_slots; ++s) {
    if (slot_bytes[s] > max_b) max_b = slot_bytes[s];
    if (slot_bytes[s] < min_b) min_b = slot_bytes[s];
  }
  TEST("byte balance: min > 0", min_b > 0U);
  TEST("byte balance: within 1% of each other",
       max_b - min_b <= total_bytes / 100U);

  /* All maps must be covered exactly once */
  TEST_EQ("slot[0] map_start", slots[0].map_start, 0U);
  TEST_EQ("slot[3] map_end", slots[3].map_end, total_maps);

  /* Last slot naturally accumulates all remaining tiny maps */
  TEST("map count variance: last slot has most tiny maps",
       slot_counts[3] > slot_counts[0]);

  free(maps);
}

/* ---- Test 1b: one huge map (8 GiB) + 200 tiny maps ---- */
static void test_single_huge_map(void) {
  printf("\n--- Single 8 GiB map + 200 tiny maps (partitioning is map-atomic) ---\n");

  const size_t n_tiny = 200U;
  const size_t total_maps = 1U + n_tiny;
  const size_t num_slots = 4U;

  memdbg_map_entry_t *maps = make_maps(total_maps, 0);
  maps[0].end = 8ULL * 1024ULL * 1024ULL * 1024ULL;

  uint64_t base = maps[0].end + 0x10000ULL;
  for (size_t i = 0U; i < n_tiny; ++i) {
    maps[1U + i].start = base;
    maps[1U + i].end   = base + 1024ULL;
    base += 1024ULL + 0x1000ULL;
  }

  scan_partition_slot_t slots[4];
  size_t used = 0U;
  memdbg_status_t st = partition_maps_by_bytes(
      maps, total_maps, MAP_PROT_READ, 0U, 0U, 0U, num_slots, slots, &used);
  TEST_EQ("partition_maps_by_bytes returns OK", st, MEMDBG_OK);
  TEST_EQ("huge: slots used", used, 2U);

  uint64_t slot_bytes[4];
  size_t   slot_counts[4];
  compute_slot_totals(maps, slots, num_slots, MAP_PROT_READ, 0U, 0U, 0U,
                      slot_bytes, slot_counts);

  for (size_t s = 0U; s < num_slots; ++s) {
    printf("  slot %zu: maps %zu-%zu  bytes=%s  count=%zu%s\n",
           s, slots[s].map_start, slots[s].map_end,
           fmt_bytes(slot_bytes[s]), slot_counts[s],
           slot_bytes[s] > 0 ? "" : " (empty)");
  }

  /* Slot 0: the huge map only */
  TEST_EQ("huge: slot 0 bytes", slot_bytes[0],
          8ULL * 1024ULL * 1024ULL * 1024ULL);
  TEST_EQ("huge: slot 0 map count", slot_counts[0], 1U);

  /* Slot 1: all 200 tiny maps */
  TEST_EQ("huge: slot 1 map count", slot_counts[1], n_tiny);
  TEST_EQ("huge: slot 1 bytes", slot_bytes[1], n_tiny * 1024ULL);

  /* Slots 2-3: empty (all maps already assigned) */
  TEST_EQ("huge: slot 2 map count", slot_counts[2], 0U);
  TEST_EQ("huge: slot 2 total_bytes", slot_bytes[2], 0U);
  TEST_EQ("huge: slot 3 map count", slot_counts[3], 0U);

  TEST_EQ("huge: slot[0] start", slots[0].map_start, 0U);

  free(maps);
}

/* ---- Test 2: all maps roughly equal size (4 threads) ---- */
static void test_all_equal(void) {
  printf("\n--- All maps equal size (4 slots, 100 maps of 10 MiB each) ---\n");

  const size_t n_maps = 100U;
  const uint64_t map_bytes = 10ULL * 1024ULL * 1024ULL;
  const size_t num_slots = 4U;

  memdbg_map_entry_t *maps = make_maps(n_maps, 0);

  uint64_t base = 0;
  for (size_t i = 0U; i < n_maps; ++i) {
    maps[i].start = base;
    maps[i].end   = base + map_bytes;
    base += map_bytes + 4096ULL;
  }

  scan_partition_slot_t slots[4];
  size_t used = 0U;
  memdbg_status_t st = partition_maps_by_bytes(
      maps, n_maps, MAP_PROT_READ, 0U, 0U, 0U, num_slots, slots, &used);
  TEST_EQ("partition_maps_by_bytes returns OK", st, MEMDBG_OK);
  TEST_EQ("equal: slots used", used, 4U);

  uint64_t slot_bytes[4];
  size_t   slot_counts[4];
  compute_slot_totals(maps, slots, num_slots, MAP_PROT_READ, 0U, 0U, 0U,
                      slot_bytes, slot_counts);

  for (size_t s = 0U; s < num_slots; ++s)
    printf("  slot %zu: maps %zu-%zu  bytes=%s  count=%zu\n",
           s, slots[s].map_start, slots[s].map_end,
           fmt_bytes(slot_bytes[s]), slot_counts[s]);

  /* Each slot should have ~25 maps (100 / 4), ±2 for boundary alignment */
  for (size_t s = 0U; s < num_slots; ++s) {
    TEST("equal: slot has ~25 maps",
         slot_counts[s] >= 23 && slot_counts[s] <= 27);
    TEST("equal: slot bytes ~250 MiB",
         slot_bytes[s] >= 230ULL * 1024ULL * 1024ULL &&
         slot_bytes[s] <= 270ULL * 1024ULL * 1024ULL);
  }

  free(maps);
}

/* ---- Test 3: single map (single-thread fallback) ---- */
static void test_single_map(void) {
  printf("\n--- Single map of 4 KiB (falls to single slot) ---\n");

  const size_t num_slots = 1U;
  memdbg_map_entry_t *maps = make_maps(1U, 0);
  maps[0].end = 4096ULL;

  scan_partition_slot_t slot;
  size_t used = 0U;
  memdbg_status_t st = partition_maps_by_bytes(
      maps, 1U, MAP_PROT_READ, 0U, 0U, 0U, num_slots, &slot, &used);
  TEST_EQ("single: returns OK", st, MEMDBG_OK);
  TEST_EQ("single: slots used", used, 1U);

  TEST_EQ("single: slot map_start", slot.map_start, 0U);
  TEST_EQ("single: slot map_end",   slot.map_end,   1U);

  free(maps);
}

/* ---- Test 4: min_map_len filtering ---- */
static void test_min_map_len_filter(void) {
  printf("\n--- min_map_len filter (2 KiB threshold) removes 1 KiB maps ---\n");

  const size_t n_maps = 10U;
  memdbg_map_entry_t *maps = make_maps(n_maps, 0);

  uint64_t base = 0;
  for (size_t i = 0U; i < 5U; ++i) {
    maps[i].start = base;
    maps[i].end   = base + 1024ULL;
    base += 1024ULL + 4096ULL;
  }
  for (size_t i = 5U; i < 10U; ++i) {
    maps[i].start = base;
    maps[i].end   = base + 65536ULL;
    base += 65536ULL + 4096ULL;
  }

  const size_t num_slots = 2U;
  scan_partition_slot_t slots[2];
  size_t used = 0U;
  memdbg_status_t st = partition_maps_by_bytes(
      maps, n_maps, MAP_PROT_READ, 0U, 0U, 2048ULL, num_slots, slots, &used);
  TEST_EQ("min_map: returns OK", st, MEMDBG_OK);

  uint64_t slot_bytes[2];
  size_t   slot_counts[2];
  compute_slot_totals(maps, slots, num_slots, MAP_PROT_READ, 0U, 0U, 2048ULL,
                      slot_bytes, slot_counts);

  size_t total_qualifying = 0;
  uint64_t total_qual_bytes = 0;
  for (size_t s = 0U; s < num_slots; ++s) {
    total_qualifying += slot_counts[s];
    total_qual_bytes += slot_bytes[s];
  }

  TEST_EQ("min_map: 5 maps qualify (64 KiB each)", total_qualifying, 5U);
  TEST_EQ("min_map: total bytes = 5 * 64 KiB", total_qual_bytes, 5ULL * 65536ULL);

  free(maps);
}

/* ---- Test 5: protection mask filtering ---- */
static void test_prot_mask_filter(void) {
  printf("\n--- prot_mask filters non-readable maps ---\n");

  const size_t n_maps = 5U;
  memdbg_map_entry_t *maps = make_maps(n_maps, 0);

  for (size_t i = 0U; i < n_maps; ++i) {
    maps[i].start = (uint64_t)i * 0x10000ULL;
    maps[i].end   = maps[i].start + 0x1000ULL;
  }
  maps[2].protection = 0U;  /* no permissions */
  maps[4].protection = 2U;  /* write only, not readable */

  const size_t num_slots = 2U;
  scan_partition_slot_t slots[2];
  size_t used = 0U;
  memdbg_status_t st = partition_maps_by_bytes(
      maps, n_maps, MAP_PROT_READ, 0U, 0U, 0U, num_slots, slots, &used);
  TEST_EQ("prot_mask: returns OK", st, MEMDBG_OK);

  uint64_t slot_bytes[2];
  size_t   slot_counts[2];
  compute_slot_totals(maps, slots, num_slots, MAP_PROT_READ, 0U, 0U, 0U,
                      slot_bytes, slot_counts);

  size_t total = slot_counts[0] + slot_counts[1];
  TEST_EQ("prot_mask: 3 maps qualify", total, 3U);

  free(maps);
}

/* ---- Test 5b: prot_mask with filtered-out maps interspersed ----
 * Verifies that compute_slot_totals correctly excludes non-readable maps
 * that fall between qualifying maps within the same slot range. */
static void test_per_slot_prot_mask_filter(void) {
  printf("\n--- prot_mask: non-readable maps interspersed between readable ones ---\n");

  const size_t n_maps = 5U;
  memdbg_map_entry_t *maps = make_maps(n_maps, 0);

  /* Interleave: R, U, R, U, R  (R=readable, U=unreadable) */
  maps[0].start=0x1000;  maps[0].end=0x2000;  maps[0].protection=MAP_PROT_READ;
  maps[1].start=0x2000;  maps[1].end=0x4000;  maps[1].protection=0U;
  maps[2].start=0x4000;  maps[2].end=0x6000;  maps[2].protection=MAP_PROT_READ;
  maps[3].start=0x6000;  maps[3].end=0x7000;  maps[3].protection=2U;
  maps[4].start=0x7000;  maps[4].end=0x9000;  maps[4].protection=MAP_PROT_READ;

  /* Single slot so map_end = map_count = 5, encompassing all maps. */
  const size_t num_slots = 1U;
  scan_partition_slot_t slot;
  size_t used = 0U;
  memdbg_status_t st = partition_maps_by_bytes(
      maps, n_maps, MAP_PROT_READ, 0U, 0U, 0U, num_slots, &slot, &used);
  TEST_EQ("interspersed prot_mask: returns OK", st, MEMDBG_OK);
  TEST_EQ("interspersed prot_mask: slots used", used, 1U);

  /* Slot must cover indices 0-4. Indices 1 and 3 are unreadable. */
  TEST_EQ("interspersed prot_mask: slot covers all", slot.map_start, 0U);
  TEST_EQ("interspersed prot_mask: slot end = map_count", slot.map_end, n_maps);

  uint64_t slot_bytes[1];
  size_t   slot_counts[1];
  compute_slot_totals(maps, &slot, 1U, MAP_PROT_READ, 0U, 0U, 0U,
                      slot_bytes, slot_counts);

  /* Only indices 0, 2, 4 qualify: 0x1000 + 0x2000 + 0x2000 = 0x5000 bytes */
  TEST_EQ("interspersed prot_mask: 3 maps counted", slot_counts[0], 3U);
  TEST_EQ("interspersed prot_mask: total bytes = 0x5000",
          slot_bytes[0], 0x5000ULL);

  free(maps);
}

/* ---- Test 6: all maps filtered out ---- */
static void test_all_filtered_out(void) {
  printf("\n--- All maps empty (zero effective maps) ---\n");

  const size_t num_slots = 4U;
  memdbg_map_entry_t *maps = make_maps(3U, 0);
  for (size_t i = 0U; i < 3U; ++i) {
    maps[i].start = (uint64_t)i * 0x1000ULL;
    maps[i].end   = maps[i].start;
  }

  scan_partition_slot_t slots[4];
  size_t used = 0U;
  memdbg_status_t st = partition_maps_by_bytes(
      maps, 3U, MAP_PROT_READ, 0U, 0U, 0U, num_slots, slots, &used);
  TEST_EQ("empty: returns OK", st, MEMDBG_OK);
  TEST_EQ("empty: slots used", used, 1U);

  uint64_t slot_bytes[4];
  size_t   slot_counts[4];
  compute_slot_totals(maps, slots, num_slots, MAP_PROT_READ, 0U, 0U, 0U,
                      slot_bytes, slot_counts);

  size_t total = 0;
  uint64_t total_b = 0;
  for (size_t s = 0U; s < num_slots; ++s) {
    total   += slot_counts[s];
    total_b += slot_bytes[s];
  }
  TEST_EQ("empty: no maps assigned", total, 0U);
  TEST_EQ("empty: total_bytes", total_b, 0U);

  free(maps);
}

/* ---- Test 5c: min_map_len with sub-threshold maps interspersed ----
 * Verifies that compute_slot_totals correctly excludes maps below the
 * size threshold that fall between qualifying maps within the same slot. */
static void test_per_slot_min_map_len_filter(void) {
  printf("\n--- min_map_len: tiny maps interspersed between qualifying ones ---\n");

  const size_t n_maps = 6U;
  memdbg_map_entry_t *maps = make_maps(n_maps, 0);

  /* Interleave: 64K, 1K, 64K, 2K, 64K, 1K  (threshold = 2048) */
  maps[0].start=0x00000; maps[0].end=0x10000;  /* 64 KiB — qualifies */
  maps[1].start=0x10000; maps[1].end=0x10400;  /*  1 KiB — filtered */
  maps[2].start=0x10400; maps[2].end=0x20400;  /* 64 KiB — qualifies */
  maps[3].start=0x20400; maps[3].end=0x20BFF;  /* 2047 bytes — just below 2048 threshold */
  maps[4].start=0x20C00; maps[4].end=0x30C00;  /* 64 KiB — qualifies */
  maps[5].start=0x30C00; maps[5].end=0x31000;  /*  1 KiB — filtered */

  const uint64_t kMinLen = 2048ULL;
  const size_t num_slots = 1U;
  scan_partition_slot_t slot;
  size_t used = 0U;
  memdbg_status_t st = partition_maps_by_bytes(
      maps, n_maps, MAP_PROT_READ, 0U, 0U, kMinLen, num_slots, &slot, &used);
  TEST_EQ("interspersed min_map: returns OK", st, MEMDBG_OK);
  TEST_EQ("interspersed min_map: slots used", used, 1U);

  /* Single slot covers all maps. Indices 1, 3, 5 are below threshold. */
  TEST_EQ("interspersed min_map: covers all", slot.map_start, 0U);
  TEST_EQ("interspersed min_map: end = map_count", slot.map_end, n_maps);

  uint64_t slot_bytes[1];
  size_t   slot_counts[1];
  compute_slot_totals(maps, &slot, 1U, MAP_PROT_READ, 0U, 0U, kMinLen,
                      slot_bytes, slot_counts);

  /* Only indices 0, 2, 4 qualify: 3 × 64 KiB = 192 KiB */
  TEST_EQ("interspersed min_map: 3 maps counted", slot_counts[0], 3U);
  TEST_EQ("interspersed min_map: total bytes = 192 KiB",
          slot_bytes[0], 3ULL * 65536ULL);

  free(maps);
}

/* ---- Test 7: start/end filter bounds ---- */
static void test_start_end_filter(void) {
  printf("\n--- start/end filter trims map boundaries ---\n");

  memdbg_map_entry_t *maps = make_maps(2U, 0);
  maps[0].start = 0x1000ULL;  maps[0].end = 0x9000ULL;
  maps[1].start = 0xA000ULL;  maps[1].end = 0x12000ULL;

  const size_t num_slots = 1U;
  scan_partition_slot_t slot;
  size_t used = 0U;
  memdbg_status_t st = partition_maps_by_bytes(
      maps, 2U, MAP_PROT_READ,
      0x2000ULL, 0x10000ULL,  /* start_filter, end_filter */
      0U, num_slots, &slot, &used);
  TEST_EQ("start_end: returns OK", st, MEMDBG_OK);
  TEST_EQ("start_end: slots used", used, 1U);

  uint64_t slot_bytes[1];
  size_t   slot_counts[1];
  compute_slot_totals(maps, &slot, 1U, MAP_PROT_READ,
                      0x2000ULL, 0x10000ULL, 0U,
                      slot_bytes, slot_counts);

  /* map[0]: trimmed to 0x2000..0x9000 = 0x7000 bytes (28 KiB)
     map[1]: trimmed to 0xA000..0x10000 = 0x6000 bytes (24 KiB) */
  TEST_EQ("start_end: 2 maps qualify", slot_counts[0], 2U);
  TEST_EQ("start_end: total bytes = 0xD000", slot_bytes[0], 0x7000ULL + 0x6000ULL);

  free(maps);
}

/* ======================================================================
 * Main
 * ====================================================================== */

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("=== Scan Partition Test ===\n");
  printf("Verifies size-weighted map partitioning for parallel scanner\n");
  printf("Key invariant: threads get ~equal scan bytes, not ~equal map counts\n\n");

  test_large_plus_tiny();
  test_single_huge_map();
  test_all_equal();
  test_single_map();
  test_min_map_len_filter();
  test_prot_mask_filter();
  test_per_slot_prot_mask_filter();
  test_per_slot_min_map_len_filter();
  test_all_filtered_out();
  test_start_end_filter();

  printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  printf("Total:  %d\n", total);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}
