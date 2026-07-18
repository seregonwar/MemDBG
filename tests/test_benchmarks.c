/*
 * MemDBG - Performance benchmark suite.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Measures baseline performance of critical hot paths.
 * Supports --save-baseline <file> and --compare <file> for
 * before/after optimization measurement.
 *
 * Build:  make test-benchmarks
 * Run:    build/test_benchmarks [--save-baseline <file>] [--compare <file>]
 */

#include "memdbg/scanner/scan_simd.h"
#include "memdbg/scanner/scan_partition.h"
#include "memdbg/scanner/flashscan.h"
#include "memdbg/pal/lz4.h"
#include "memdbg/core/memdbg_protocol.h"
#include "bench_utils.h"

#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- Timing infrastructure ---- */

/* bench_now_ns and bench_bench_fill_pattern are provided by bench_utils.h */

typedef struct {
  const char *bench_name;
  double      total_sec;
  uint64_t    iterations;
  size_t      bytes_processed;
  double      throughput_mb_s;
  double      ops_per_sec;
} bench_result_t;

static bench_result_t g_results[128];
static int            g_result_count = 0;
static char           g_labels[128][96];

static void bench_record(const char *bname, double total_s,
                         uint64_t iters, size_t bytes) {
  if (g_result_count >= (int)(sizeof(g_results) / sizeof(g_results[0]))) {
    fprintf(stderr, "benchmark result capacity exceeded: %s\n", bname);
    return;
  }
  bench_result_t *r = &g_results[g_result_count];
  snprintf(g_labels[g_result_count], sizeof(g_labels[0]), "%s", bname);
  r->bench_name      = g_labels[g_result_count];
  r->total_sec       = total_s;
  r->iterations      = iters;
  r->bytes_processed = bytes;
  double denom       = total_s > 0.0 ? total_s : 1e-9;
  r->throughput_mb_s = ((double)bytes / (double)(1 << 20)) / denom;
  r->ops_per_sec     = (double)iters / denom;
  g_result_count++;
}

#if defined(__GNUC__) || defined(__clang__)
#define BENCH_NOINLINE __attribute__((noinline))
#else
#define BENCH_NOINLINE
#endif

static BENCH_NOINLINE void bench_memcpy_call(void *dst, const void *src,
                                             size_t size) {
  memcpy(dst, src, size);
}

static BENCH_NOINLINE int bench_memcmp_call(const void *lhs, const void *rhs,
                                            size_t size) {
  return memcmp(lhs, rhs, size);
}

/* ---- Helpers ---- */

static void fill_random_maps(memdbg_map_entry_t *maps, size_t count) {
  uint64_t base = 0x400000ULL;
  for (size_t i = 0; i < count; ++i) {
    maps[i].start      = base;
    maps[i].end        = base + 0x1000ULL + (uint64_t)(rand() % 0x100000);
    maps[i].protection = 3U;
    base               = maps[i].end + (uint64_t)(rand() % 0x10000);
  }
}

/* ---- Benchmark 1: SIMD exact match scan ---- */

static void bench_simd_scan(void) {
  printf("\n=== SIMD Exact Match Scan ===\n");
  const size_t HAY_SIZE = 128ULL * 1024 * 1024;
  uint8_t *haystack = (uint8_t *)malloc(HAY_SIZE);
  if (!haystack) { printf("  SKIP: malloc failed\n"); return; }

  uint32_t offsets[MEMDBG_SIMD_MAX_OFFSETS];
  int avail = memdbg_simd_exact_available(0, 1);
  printf("  SIMD available: %s\n", avail ? "yes" : "no (fallback memcmp)");

  uint32_t value_len[] = {1, 2, 4, 8};
  for (int vi = 0; vi < 4; ++vi) {
    uint32_t vlen = value_len[vi];
    uint8_t needle[8] = {0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42};
    bench_fill_pattern(haystack, HAY_SIZE, 0xDEADBEEFULL);
    for (size_t p = 0; p < HAY_SIZE - vlen; p += 4096)
      memcpy(haystack + p, needle, vlen);

    const uint64_t ITERS = 50;
    char label[64];
    snprintf(label, sizeof(label), "SIMD find exact %" PRIu32 "-byte", vlen);

    uint64_t t0 = bench_now_ns();
    size_t total_matches = 0;
    for (uint64_t i = 0; i < ITERS; ++i)
      total_matches += memdbg_simd_find_exact(0, haystack, HAY_SIZE, needle,
                                              vlen, offsets, MEMDBG_SIMD_MAX_OFFSETS);
    uint64_t t1 = bench_now_ns();
    double sec = (double)(t1 - t0) / 1e9;
    printf("  %-48s %10.4f s  %" PRIu64 " matches/iter\n",
           label, sec, (uint64_t)(total_matches / ITERS));
    bench_record(label, sec, ITERS, ITERS * HAY_SIZE);
  }
  free(haystack);
}

/* ---- Benchmark 2: FlashScan snap_compare ---- */

static void bench_snap_compare(void) {
  printf("\n=== FlashScan snap_compare ===\n");
  const uint64_t ITERS  = 100000000ULL; /* 100M for better resolution */
  const uint64_t BATCH  = 1000;
  uint64_t batches      = ITERS / BATCH;
  uint8_t mem[8], pattern[8], prev[8], between[8];

  /* exact match (cmp_type 0) */
  memset(mem, 0x55, 8); memset(pattern, 0x55, 8);
  volatile int vdummy = 0;
  uint64_t t0 = bench_now_ns();
  for (uint64_t i = 0; i < batches; ++i)
    for (uint64_t j = 0; j < BATCH; ++j)
      vdummy += snap_compare(mem, pattern, NULL, NULL, NULL, 0, 8);
  uint64_t t1 = bench_now_ns();
  double sec = (double)(t1 - t0) / 1e9;
  printf("  %-48s %10.6f s  (%" PRIu64 " iters)\n",
         "snap_compare exact 8-byte:", sec, ITERS);
  bench_record("FlashScan snap_compare (8B exact)", sec, ITERS, ITERS * 8);

  /* between (cmp_type 4) */
  memset(mem, 0x77, 8); memset(pattern, 0x55, 8); memset(between, 0xAA, 8);
  vdummy = 0; t0 = bench_now_ns();
  for (uint64_t i = 0; i < batches; ++i)
    for (uint64_t j = 0; j < BATCH; ++j)
      vdummy += snap_compare(mem, pattern, NULL, between, NULL, 4, 8);
  t1 = bench_now_ns(); sec = (double)(t1 - t0) / 1e9;
  printf("  %-48s %10.6f s\n", "snap_compare between 8-byte:", sec);
  bench_record("FlashScan snap_compare (8B between)", sec, ITERS, ITERS * 8);

  /* changed (cmp_type 3) */
  memset(mem, 0xAA, 8); memset(pattern, 0, 8); memset(prev, 0x55, 8);
  vdummy = 0; t0 = bench_now_ns();
  for (uint64_t i = 0; i < batches; ++i)
    for (uint64_t j = 0; j < BATCH; ++j)
      vdummy += snap_compare(mem, pattern, prev, NULL, NULL, 3, 8);
  t1 = bench_now_ns(); sec = (double)(t1 - t0) / 1e9;
  printf("  %-48s %10.6f s\n", "snap_compare changed 8-byte:", sec);
  bench_record("FlashScan snap_compare (8B changed)", sec, ITERS, ITERS * 8);

  /* 4-byte changed */
  vdummy = 0; t0 = bench_now_ns();
  for (uint64_t i = 0; i < batches; ++i)
    for (uint64_t j = 0; j < BATCH; ++j)
      vdummy += snap_compare(mem, pattern, prev, NULL, NULL, 3, 4);
  t1 = bench_now_ns(); sec = (double)(t1 - t0) / 1e9;
  printf("  %-48s %10.6f s\n", "snap_compare changed 4-byte:", sec);
  bench_record("FlashScan snap_compare (4B changed)", sec, ITERS, ITERS * 4);
  (void)vdummy;
}

/* ---- Benchmark 3: LZ4 compress + decompress ---- */

static void bench_lz4(void) {
  printf("\n=== LZ4 Compression ===\n");
  size_t sizes[] = {4096, 65536, 262144, 1048576};
  for (int si = 0; si < 4; ++si) {
    size_t src_size = sizes[si];
    uint8_t *src = (uint8_t *)malloc(src_size);
    if (!src) { printf("  SKIP %zuB: malloc failed\n", src_size); continue; }
    bench_fill_pattern(src, src_size, (uint64_t)(src_size * 0x9E3779B9ULL));

    int bound = lz4_compress_bound((int)src_size);
    uint8_t *comp = (uint8_t *)malloc((size_t)bound);
    uint8_t *decomp = (uint8_t *)malloc(src_size);
    if (!comp || !decomp) {
      free(src); free(comp); free(decomp);
      printf("  SKIP %zuB: malloc failed\n", src_size); continue;
    }

    const uint64_t ITERS = (src_size <= 65536) ? 500ULL : 50ULL;
    char label[64];

    /* Compress */
    snprintf(label, sizeof(label), "LZ4 compress %zuB", src_size);
    uint64_t t0 = bench_now_ns(); int total_out = 0;
    for (uint64_t i = 0; i < ITERS; ++i)
      total_out += lz4_compress_default((const char *)src, (char *)comp,
                                        (int)src_size, bound);
    uint64_t t1 = bench_now_ns();
    double sec = (double)(t1 - t0) / 1e9;
    int comp_len = total_out / (int)ITERS;
    double ratio = comp_len > 0 ? (double)(int)src_size / (double)comp_len : 0.0;
    printf("  %-48s %10.4f s  (avg %d B out, ratio %.2f)\n",
           label, sec, comp_len, ratio);
    bench_record(label, sec, ITERS, ITERS * src_size);

    /* Decompress */
    snprintf(label, sizeof(label), "LZ4 decompress %zuB", src_size);
    t0 = bench_now_ns(); int total_dec = 0;
    for (uint64_t i = 0; i < ITERS; ++i)
      total_dec += lz4_decompress_safe((const char *)comp, (char *)decomp,
                                       comp_len, (int)src_size);
    t1 = bench_now_ns(); sec = (double)(t1 - t0) / 1e9;
    printf("  %-48s %10.4f s  (avg %d B out)\n",
           label, sec, total_dec / (int)ITERS);
    bench_record(label, sec, ITERS, ITERS * src_size);
    free(src); free(comp); free(decomp);
  }
}

/* ---- Benchmark 4: LZ4 with compressible data ---- */

static void bench_fill_repeat(uint8_t *buf, size_t len,
                              const uint8_t *pattern, size_t pat_len) {
  for (size_t i = 0; i < len; ++i)
    buf[i] = pattern[i % pat_len];
}

static void bench_fill_text(uint8_t *buf, size_t len) {
  const char *phrase = "The quick brown fox jumps over the lazy dog. ";
  size_t plen = strlen(phrase);
  for (size_t i = 0; i < len; ++i)
    buf[i] = (uint8_t)phrase[i % plen];
}

static void bench_fill_json(uint8_t *buf, size_t len) {
  /* Simulate repetitive JSON with numbered keys.
   * Use a fixed 32-byte pattern to avoid snprintf return-value pitfalls. */
  const char tmpl[] = "\"key_0000\":\"value_0000\",";
  for (size_t i = 0; i < len; ++i)
    buf[i] = (uint8_t)tmpl[i % (sizeof(tmpl) - 1U)];
}

static void bench_lz4_compressible(void) {
  printf("\n=== LZ4 Compressible Data (with long matches) ===\n");
  printf("  (Exercises word-at-a-time match copy in decompressor)\n");

  size_t sizes[] = {4096, 65536, 262144, 1048576};
  const char *size_names[] = {"4K", "64K", "256K", "1M"};

  /* Data generators: {name, pattern, pattern_len} */
  struct {
    const char *name;
    void (*fill)(uint8_t *, size_t);
  } patterns[] = {
    {"AAAA repeat (offset=1)",  NULL},
    {"ABCD repeat (offset=4)",  NULL},
    {"text (repeated phrase)", bench_fill_text},
    {"JSON-like (repeated keys)", bench_fill_json},
  };
  const uint8_t pat_aaaa[] = {'A', 'A', 'A', 'A'};
  const uint8_t pat_abcd[] = {'A', 'B', 'C', 'D'};

  for (int pi = 0; pi < 4; ++pi) {
    printf("\n--- Pattern: %s ---\n", patterns[pi].name);
    for (int si = 0; si < 4; ++si) {
      size_t src_size = sizes[si];
      uint8_t *src = (uint8_t *)malloc(src_size);
      if (!src) { printf("  SKIP %s: malloc failed\n", size_names[si]); continue; }

      /* Fill with compressible pattern */
      if (pi == 0) bench_fill_repeat(src, src_size, pat_aaaa, 1);
      else if (pi == 1) bench_fill_repeat(src, src_size, pat_abcd, 4);
      else patterns[pi].fill(src, src_size);

      int bound = lz4_compress_bound((int)src_size);
      uint8_t *comp = (uint8_t *)malloc((size_t)bound);
      uint8_t *decomp = (uint8_t *)malloc(src_size);
      if (!comp || !decomp) {
        free(src); free(comp); free(decomp);
        printf("  SKIP %s: malloc failed\n", size_names[si]); continue;
      }

      const uint64_t ITERS = (src_size <= 65536) ? 500ULL : 50ULL;
      char label[64];

      /* Compress */
      snprintf(label, sizeof(label), "LZ4 cmpbl compress %s %s",
               patterns[pi].name, size_names[si]);
      uint64_t t0 = bench_now_ns(); int total_out = 0;
      for (uint64_t i = 0; i < ITERS; ++i)
        total_out += lz4_compress_default((const char *)src, (char *)comp,
                                          (int)src_size, bound);
      uint64_t t1 = bench_now_ns();
      double sec = (double)(t1 - t0) / 1e9;
      int comp_len = total_out / (int)ITERS;
      double ratio = comp_len > 0 ? (double)(int)src_size / (double)comp_len : 0.0;
      printf("  %-48s %10.4f s  (compress %6d -> %5d B, ratio %5.0f:1)\n",
             label, sec, (int)src_size, comp_len, ratio);
      bench_record(label, sec, ITERS, ITERS * src_size);

      /* Decompress */
      snprintf(label, sizeof(label), "LZ4 cmpbl decompress %s %s",
               patterns[pi].name, size_names[si]);
      t0 = bench_now_ns(); int total_dec = 0;
      for (uint64_t i = 0; i < ITERS; ++i)
        total_dec += lz4_decompress_safe((const char *)comp, (char *)decomp,
                                         comp_len, (int)src_size);
      t1 = bench_now_ns();
      double dec_sec = (double)(t1 - t0) / 1e9;
      printf("  %-48s %10.4f s  (avg %d B out)\n",
             label, dec_sec, total_dec / (int)ITERS);
      bench_record(label, dec_sec, ITERS, ITERS * src_size);

      /* Verify roundtrip */
      int ok = (total_dec / (int)ITERS == (int)src_size &&
                memcmp(src, decomp, src_size) == 0);
      if (!ok) printf("  WARN: roundtrip mismatch!\n");

      free(src); free(comp); free(decomp);
    }
  }
}

static void bench_scan_partition(void) {
  printf("\n=== Scan Partition ===\n");
  size_t map_counts[] = {64, 256, 1024, 4096};
  size_t thread_counts[] = {4, 8, 16};

  for (int mi = 0; mi < 4; ++mi) {
    size_t map_count = map_counts[mi];
    memdbg_map_entry_t *maps =
        (memdbg_map_entry_t *)malloc(map_count * sizeof(*maps));
    if (!maps) { printf("  SKIP %zu maps\n", map_count); continue; }
    fill_random_maps(maps, map_count);

    for (int ti = 0; ti < 3; ++ti) {
      size_t num_threads = thread_counts[ti];
      scan_partition_slot_t *slots =
          (scan_partition_slot_t *)calloc(num_threads, sizeof(*slots));
      if (!slots) continue;

      const uint64_t ITERS = 2000;
      char label[64];
      snprintf(label, sizeof(label), "partition maps %zux%zu threads",
               map_count, num_threads);

      uint64_t t0 = bench_now_ns(); size_t used = 0;
      for (uint64_t i = 0; i < ITERS; ++i)
        (void)partition_maps_by_bytes(maps, map_count, 3U, 0, 0, 4096,
                                      num_threads, slots, &used);
      uint64_t t1 = bench_now_ns();
      double sec = (double)(t1 - t0) / 1e9;
      printf("  %-48s %10.4f s  (%zu slots)\n", label, sec, used);
      bench_record(label, sec, ITERS, map_count * sizeof(*maps) * ITERS);
      free(slots);
    }
    free(maps);
  }
}

/* ---- Benchmark 5: memcpy throughput (DMAP proxy) ---- */

static void bench_memcpy_throughput(void) {
  printf("\n=== Memory Copy Throughput (DMAP proxy) ===\n");
  size_t sizes[] = {4096, 65536, 262144, 1048576, 16777216};
  for (int si = 0; si < 5; ++si) {
    size_t chunk = sizes[si];
    uint8_t *src = (uint8_t *)malloc(chunk);
    uint8_t *dst = (uint8_t *)malloc(chunk);
    if (!src || !dst) { free(src); free(dst); continue; }
    bench_fill_pattern(src, chunk, 0x12345678ULL);

    /* Process 16 GiB at every size: long enough for stable timing without
       making small-block cases dominate the whole suite. */
    uint64_t ITERS = (16ULL << 30) / chunk;
    if (ITERS < 16U) ITERS = 16U;

    char label[64];
    snprintf(label, sizeof(label), "memcpy %zuB (DMAP proxy)", chunk);

    uint64_t t0 = bench_now_ns();
    for (uint64_t i = 0; i < ITERS; ++i)
      bench_memcpy_call(dst, src, chunk);
    uint64_t t1 = bench_now_ns();
    /* Make the copied state observable after the timed loop. */
    volatile uint8_t copied = dst[(chunk - 1U) / 2U];
    (void)copied;
    double sec = (double)(t1 - t0) / 1e9;
    printf("  %-48s %10.4f s  (%" PRIu64 " iters, %zu B)\n",
           label, sec, ITERS, chunk);
    bench_record(label, sec, ITERS, ITERS * chunk);
    free(src); free(dst);
  }
}

/* ---- Benchmark 6: memcmp throughput (scan compare proxy) ---- */

static void bench_memcmp_throughput(void) {
  printf("\n=== Memory Compare Throughput (scan compare proxy) ===\n");
  size_t sizes[] = {4096, 65536, 262144, 1048576};
  for (int si = 0; si < 4; ++si) {
    size_t chunk = sizes[si];
    uint8_t *a = (uint8_t *)malloc(chunk);
    uint8_t *b = (uint8_t *)malloc(chunk);
    if (!a || !b) { free(a); free(b); continue; }
    bench_fill_pattern(a, chunk, 0xAAAAAAAAULL);
    bench_fill_pattern(b, chunk, 0xAAAAAAAAULL);

    uint64_t ITERS = (16ULL << 30) / chunk;
    if (ITERS < 16U) ITERS = 16U;

    char label[64];
    snprintf(label, sizeof(label), "memcmp %zuB (scan compare proxy)", chunk);

    volatile int vdummy = 0;
    uint64_t t0 = bench_now_ns();
    for (uint64_t i = 0; i < ITERS; ++i) {
      /* Change the last byte so the comparison must inspect the complete
         range and cannot be hoisted out as an invariant equal-buffer test. */
      b[chunk - 1U] ^= (uint8_t)((i & 1U) + 1U);
      vdummy += bench_memcmp_call(a, b, chunk);
    }
    uint64_t t1 = bench_now_ns();
    double sec = (double)(t1 - t0) / 1e9;
    printf("  %-48s %10.4f s  (%" PRIu64 " iters)\n", label, sec, ITERS);
    bench_record(label, sec, ITERS, ITERS * chunk);
    (void)vdummy;
    free(a); free(b);
  }
}

/* ---- Benchmark 7: Scan + LZ4 compress pipeline ---- */

static void bench_scan_compress_pipeline(void) {
  printf("\n=== Scan + LZ4 Compress Pipeline ===\n");
  printf("  (Simulates daemon: SIMD scan offsets -> LZ4 compress -> framed response)\n");

  const size_t HAY_SIZE = 128ULL * 1024 * 1024;
  uint8_t *haystack = (uint8_t *)malloc(HAY_SIZE);
  if (!haystack) { printf("  SKIP: malloc failed\n"); return; }

  /* Accumulate offsets across multiple scan passes to simulate 200K results
   * (daemon's max_scan_results default). */
  const size_t MAX_OFFSETS = 200000U;
  uint32_t *offsets = (uint32_t *)malloc(MAX_OFFSETS * sizeof(uint32_t));
  if (!offsets) { free(haystack); printf("  SKIP: malloc failed\n"); return; }

  uint32_t value_len[] = {1, 4, 8};
  for (int vi = 0; vi < 3; ++vi) {
    uint32_t vlen = value_len[vi];
    uint8_t needle[8] = {0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42};
    bench_fill_pattern(haystack, HAY_SIZE, 0xDEADBEEFULL);
    /* Plant ~32K matches per 128MB pass → need ~6 passes for 200K */
    for (size_t p = 0; p < HAY_SIZE - vlen; p += 4096)
      memcpy(haystack + p, needle, vlen);

    /* Accumulate offsets across passes into a contiguous array. */
    size_t total_hits = 0;
    uint32_t chunk[MEMDBG_SIMD_MAX_OFFSETS];

    const uint64_t ITERS = 20;
    char label[64];

    /* Phase 1: Scan only */
    snprintf(label, sizeof(label),
             "Pipeline scan %" PRIu32 "B (accum %zu offsets)",
             vlen, MAX_OFFSETS);
    uint64_t t0 = bench_now_ns();
    for (uint64_t i = 0; i < ITERS; ++i) {
      total_hits = 0;
      while (total_hits < MAX_OFFSETS) {
        size_t n = memdbg_simd_find_exact(0, haystack, HAY_SIZE, needle,
                                          vlen, chunk, MEMDBG_SIMD_MAX_OFFSETS);
        if (n == 0) break;
        size_t to_copy = total_hits + n > MAX_OFFSETS
                             ? MAX_OFFSETS - total_hits
                             : n;
        memcpy(offsets + total_hits, chunk, to_copy * sizeof(uint32_t));
        total_hits += to_copy;
        if (total_hits >= MAX_OFFSETS) break;
      }
    }
    uint64_t t1 = bench_now_ns();
    double scan_sec = (double)(t1 - t0) / 1e9;
    double scan_mb_s = ((double)(HAY_SIZE * ITERS) / (double)(1 << 20)) / scan_sec;
    printf("  %-48s %10.4f s  (scan %.2f MB/s)\n",
           label, scan_sec, scan_mb_s);
    bench_record(label, scan_sec, ITERS, ITERS * HAY_SIZE);

    /* Phase 2: Compress offset array with LZ4.
     * The offset array is monotonically increasing 32-bit ints — highly
     * compressible (LZ4 will find many 4-byte matches). */
    size_t data_len = MAX_OFFSETS * sizeof(uint32_t);
    int bound = lz4_compress_bound((int)data_len);
    uint8_t *comp = (uint8_t *)malloc((size_t)bound);
    if (!comp) { free(haystack); free(offsets); return; }

    snprintf(label, sizeof(label),
             "Pipeline compress %zuB offsets (%" PRIu32 "B needle)",
             data_len, vlen);
    t0 = bench_now_ns();
    int comp_len = 0;
    for (uint64_t i = 0; i < ITERS; ++i)
      comp_len = lz4_compress_default((const char *)offsets, (char *)comp,
                                      (int)data_len, bound);
    t1 = bench_now_ns();
    double comp_sec = (double)(t1 - t0) / 1e9;
    double comp_mb_s =
        ((double)(data_len * ITERS) / (double)(1 << 20)) / comp_sec;
    double ratio = comp_len > 0 ? (double)data_len / (double)comp_len : 0.0;
    printf("  %-48s %10.4f s  (compress %.2f MB/s, %d -> %d B, ratio %.1f:1)\n",
           label, comp_sec, comp_mb_s, (int)data_len, comp_len, ratio);
    bench_record(label, comp_sec, ITERS, ITERS * data_len);

    /* Phase 3: Combined pipeline (scan + compress) */
    snprintf(label, sizeof(label),
             "Pipeline scan+compress %" PRIu32 "B (end-to-end)", vlen);
    t0 = bench_now_ns();
    for (uint64_t i = 0; i < ITERS; ++i) {
      /* Scan */
      total_hits = 0;
      while (total_hits < MAX_OFFSETS) {
        size_t n = memdbg_simd_find_exact(0, haystack, HAY_SIZE, needle,
                                          vlen, chunk, MEMDBG_SIMD_MAX_OFFSETS);
        if (n == 0) break;
        size_t to_copy = total_hits + n > MAX_OFFSETS
                             ? MAX_OFFSETS - total_hits
                             : n;
        memcpy(offsets + total_hits, chunk, to_copy * sizeof(uint32_t));
        total_hits += to_copy;
        if (total_hits >= MAX_OFFSETS) break;
      }
      /* Compress */
      comp_len = lz4_compress_default((const char *)offsets, (char *)comp,
                                      (int)data_len, bound);
    }
    t1 = bench_now_ns();
    double combined_sec = (double)(t1 - t0) / 1e9;
    double combined_mb_s =
        ((double)((HAY_SIZE + data_len) * ITERS) / (double)(1 << 20)) /
        combined_sec;
    double scan_pct = (scan_sec / combined_sec) * 100.0;
    double comp_pct = (comp_sec / combined_sec) * 100.0;
    printf("  %-48s %10.4f s  (combined %.2f MB/s, %.0f%% scan + %.0f%% compress)\n",
           label, combined_sec, combined_mb_s, scan_pct, comp_pct);
    bench_record(label, combined_sec, ITERS,
                 ITERS * (HAY_SIZE + data_len));

    /* Verify roundtrip */
    uint8_t *decomp = (uint8_t *)malloc(data_len);
    if (decomp) {
      int dec = lz4_decompress_safe((const char *)comp, (char *)decomp,
                                    comp_len, (int)data_len);
      int ok = (dec == (int)data_len &&
                memcmp(offsets, decomp, data_len) == 0);
      printf("  %-48s %s\n", "  roundtrip verify", ok ? "PASS" : "FAIL");
      free(decomp);
    }
    free(comp);

    /* Show breakdown */
    printf("  --- Pipeline breakdown: scan %.4f s + compress %.4f s = %.4f s ---\n\n",
           scan_sec, comp_sec, combined_sec);
  }

  free(haystack);
  free(offsets);
}

static void bench_save_baseline(const char *path) {
  FILE *f = fopen(path, "w");
  if (!f) { fprintf(stderr, "Cannot write baseline: %s\n", path); return; }
  for (int i = 0; i < g_result_count; ++i) {
    bench_result_t *r = &g_results[i];
    fprintf(f, "%s\t%.6f\t%" PRIu64 "\t%zu\t%.2f\t%.0f\n",
            r->bench_name, r->total_sec, r->iterations,
            r->bytes_processed, r->throughput_mb_s, r->ops_per_sec);
  }
  fclose(f);
  printf("\nBaseline saved to %s (%d benchmarks)\n", path, g_result_count);
}

static void bench_compare_baseline(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) { fprintf(stderr, "Cannot read baseline: %s\n", path); return; }

  printf("\n================================================================================\n");
  printf("  BASELINE COMPARISON (vs %s)\n", path);
  printf("================================================================================\n");
  printf("  %-48s %10s  %10s  %8s\n",
         "Benchmark", "Before", "After", "Delta");
  printf("  ----------------------------------------------------------------------------\n");

  char line[256]; int b_idx = 0;
  while (fgets(line, sizeof(line), f) && b_idx < g_result_count) {
    char name[128]; double before_sec;
    if (sscanf(line, "%127[^\t]\t%lf", name, &before_sec) < 2) continue;

    bench_result_t *r = &g_results[b_idx];
    if (strcmp(name, r->bench_name) != 0) continue;

    double pct = ((before_sec - r->total_sec) / before_sec) * 100.0;
    const char *mark = pct > 0.5  ? "FASTER" :
                       pct < -0.5 ? "SLOWER" : "~same";
    printf("  %-48s %10.4f  %10.4f  %+7.1f%% %s\n",
           r->bench_name, before_sec, r->total_sec, pct, mark);
    b_idx++;
  }
  fclose(f);
  printf("================================================================================\n");
}

/* ---- Report ---- */

static void bench_print_summary(void) {
  printf("\n================================================================================\n");
  printf("  BENCHMARK SUMMARY\n");
  printf("================================================================================\n");
  printf("  %-48s %10s  %12s  %12s\n",
         "Benchmark", "Time(s)", "MB/s", "Ops/s");
  printf("  ----------------------------------------------------------------------------\n");
  for (int i = 0; i < g_result_count; ++i) {
    bench_result_t *r = &g_results[i];
    printf("  %-48s %10.4f  %12.2f  %12.0f\n",
           r->bench_name, r->total_sec, r->throughput_mb_s, r->ops_per_sec);
  }
  printf("================================================================================\n");
}

/* ---- Main ---- */

int main(int argc, char **argv) {
  const char *save_path    = NULL;
  const char *compare_path = NULL;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--save-baseline") == 0 && i + 1 < argc)
      save_path = argv[++i];
    else if (strcmp(argv[i], "--compare") == 0 && i + 1 < argc)
      compare_path = argv[++i];
    else if (strcmp(argv[i], "--help") == 0) {
      printf("Usage: test_benchmarks [--save-baseline <file>] [--compare <file>]\n");
      printf("  --save-baseline <f>   Save results as baseline\n");
      printf("  --compare <f>         Compare against saved baseline\n");
      return 0;
    }
  }

  printf("MemDBG Performance Benchmarks\nPlatform: ");
#if defined(__AVX512F__)
  printf("AVX-512\n");
#elif defined(__AVX2__)
  printf("AVX2\n");
#elif defined(__SSE2__)
  printf("SSE2\n");
#elif defined(__aarch64__) && defined(__ARM_NEON)
  printf("ARM NEON\n");
#else
  printf("scalar\n");
#endif

  bench_simd_scan();
  bench_snap_compare();
  bench_lz4();
  bench_lz4_compressible();
  bench_scan_partition();
  bench_scan_compress_pipeline();
  bench_memcpy_throughput();
  bench_memcmp_throughput();

  bench_print_summary();

  if (save_path)    bench_save_baseline(save_path);
  if (compare_path) bench_compare_baseline(compare_path);

  printf("\nTotal benchmarks: %d\n", g_result_count);
  return 0;
}
