/*
 * memDBG - NEON instruction-level profiler for SIMD scan bottleneck analysis.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Isolates each NEON instruction used in the 1-byte and 2-byte scan paths
 * to identify which instruction causes the 5× throughput gap.
 *
 * Build:  cc -std=c11 -O2 -Isrc -Iinclude -D_DARWIN_C_SOURCE \
 *              tests/test_neon_profile.c -o build/test_neon_profile
 * Run:    build/test_neon_profile
 */

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ITERS    50000000ULL  /* 50M iterations per test */
#define UNROLL   8U

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void run_test(const char *name, void (*fn)(void)) {
  uint64_t t0 = now_ns();
  fn();
  uint64_t t1 = now_ns();
  double ns_per = (double)(t1 - t0) / (double)ITERS;
  printf("  %-52s %8.2f ns/iter\n", name, ns_per);
}

/* ===================================================================
 * Instruction-level micro-benchmarks
 * =================================================================== */

#if defined(__aarch64__) && defined(__ARM_NEON)

static uint8_t  g_buf8[16]  __attribute__((aligned(16)));
static uint16_t g_buf16[8]  __attribute__((aligned(16)));
static uint32_t g_buf32[4]  __attribute__((aligned(16)));
static uint64_t g_buf64[2]  __attribute__((aligned(16)));
static uint8_t  g_dst8[16]  __attribute__((aligned(16)));
static uint16_t g_dst16[8]  __attribute__((aligned(16)));
static uint8_t  g_lanes8[16];
static uint16_t g_lanes16[8];
static uint32_t g_lanes32[4];
static volatile uint64_t g_sink;

/* --- Load throughput --- */

static void bench_vld1q_u8(void) {
  for (uint64_t n = 0; n < ITERS; n += UNROLL) {
    uint8x16_t a = vld1q_u8(g_buf8);  (void)a;
    uint8x16_t b = vld1q_u8(g_buf8);  (void)b;
    uint8x16_t c = vld1q_u8(g_buf8);  (void)c;
    uint8x16_t d = vld1q_u8(g_buf8);  (void)d;
    uint8x16_t e = vld1q_u8(g_buf8);  (void)e;
    uint8x16_t f = vld1q_u8(g_buf8);  (void)f;
    uint8x16_t g = vld1q_u8(g_buf8);  (void)g;
    uint8x16_t h = vld1q_u8(g_buf8);  (void)h;
    g_sink = vgetq_lane_u64(vreinterpretq_u64_u8(h), 0);
  }
}

static void bench_vld1q_u16(void) {
  uint16x8_t pat = vdupq_n_u16(0x4242);
  for (uint64_t n = 0; n < ITERS; n += UNROLL) {
    uint16x8_t a = vld1q_u16(g_buf16); (void)a;
    uint16x8_t b = vld1q_u16(g_buf16); (void)b;
    uint16x8_t c = vld1q_u16(g_buf16); (void)c;
    uint16x8_t d = vld1q_u16(g_buf16); (void)d;
    uint16x8_t e = vld1q_u16(g_buf16); (void)e;
    uint16x8_t f = vld1q_u16(g_buf16); (void)f;
    uint16x8_t g = vld1q_u16(g_buf16); (void)g;
    uint16x8_t h = vld1q_u16(g_buf16); (void)h;
    g_sink = vgetq_lane_u64(vreinterpretq_u64_u16(h), 0);
  }
}

/* --- Compare throughput --- */

static uint8x16_t g_pat8;
static uint16x8_t g_pat16;

static void bench_vceqq_u8(void) {
  for (uint64_t n = 0; n < ITERS; n += UNROLL) {
    uint8x16_t a = vceqq_u8(vld1q_u8(g_buf8), g_pat8); (void)a;
    uint8x16_t b = vceqq_u8(vld1q_u8(g_buf8), g_pat8); (void)b;
    uint8x16_t c = vceqq_u8(vld1q_u8(g_buf8), g_pat8); (void)c;
    uint8x16_t d = vceqq_u8(vld1q_u8(g_buf8), g_pat8); (void)d;
    uint8x16_t e = vceqq_u8(vld1q_u8(g_buf8), g_pat8); (void)e;
    uint8x16_t f = vceqq_u8(vld1q_u8(g_buf8), g_pat8); (void)f;
    uint8x16_t g = vceqq_u8(vld1q_u8(g_buf8), g_pat8); (void)g;
    uint8x16_t h = vceqq_u8(vld1q_u8(g_buf8), g_pat8); (void)h;
    g_sink = vgetq_lane_u64(vreinterpretq_u64_u8(h), 0);
  }
}

static void bench_vceqq_u16(void) {
  for (uint64_t n = 0; n < ITERS; n += UNROLL) {
    uint16x8_t a = vceqq_u16(vld1q_u16(g_buf16), g_pat16); (void)a;
    uint16x8_t b = vceqq_u16(vld1q_u16(g_buf16), g_pat16); (void)b;
    uint16x8_t c = vceqq_u16(vld1q_u16(g_buf16), g_pat16); (void)c;
    uint16x8_t d = vceqq_u16(vld1q_u16(g_buf16), g_pat16); (void)d;
    uint16x8_t e = vceqq_u16(vld1q_u16(g_buf16), g_pat16); (void)e;
    uint16x8_t f = vceqq_u16(vld1q_u16(g_buf16), g_pat16); (void)f;
    uint16x8_t g = vceqq_u16(vld1q_u16(g_buf16), g_pat16); (void)g;
    uint16x8_t h = vceqq_u16(vld1q_u16(g_buf16), g_pat16); (void)h;
    g_sink = vgetq_lane_u64(vreinterpretq_u64_u16(h), 0);
  }
}

/* --- Store throughput --- */

static void bench_vst1q_u8(void) {
  uint8x16_t val = vdupq_n_u8(0x42);
  for (uint64_t n = 0; n < ITERS; n += UNROLL) {
    vst1q_u8(g_dst8, val);
    vst1q_u8(g_dst8, val);
    vst1q_u8(g_dst8, val);
    vst1q_u8(g_dst8, val);
    vst1q_u8(g_dst8, val);
    vst1q_u8(g_dst8, val);
    vst1q_u8(g_dst8, val);
    vst1q_u8(g_dst8, val);
  }
}

static void bench_vst1q_u16(void) {
  uint16x8_t val = vdupq_n_u16(0x4242);
  for (uint64_t n = 0; n < ITERS; n += UNROLL) {
    vst1q_u16(g_dst16, val);
    vst1q_u16(g_dst16, val);
    vst1q_u16(g_dst16, val);
    vst1q_u16(g_dst16, val);
    vst1q_u16(g_dst16, val);
    vst1q_u16(g_dst16, val);
    vst1q_u16(g_dst16, val);
    vst1q_u16(g_dst16, val);
  }
}

/* --- Lane extraction methods --- */

/* Method A (1-byte style): vst1q + scalar lane loop */
static void bench_extract_vst1q_u8_loop(void) {
  uint8x16_t cmp = vdupq_n_u8(0xFF);
  for (uint64_t n = 0; n < ITERS; n += UNROLL) {
    for (int u = 0; u < UNROLL; u++) {
      uint8_t lanes[16];
      vst1q_u8(lanes, cmp);
      for (int k = 0; k < 16; k++) g_sink += lanes[k];
    }
  }
}

/* Method B (2-byte style): vst1q_u16 + scalar lane loop */
static void bench_extract_vst1q_u16_loop(void) {
  uint16x8_t cmp = vdupq_n_u16(0xFFFF);
  for (uint64_t n = 0; n < ITERS; n += UNROLL) {
    for (int u = 0; u < UNROLL; u++) {
      uint16_t lanes[8];
      vst1q_u16(lanes, cmp);
      for (int k = 0; k < 8; k++) g_sink += lanes[k];
    }
  }
}

/* Method C: vshrn_n_u16 + vget_lane_u64 + shift loop */
static void bench_extract_vshrn_shift(void) {
  uint16x8_t cmp = vdupq_n_u16(0xFFFF);
  for (uint64_t n = 0; n < ITERS; n += UNROLL) {
    for (int u = 0; u < UNROLL; u++) {
      uint8x8_t narrow = vshrn_n_u16(cmp, 8);
      uint64_t mask = vget_lane_u64(vreinterpret_u64_u8(narrow), 0);
      for (int k = 0; k < 8; k++) { g_sink += (mask & 0xFFULL); mask >>= 8; }
    }
  }
}

/* Method D: vgetq_lane_u16 × 8 direct extraction */
static void bench_extract_vget_lane_u16_x8(void) {
  uint16x8_t cmp = vdupq_n_u16(0xFFFF);
  for (uint64_t n = 0; n < ITERS; n += UNROLL) {
    for (int u = 0; u < UNROLL; u++) {
      g_sink += vgetq_lane_u16(cmp, 0);
      g_sink += vgetq_lane_u16(cmp, 1);
      g_sink += vgetq_lane_u16(cmp, 2);
      g_sink += vgetq_lane_u16(cmp, 3);
      g_sink += vgetq_lane_u16(cmp, 4);
      g_sink += vgetq_lane_u16(cmp, 5);
      g_sink += vgetq_lane_u16(cmp, 6);
      g_sink += vgetq_lane_u16(cmp, 7);
    }
  }
}

/* --- Reinterpret cost --- */

static void bench_vreinterpret_u16_u8(void) {
  uint8x16_t raw = vdupq_n_u8(0x42);
  for (uint64_t n = 0; n < ITERS; n += UNROLL) {
    uint16x8_t a = vreinterpretq_u16_u8(raw); (void)a;
    uint16x8_t b = vreinterpretq_u16_u8(raw); (void)b;
    uint16x8_t c = vreinterpretq_u16_u8(raw); (void)c;
    uint16x8_t d = vreinterpretq_u16_u8(raw); (void)d;
    uint16x8_t e = vreinterpretq_u16_u8(raw); (void)e;
    uint16x8_t f = vreinterpretq_u16_u8(raw); (void)f;
    uint16x8_t g = vreinterpretq_u16_u8(raw); (void)g;
    uint16x8_t h = vreinterpretq_u16_u8(raw); (void)h;
    g_sink = vgetq_lane_u64(vreinterpretq_u64_u16(h), 0);
  }
}

/* --- Full 1-byte loop (reference) --- */

static void bench_full_1byte_loop(void) {
  uint8x16_t pat = vdupq_n_u8(0x42);
  for (uint64_t n = 0; n < ITERS; n++) {
    uint8x16_t chunk = vld1q_u8(g_buf8);
    uint8x16_t cmp   = vceqq_u8(chunk, pat);
    uint8_t lanes[16];
    vst1q_u8(lanes, cmp);
    for (int k = 0; k < 16; k++) {
      if (lanes[k]) g_sink += (uint64_t)k;
    }
  }
}

/* --- Full 2-byte loop variants --- */

/* Variant A: vld1q_u16 + vceqq_u16 + vst1q_u16 + lane loop (original) */
static void bench_full_2byte_vld1q_u16(void) {
  uint8x16_t pat8 = vreinterpretq_u8_u16(vdupq_n_u16(0x4242));
  for (uint64_t n = 0; n < ITERS; n++) {
    uint16x8_t chunk = vld1q_u16(g_buf16);
    uint16x8_t cmp   = vceqq_u16(chunk, vreinterpretq_u16_u8(pat8));
    uint16_t lanes[8];
    vst1q_u16(lanes, cmp);
    for (int k = 0; k < 8; k++) {
      if (lanes[k]) g_sink += (uint64_t)(k * 2);
    }
  }
}

/* Variant B: vld1q_u8 + reinterpret + vceqq_u16 + vst1q_u16 + lane loop */
static void bench_full_2byte_vld1q_u8(void) {
  uint16x8_t pat16 = vdupq_n_u16(0x4242);
  for (uint64_t n = 0; n < ITERS; n++) {
    uint8x16_t raw   = vld1q_u8(g_buf8);
    uint16x8_t chunk = vreinterpretq_u16_u8(raw);
    uint16x8_t cmp   = vceqq_u16(chunk, pat16);
    uint16_t lanes[8];
    vst1q_u16(lanes, cmp);
    for (int k = 0; k < 8; k++) {
      if (lanes[k]) g_sink += (uint64_t)(k * 2);
    }
  }
}

/* Variant C: vld1q_u8 + vceqq_u16 + vshrn + shift (no store) */
static void bench_full_2byte_vshrn(void) {
  uint16x8_t pat16 = vdupq_n_u16(0x4242);
  for (uint64_t n = 0; n < ITERS; n++) {
    uint8x16_t raw   = vld1q_u8(g_buf8);
    uint16x8_t chunk = vreinterpretq_u16_u8(raw);
    uint16x8_t cmp   = vceqq_u16(chunk, pat16);
    uint8x8_t narrow = vshrn_n_u16(cmp, 8);
    uint64_t mask    = vget_lane_u64(vreinterpret_u64_u8(narrow), 0);
    for (int k = 0; k < 8; k++) {
      if (mask & 0xFFULL) g_sink += (uint64_t)(k * 2);
      mask >>= 8;
    }
  }
}

/* Variant D: vld1q_u8 + vceqq_u16 + vgetq_lane_u16 × 8 (no store, direct extract) */
static void bench_full_2byte_vget_lane(void) {
  uint16x8_t pat16 = vdupq_n_u16(0x4242);
  for (uint64_t n = 0; n < ITERS; n++) {
    uint8x16_t raw   = vld1q_u8(g_buf8);
    uint16x8_t chunk = vreinterpretq_u16_u8(raw);
    uint16x8_t cmp   = vceqq_u16(chunk, pat16);
    if (vgetq_lane_u16(cmp, 0)) g_sink += 0;
    if (vgetq_lane_u16(cmp, 1)) g_sink += 2;
    if (vgetq_lane_u16(cmp, 2)) g_sink += 4;
    if (vgetq_lane_u16(cmp, 3)) g_sink += 6;
    if (vgetq_lane_u16(cmp, 4)) g_sink += 8;
    if (vgetq_lane_u16(cmp, 5)) g_sink += 10;
    if (vgetq_lane_u16(cmp, 6)) g_sink += 12;
    if (vgetq_lane_u16(cmp, 7)) g_sink += 14;
  }
}

#endif /* __aarch64__ && __ARM_NEON */

int main(void) {
#if defined(__aarch64__) && defined(__ARM_NEON)
  setvbuf(stdout, NULL, _IONBF, 0);

  /* Initialize buffers */
  memset(g_buf8,  0x42, sizeof(g_buf8));
  memset(g_buf16, 0x42, sizeof(g_buf16));
  g_pat8  = vdupq_n_u8(0x42);
  g_pat16 = vdupq_n_u16(0x4242);

  printf("=== NEON Instruction Profiling (Apple Silicon) ===\n");
  printf("Iterations per test: %llu M, unroll: %u×\n\n",
         (unsigned long long)(ITERS / 1000000ULL), UNROLL);

  /* Section 1: Load throughput */
  printf("--- Load throughput ---\n");
  run_test("vld1q_u8  (1-byte path load)",           bench_vld1q_u8);
  run_test("vld1q_u16 (2-byte path load)",           bench_vld1q_u16);
  printf("  → Delta: load u16 vs u8\n\n");

  /* Section 2: Compare throughput */
  printf("--- Compare throughput ---\n");
  run_test("vceqq_u8  (1-byte path compare)",        bench_vceqq_u8);
  run_test("vceqq_u16 (2-byte path compare)",        bench_vceqq_u16);
  printf("  → Delta: compare u16 vs u8\n\n");

  /* Section 3: Store throughput */
  printf("--- Store throughput ---\n");
  run_test("vst1q_u8  (1-byte path store)",          bench_vst1q_u8);
  run_test("vst1q_u16 (2-byte path store)",          bench_vst1q_u16);
  printf("  → Delta: store u16 vs u8\n\n");

  /* Section 4: Reinterpret cost */
  printf("--- Reinterpret cost ---\n");
  run_test("vreinterpretq_u16_u8 (zero-cost check)",  bench_vreinterpret_u16_u8);
  printf("  → Should be ~0 ns/iter (compile-time only)\n\n");

  /* Section 5: Lane extraction methods */
  printf("--- Lane extraction methods ---\n");
  run_test("vst1q_u8  + lane loop   (1-byte, 16 lanes)", bench_extract_vst1q_u8_loop);
  run_test("vst1q_u16 + lane loop   (2-byte,  8 lanes)", bench_extract_vst1q_u16_loop);
  run_test("vshrn     + shift loop  (2-byte,  8 lanes)", bench_extract_vshrn_shift);
  run_test("vget_lane_u16 × 8       (2-byte,  8 lanes)", bench_extract_vget_lane_u16_x8);
  printf("  → Compare extraction cost per lane\n\n");

  /* Section 6: Full loop comparison (THE KEY SECTION) */
  printf("=== Full scan loop comparison ===\n");
  printf("(vld1q + vceqq + extract per iteration)\\n\\n");
  run_test("1-byte: vld1q_u8  + vceqq_u8  + vst1q_u8  + 16 lanes",
           bench_full_1byte_loop);
  run_test("2-byte A: vld1q_u16 + vceqq_u16 + vst1q_u16 + 8 lanes [ORIGINAL]",
           bench_full_2byte_vld1q_u16);
  run_test("2-byte B: vld1q_u8  + vceqq_u16 + vst1q_u16 + 8 lanes [CURRENT]",
           bench_full_2byte_vld1q_u8);
  run_test("2-byte C: vld1q_u8  + vceqq_u16 + vshrn     + 8 lanes [NO STORE]",
           bench_full_2byte_vshrn);
  run_test("2-byte D: vld1q_u8  + vceqq_u16 + vget_lane × 8   [DIRECT]",
           bench_full_2byte_vget_lane);

  printf("\n=== Analysis ===\n");
  printf("Compare 2-byte A/B/C/D vs 1-byte. The variant closest to 1-byte\n");
  printf("performance reveals which instruction is the bottleneck.\n");
  printf("If ALL variants are equally slow → vceqq_u16 is the culprit.\n");
  printf("If B is faster than A → vld1q_u16 was the issue.\n");
  printf("If C/D are faster than A/B → vst1q was the issue.\n");
  (void)g_sink;

#else
  printf("This profiler requires ARM NEON (aarch64).\n");
  printf("Run on Apple Silicon or an ARM Linux box.\n");
#endif
  return 0;
}
