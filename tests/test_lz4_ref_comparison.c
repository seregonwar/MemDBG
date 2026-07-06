/*
 * MemDBG - LZ4 decompression comparison: memDBG vs reference liblz4.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Compresses data with memDBG's LZ4, then decompresses with both
 * memDBG and reference liblz4 (loaded via dlopen) to measure
 * throughput of each.
 *
 * Build:
 *   cc -std=c11 -O2 -Isrc -Iinclude tests/test_lz4_ref_comparison.c \
 *      src/pal/lz4.c -o build/test_lz4_ref_comparison -ldl
 * Run:
 *   build/test_lz4_ref_comparison
 */

#include "memdbg/pal/lz4.h"
#include "bench_utils.h"

#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- Function pointer types matching reference lz4.h ABI ---- */
typedef int (*lz4_decompress_fn)(const char *src, char *dst,
                                 int compressed_size, int dst_capacity);
typedef int (*lz4_compress_fn)(const char *src, char *dst,
                               int src_size, int dst_capacity);

/* bench_now_ns and bench_fill_pattern are provided by bench_utils.h */

/* ---- Run decompression benchmark for one implementation ---- */
static double bench_decompress(const char *name,
                               lz4_decompress_fn decompress,
                               const uint8_t *comp, int comp_len,
                               uint8_t *dst, int dst_cap,
                               uint64_t iters) {
  uint64_t t0 = bench_now_ns();
  int total = 0;
  for (uint64_t i = 0; i < iters; ++i)
    total += decompress((const char *)comp, (char *)dst, comp_len, dst_cap);
  uint64_t t1 = bench_now_ns();
  double sec = (double)(t1 - t0) / 1e9;
  double mb_s = ((double)dst_cap * (double)iters) / (double)(1 << 20) / sec;
  printf("  %-32s %10.4f s  %12.2f MB/s  (%d B out)\\n",
         name, sec, mb_s, total / (int)iters);
  return mb_s;
}

/* ---- Main ---- */
int main(void) {
  /* ---- Load reference lz4 via dlopen ---- */
  /* Try Homebrew path first; fall back to system path. */
  void *ref_handle = dlopen("/opt/homebrew/opt/lz4/lib/liblz4.dylib",
                            RTLD_NOW | RTLD_LOCAL);
  if (!ref_handle)
    ref_handle = dlopen("/usr/local/opt/lz4/lib/liblz4.dylib",
                        RTLD_NOW | RTLD_LOCAL);
  if (!ref_handle)
    ref_handle = dlopen("liblz4.dylib", RTLD_NOW | RTLD_LOCAL);
  if (!ref_handle) {
    fprintf(stderr,
            "ERROR: Cannot load reference liblz4.  Is 'brew install lz4' run?"
            "\\n  dlopen: %s\\n",
            dlerror());
    return 1;
  }

  lz4_compress_fn ref_compress =
      (lz4_compress_fn)dlsym(ref_handle, "LZ4_compress_default");
  lz4_decompress_fn ref_decompress =
      (lz4_decompress_fn)dlsym(ref_handle, "LZ4_decompress_safe");

  if (!ref_compress || !ref_decompress) {
    fprintf(stderr, "ERROR: Cannot resolve reference LZ4 symbols\\n");
    dlclose(ref_handle);
    return 1;
  }

  printf(
      "===================================================================\\n");
  printf("  LZ4 DECOMPRESSION: memDBG vs reference liblz4\\n");
  printf(
      "===================================================================\\n");
  printf(
      "  Each block is compressed with memDBG LZ4, then decompressed\\n");
  printf(
      "  by both implementations on the same compressed data.\\n");
  printf(
      "  The reference library is also used to compress for an\\n");
  printf(
      "  interop check (can each decompress the other's output?).\\n");
  printf(
      "===================================================================\\n\\n");

  size_t sizes[] = {4096, 65536, 262144, 1048576};
  const char *size_names[] = {"4 KiB", "64 KiB", "256 KiB", "1 MiB"};

  for (int si = 0; si < 4; ++si) {
    size_t src_size = sizes[si];
    printf("--- Block size: %s (%zu B) ---\\n", size_names[si], src_size);

    /* Allocate */
    uint8_t *src = (uint8_t *)malloc(src_size);
    int bound = lz4_compress_bound((int)src_size);
    uint8_t *comp = (uint8_t *)malloc((size_t)bound);
    uint8_t *decomp_a = (uint8_t *)malloc(src_size);
    uint8_t *decomp_b = (uint8_t *)malloc(src_size);
    if (!src || !comp || !decomp_a || !decomp_b) {
      printf("  SKIP: malloc failed\\n");
      free(src); free(comp); free(decomp_a); free(decomp_b);
      continue;
    }

    bench_fill_pattern(src, src_size, (uint64_t)(src_size * 0x9E3779B9ULL));

    /* ---- Compress with memDBG LZ4 ---- */
    int memdbg_clen = lz4_compress_default(
        (const char *)src, (char *)comp, (int)src_size, bound);
    double ratio = memdbg_clen > 0
                       ? (double)(int)src_size / (double)memdbg_clen
                       : 0.0;
    printf("  memDBG compressed: %d B (ratio %.2f:1)\\n", memdbg_clen, ratio);

    if (memdbg_clen <= 0) {
      printf("  SKIP: compression failed\\n");
      free(src); free(comp); free(decomp_a); free(decomp_b);
      continue;
    }

    /* ---- Interop: reference decompresses memDBG output ---- */
    int ref_from_memdbg = ref_decompress(
        (const char *)comp, (char *)decomp_b, memdbg_clen, (int)src_size);
    int interop_ok = (ref_from_memdbg == (int)src_size &&
                      memcmp(src, decomp_b, src_size) == 0);
    printf("  Interop (ref reads memDBG): %s\\n",
           interop_ok ? "PASS" : "FAIL");

    /* ---- Also compress with reference, then decompress with memDBG ---- */
    int ref_clen = ref_compress(
        (const char *)src, (char *)comp, (int)src_size, bound);
    if (ref_clen > 0) {
      int memdbg_from_ref = lz4_decompress_safe(
          (const char *)comp, (char *)decomp_a, ref_clen, (int)src_size);
      int interop2 = (memdbg_from_ref == (int)src_size &&
                      memcmp(src, decomp_a, src_size) == 0);
      printf("  Interop (memDBG reads ref):  %s\\n",
             interop2 ? "PASS" : "FAIL");
    }

    /* ---- Benchmark: decompress memDBG-compressed data ---- */
    const uint64_t ITERS =
        (src_size <= 65536) ? 50000ULL : (src_size <= 262144) ? 5000ULL : 1000ULL;

    printf("\\n  Decompressing memDBG-compressed data (%" PRIu64 " iters):\\n", ITERS);
    double memdbg_mbs = bench_decompress(
        "memDBG lz4_decompress_safe", lz4_decompress_safe,
        comp, memdbg_clen, decomp_a, (int)src_size, ITERS);
    double ref_mbs = bench_decompress(
        "reference LZ4_decompress_safe", ref_decompress,
        comp, memdbg_clen, decomp_a, (int)src_size, ITERS);
    if (ref_mbs > 0.0)
      printf("  %-32s %12s  %12.2f%%\\n",
             "memDBG / reference", "", (memdbg_mbs / ref_mbs) * 100.0);

    /* ---- Benchmark: decompress ref-compressed data ---- */
    if (ref_clen > 0) {
      printf("\\n  Decompressing ref-compressed data (%" PRIu64 " iters):\\n", ITERS);
      bench_decompress("memDBG lz4_decompress_safe", lz4_decompress_safe,
                       comp, ref_clen, decomp_b, (int)src_size, ITERS);
      bench_decompress("reference LZ4_decompress_safe", ref_decompress,
                       comp, ref_clen, decomp_b, (int)src_size, ITERS);
    }

    printf("\\n");
    free(src); free(comp); free(decomp_a); free(decomp_b);
  }

  dlclose(ref_handle);
  printf(
      "===================================================================\\n");
  printf("  Done.\\n");
  printf(
      "===================================================================\\n");
  return 0;
}
