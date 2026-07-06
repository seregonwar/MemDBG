/*
 * MemDBG - LZ4 interop diagnostic: find the exact byte-level difference
 * between memDBG and reference LZ4 compression.
 *
 * Build:
 *   cc -std=c11 -O2 -Isrc -Iinclude tests/test_lz4_interop_diag.c \
 *      src/pal/lz4.c -L/opt/homebrew/opt/lz4/lib -ldl \
 *      -o build/test_lz4_interop_diag
 */

#include "memdbg/pal/lz4.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*lz4_compress_fn)(const char *src, char *dst,
                               int src_size, int dst_capacity);
typedef int (*lz4_decompress_fn)(const char *src, char *dst,
                                 int compressed_size, int dst_capacity);

static void hexdump(const uint8_t *buf, size_t len, const char *label) {
  printf("%s (%zu bytes):\n", label, len);
  for (size_t i = 0; i < len; i += 16) {
    printf("  %04zx:", i);
    for (size_t j = 0; j < 16 && i + j < len; ++j)
      printf(" %02x", buf[i + j]);
    printf("\n");
  }
}

static void compare_outputs(const uint8_t *memdbg_out, int memdbg_len,
                            const uint8_t *ref_out, int ref_len,
                            const uint8_t *input, int input_len) {
  printf("\n=== Comparison ===\n");
  printf("memDBG compressed: %d bytes\n", memdbg_len);
  printf("Ref LZ4 compressed: %d bytes\n", ref_len);

  if (memdbg_len != ref_len) {
    printf("SIZE MISMATCH: memDBG=%d ref=%d\n", memdbg_len, ref_len);
  }

  int min_len = memdbg_len < ref_len ? memdbg_len : ref_len;
  int diffs = 0;
  for (int i = 0; i < min_len; ++i) {
    if (memdbg_out[i] != ref_out[i]) {
      printf("  DIFF at byte %d: memDBG=0x%02x ref=0x%02x\n",
             i, memdbg_out[i], ref_out[i]);
      if (++diffs >= 20) { printf("  ... (stopping after 20 diffs)\n"); break; }
    }
  }
  if (diffs == 0 && memdbg_len == ref_len)
    printf("  IDENTICAL — interop should work!\n");
  else if (diffs == 0)
    printf("  Same prefix, different length (extra bytes in longer output)\n");

  /* Verify that at least memDBG can decompress its own output */
  uint8_t *decomp = (uint8_t *)malloc((size_t)input_len);
  int dec = lz4_decompress_safe((const char *)memdbg_out, (char *)decomp,
                                memdbg_len, input_len);
  printf("\n  memDBG self-roundtrip: %s (dec=%d)\n",
         (dec == input_len && memcmp(input, decomp, input_len) == 0)
             ? "PASS" : "FAIL", dec);
  free(decomp);
}

int main(void) {
  /* Load reference LZ4 */
  void *ref_handle = dlopen("/opt/homebrew/opt/lz4/lib/liblz4.dylib",
                            RTLD_NOW | RTLD_LOCAL);
  if (!ref_handle) {
    fprintf(stderr, "ERROR: Cannot load reference liblz4\n");
    return 1;
  }
  lz4_compress_fn ref_compress =
      (lz4_compress_fn)dlsym(ref_handle, "LZ4_compress_default");
  lz4_decompress_fn ref_decompress =
      (lz4_decompress_fn)dlsym(ref_handle, "LZ4_decompress_safe");

  /* Test with small, predictable inputs to find the bug */
  int sizes[] = {32, 33, 64, 65, 128, 255, 256, 257, 512, 4096};
  int n_sizes = sizeof(sizes) / sizeof(sizes[0]);

  for (int si = 0; si < n_sizes; ++si) {
    int input_len = sizes[si];
    uint8_t *input = (uint8_t *)malloc((size_t)input_len);
    /* Repetitive data that WILL produce matches */
    for (int i = 0; i < input_len; ++i)
      input[i] = (uint8_t)('A' + (i % 57));

    int bound = lz4_compress_bound(input_len);
    uint8_t *memdbg_out = (uint8_t *)malloc((size_t)bound);
    uint8_t *ref_out    = (uint8_t *)malloc((size_t)bound);

    int memdbg_len = lz4_compress_default((const char *)input,
        (char *)memdbg_out, input_len, bound);
    int ref_len = ref_compress((const char *)input,
        (char *)ref_out, input_len, bound);

    printf("\n========================================\n");
    printf("Input: %d bytes (repetitive A-Z + special)\n", input_len);
    printf("memDBG: %d bytes, ref: %d bytes\n", memdbg_len, ref_len);

    if (memdbg_len <= 0) {
      printf("  memDBG compression failed (returns %d)\n", memdbg_len);
    } else {
      /* Try ref decompress memDBG output */
      uint8_t *decomp = (uint8_t *)malloc((size_t)input_len);
      int ref_dec = ref_decompress((const char *)memdbg_out,
          (char *)decomp, memdbg_len, input_len);
      int interop_ok = (ref_dec == input_len &&
                        memcmp(input, decomp, input_len) == 0);
      printf("  Ref reads memDBG: %s (dec=%d)\n",
             interop_ok ? "PASS" : "FAIL", ref_dec);

      if (!interop_ok) {
        /* Show the first 32 bytes of both compressed outputs */
        hexdump(memdbg_out, memdbg_len < 64 ? (size_t)memdbg_len : 64,
                "memDBG output (first 64B)");
        hexdump(ref_out, ref_len < 64 ? (size_t)ref_len : 64,
                "ref output (first 64B)");
        printf("  --- memDBG decomp of self: ");
        int self_dec = lz4_decompress_safe((const char *)memdbg_out,
            (char *)decomp, memdbg_len, input_len);
        printf("%s\n", (self_dec == input_len &&
                 memcmp(input, decomp, input_len) == 0) ? "PASS" : "FAIL");
      }

      /* Try memDBG decompress ref output */
      int memdbg_dec = lz4_decompress_safe((const char *)ref_out,
          (char *)decomp, ref_len, input_len);
      printf("  memDBG reads ref: %s (dec=%d)\n",
             (memdbg_dec == input_len &&
              memcmp(input, decomp, input_len) == 0) ? "PASS" : "FAIL",
             memdbg_dec);

      free(decomp);
    }

    free(input); free(memdbg_out); free(ref_out);
  }

  dlclose(ref_handle);
  return 0;
}
