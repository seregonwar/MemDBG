/*
 * memDBG - Minimal LZ4 codec tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/pal/lz4.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failed = 0;

#define TEST(name, cond)                                                       \
  do {                                                                         \
    if (cond) {                                                                \
      printf("  [OK] %s\n", name);                                             \
    } else {                                                                   \
      printf("  [FAIL] %s\n", name);                                           \
      ++g_failed;                                                              \
    }                                                                          \
  } while (0)

static void fill_repetitive(uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if ((i % 64U) < 48U) {
      buf[i] = (uint8_t)('A' + (int)(i % 7U));
    } else {
      buf[i] = (uint8_t)i;
    }
  }
}

static void test_roundtrip(void) {
  uint8_t input[4096];
  fill_repetitive(input, sizeof(input));

  int bound = lz4_compress_bound((int)sizeof(input));
  TEST("compress bound positive", bound > 0);
  if (bound <= 0) return;

  uint8_t *compressed = (uint8_t *)malloc((size_t)bound);
  uint8_t *output = (uint8_t *)malloc(sizeof(input));
  TEST("alloc compressed", compressed != NULL);
  TEST("alloc output", output != NULL);
  if (compressed == NULL || output == NULL) {
    free(compressed);
    free(output);
    return;
  }

  int compressed_len = lz4_compress_default((const char *)(const void *)input,
                                            (char *)(void *)compressed,
                                            (int)sizeof(input), bound);
  TEST("compress repetitive block", compressed_len > 0);

  memset(output, 0, sizeof(input));
  int output_len = lz4_decompress_safe((const char *)(const void *)compressed,
                                       (char *)(void *)output, compressed_len,
                                       (int)sizeof(input));
  TEST("decompress size matches", output_len == (int)sizeof(input));
  TEST("roundtrip bytes match", memcmp(input, output, sizeof(input)) == 0);

  free(compressed);
  free(output);
}

static void test_literal_only_blocks(void) {
  uint8_t block15[17];
  block15[0] = 0xF0U;
  block15[1] = 0U;
  for (uint32_t i = 0; i < 15U; ++i) block15[2U + i] = (uint8_t)(0x30U + i);

  uint8_t output[32];
  memset(output, 0, sizeof(output));
  int out_len = lz4_decompress_safe((const char *)(const void *)block15,
                                    (char *)(void *)output,
                                    (int)sizeof(block15), (int)sizeof(output));
  TEST("literal-only len 15", out_len == 15);
  TEST("literal-only len 15 bytes", memcmp(output, block15 + 2, 15U) == 0);

  uint8_t block16[18];
  block16[0] = 0xF0U;
  block16[1] = 1U;
  for (uint32_t i = 0; i < 16U; ++i) block16[2U + i] = (uint8_t)(0x60U + i);

  memset(output, 0, sizeof(output));
  out_len = lz4_decompress_safe((const char *)(const void *)block16,
                                (char *)(void *)output, (int)sizeof(block16),
                                (int)sizeof(output));
  TEST("literal-only len 16", out_len == 16);
  TEST("literal-only len 16 bytes", memcmp(output, block16 + 2, 16U) == 0);
}

static void test_corrupt_blocks(void) {
  const uint8_t zero_offset[] = {0x00U, 0x00U, 0x00U};
  uint8_t output[16];
  int out_len = lz4_decompress_safe((const char *)(const void *)zero_offset,
                                    (char *)(void *)output,
                                    (int)sizeof(zero_offset),
                                    (int)sizeof(output));
  TEST("reject zero offset", out_len < 0);

  const uint8_t truncated_literal[] = {0x50U, 1U, 2U, 3U};
  out_len = lz4_decompress_safe((const char *)(const void *)truncated_literal,
                                (char *)(void *)output,
                                (int)sizeof(truncated_literal),
                                (int)sizeof(output));
  TEST("reject truncated literal", out_len < 0);
}

int main(void) {
  printf("--- LZ4 tests ---\n");
  test_roundtrip();
  test_literal_only_blocks();
  test_corrupt_blocks();

  if (g_failed != 0) {
    printf("\n%d LZ4 test(s) failed\n", g_failed);
    return 1;
  }

  printf("\nAll LZ4 tests passed.\n");
  return 0;
}
