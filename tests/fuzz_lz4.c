/*
 * memDBG - Fuzz target: LZ4 frame decompression.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Pure fuzz harness for lz4_decompress_safe. Reads arbitrary input and
 * attempts to decompress it with a variety of destination buffer sizes.
 *
 * Usage: fuzz_lz4 [input_file]
 */

#include "memdbg/pal/lz4.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Fuzz entry point ---- */

static int fuzz_lz4(const uint8_t *data, size_t size) {
  /* Reject absurd inputs that would cause integer overflow in sizing */
  if (size > LZ4_MAX_INPUT_SIZE) return 0;

  /* Try decompression with several destination buffer sizes to exercise
   * different code paths (small buffer, exact buffer, large buffer) */

  /* 1. Small buffer — tests truncation handling */
  {
    uint8_t dst[64];
    int ret = lz4_decompress_safe((const char *)data, (char *)dst,
                                   (int)size, (int)sizeof(dst));
    (void)ret; /* errors are expected — just check no crash */
  }

  /* 2. Exact-size buffer — if size is reasonable */
  if (size <= 65536 && size > 0) {
    uint8_t *dst = (uint8_t *)malloc(size);
    if (dst) {
      int ret = lz4_decompress_safe((const char *)data, (char *)dst,
                                     (int)size, (int)size);
      (void)ret;
      free(dst);
    }
  }

  /* 3. Double-size buffer — gives decompressor room to work */
  if (size <= 32768 && size > 0) {
    uint8_t *dst = (uint8_t *)malloc(size * 2);
    if (dst) {
      int ret = lz4_decompress_safe((const char *)data, (char *)dst,
                                     (int)size, (int)(size * 2));
      (void)ret;
      free(dst);
    }
  }

  /* 4. Zero-size destination — tests edge case */
  {
    char dummy;
    int ret = lz4_decompress_safe((const char *)data, &dummy,
                                   (int)size, 0);
    (void)ret;
  }

  return 0;
}

/* ---- I/O wrapper ---- */

int main(int argc, char **argv) {
  const uint8_t *data;
  size_t size;
  uint8_t *buf = NULL;

  if (argc >= 2) {
    const char *path = argv[1];
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", path); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return 1; }
    size = (size_t)sz;
    rewind(f);
    data = malloc(size + 1);
    if (!data) { fclose(f); return 1; }
    if (fread((void *)data, 1, size, f) != size) {
      free((void *)data);
      fclose(f);
      return 1;
    }
    fclose(f);
  } else {
    size_t cap = 65536;
    size_t len = 0;
    buf = malloc(cap);
    if (!buf) return 1;
    int c;
    while ((c = getchar()) != EOF) {
      if (len >= cap) {
        cap *= 2;
        uint8_t *nb = realloc(buf, cap);
        if (!nb) { free(buf); return 1; }
        buf = nb;
      }
      buf[len++] = (uint8_t)c;
    }
    data = buf;
    size = len;
  }

  int ret = fuzz_lz4(data, size);

  if (buf) free(buf);
  else free((void *)data);

  return ret;
}
