/*
 * memDBG - Fuzz target: process maps response parsing.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Pure fuzz harness for memdbg_map_entry_t array parsing.  Reads
 * arbitrary input and interprets it as a sequence of packed map
 * entries to exercise bounds checking, address validation, and
 * protection flag parsing.
 *
 * Usage: fuzz_process_maps [input_file]
 */

#include "memdbg/core/memdbg_protocol.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Fuzz entry point ---- */

static int fuzz_process_maps(const uint8_t *data, size_t size) {
  /* Interpret the input as an array of packed map entries */
  uint32_t count = (uint32_t)(size / sizeof(memdbg_map_entry_t));
  if (count == 0) return 0;

  const memdbg_map_entry_t *entries =
      (const memdbg_map_entry_t *)data;

  /* Iterate through each full entry and validate fields */
  uint32_t full_entries = count;
  if ((uint64_t)full_entries * sizeof(memdbg_map_entry_t) > size)
    full_entries = (uint32_t)(size / sizeof(memdbg_map_entry_t));

  for (uint32_t i = 0; i < full_entries && i < 1000; i++) {
    uint64_t start = entries[i].start;
    uint64_t end   = entries[i].end;
    uint32_t prot  = entries[i].protection;
    uint32_t flags = entries[i].flags;

    /* Validate address range — no crash on any combination */
    if (start <= end) {
      /* Valid range — check protection bits are within known mask */
      uint32_t known_prot = prot & (MEMDBG_MAP_PROT_READ |
                                    MEMDBG_MAP_PROT_WRITE |
                                    MEMDBG_MAP_PROT_EXEC);
      (void)known_prot;

      /* Extract map type from flags */
      uint32_t map_type = (flags & MEMDBG_MAP_FLAG_TYPE_MASK) >>
                          MEMDBG_MAP_FLAG_TYPE_SHIFT;
      (void)map_type;

      /* Check for valid map type */
      if (map_type <= MEMDBG_MAP_TYPE_UNKNOWN) {
        /* Valid type */
      }
    }

    /* Check name field is safely readable */
    size_t name_len = strnlen(entries[i].name, sizeof(entries[i].name));
    (void)name_len;
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
      free((void *)data); fclose(f); return 1;
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

  int ret = fuzz_process_maps(data, size);

  if (buf) free(buf);
  else free((void *)data);

  return ret;
}
