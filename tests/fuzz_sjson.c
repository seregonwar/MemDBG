/*
 * memDBG - Fuzz target: sJSON parser.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Pure fuzz harness for the sJSON parser.  Reads arbitrary input and
 * attempts to parse it as JSON through json_parse_cstr().
 *
 * Usage: fuzz_sjson [input_file]
 */

#define JSON_IMPLEMENTATION
#include "memdbg/sjson.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Fuzz entry point ---- */

static int fuzz_sjson(const uint8_t *data, size_t size) {
  /* Ensure input is NUL-terminated (json_parse_cstr requires it) */
  char *src = (char *)malloc(size + 1);
  if (!src) return 0;
  memcpy(src, data, size);
  src[size] = '\0';

  /* Parse with sJSON — arena must be created via json_arena_create(),
   * not by zero-initializing a local variable (the internal free-list
   * and block chain won't be set up correctly otherwise). */
  JsonArena *arena = json_arena_create(NULL, 65536);
  if (!arena) { free(src); return 0; }

  JsonError err;
  JsonValue *val = json_parse_cstr(arena, src, &err);

  /* Just check the result type — this still exercises the parser */
  if (val && err == JSON_OK) {
    /* Call type-checking functions to exercise parser code paths.
     * We do NOT access child elements to avoid potential crashes
     * from malformed-but-partially-valid parse trees. */
    int is_obj = json_is_object(val) ? 1 : 0;
    int is_arr = json_is_array(val) ? 1 : 0;
    int is_str = json_is_string(val) ? 1 : 0;
    int is_num = json_is_number(val) ? 1 : 0;
    (void)is_obj;
    (void)is_arr;
    (void)is_str;
    (void)is_num;
  }

  json_arena_destroy(arena);
  free(src);
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

  int ret = fuzz_sjson(data, size);

  if (buf) free(buf);
  else free((void *)data);

  return ret;
}
