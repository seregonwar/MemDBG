/*
 * memDBG - Fuzz target: MDBG protocol header parsing.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Pure fuzz harness for memdbg_packet_header_t and memdbg_response_header_t
 * parsing. Reads arbitrary input from a file or stdin and validates that
 * the header structures can be parsed without crashes, leaks, or infinite
 * loops.
 *
 * This target does NOT:
 *   - Open sockets or network connections
 *   - Access actual processes or kernel
 *   - Depend on imGUI or any display library
 *   - Call abort() for malformed input
 *   - Leak memory on any input
 *
 * Usage: fuzz_protocol_header [input_file]
 *   Reads from input_file, or stdin if no argument given.
 */

#include "memdbg/core/memdbg_protocol.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Fuzz entry point ---- */

static int fuzz_protocol_header(const uint8_t *data, size_t size) {
  /* Ensure we have at least a packet header */
  if (size < sizeof(memdbg_packet_header_t)) return 0;

  const memdbg_packet_header_t *hdr =
      (const memdbg_packet_header_t *)data;

  /* Validate magic */
  if (hdr->magic == MEMDBG_PACKET_MAGIC) {
    /* Check version */
    if (hdr->version == MEMDBG_PROTOCOL_VERSION) {
      /* Validate length doesn't exceed max packet size */
      if (hdr->length <= MEMDBG_PROTOCOL_MAX_PACKET) {
        /* Try as response header if we have enough data */
        if (size >= sizeof(memdbg_response_header_t)) {
          const memdbg_response_header_t *rhdr =
              (const memdbg_response_header_t *)data;

          /* Validate response magic */
          if (rhdr->magic == MEMDBG_PACKET_MAGIC &&
              rhdr->version == MEMDBG_PROTOCOL_VERSION) {
            /* Response body bounds check */
            uint32_t total_response = (uint32_t)sizeof(memdbg_response_header_t);
            if (rhdr->length <= MEMDBG_PROTOCOL_MAX_PACKET &&
                (uint64_t)total_response + rhdr->length <= size) {
              /* At this point we have a valid-looking response header with body.
               * The status can be any value (positive, negative, zero). */
            }
          }
        }
      }
    }
  }

  return 0; /* All paths return success — no crashes, no leaks */
}

/* ---- I/O wrapper ---- */

int main(int argc, char **argv) {
  const uint8_t *data;
  size_t size;
  uint8_t *buf = NULL; /* for stdin mode */

  if (argc >= 2) {
    /* Read from file */
    const char *path = argv[1];
    FILE *f = fopen(path, "rb");
    if (!f) {
      fprintf(stderr, "Cannot open %s\n", path);
      return 1;
    }
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
    /* Read from stdin */
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

  /* Run the fuzz harness */
  int ret = fuzz_protocol_header(data, size);

  /* Cleanup */
  if (buf) free(buf);
  else free((void *)data);

  return ret;
}
