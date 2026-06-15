/*
 * memDBG - Memory debugger payload for jailbroken consoles.
 * Copyright (C) 2026 SeregonWar
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/scanner/memdbg_scan.h"

#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/debug/memdbg_process.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MEMDBG_SCAN_CHUNK (1024U * 1024U)  /* 1 MiB (was 256 KiB) */
#define MEMDBG_SCAN_INITIAL_CAPACITY 256U
#define MEMDBG_MAP_PROT_READ 1U

/* ---- Boyer-Moore-Horspool skip table (256 entries) ---- */

#define BM_ALPHABET_SIZE 256U

typedef struct {
  size_t skip[BM_ALPHABET_SIZE];
} bm_table_t;

static void bm_build_table(const unsigned char *pattern, size_t pat_len,
                           const unsigned char *mask, bm_table_t *table) {
  for (size_t i = 0U; i < BM_ALPHABET_SIZE; ++i)
    table->skip[i] = pat_len;
  for (size_t i = 0U; i < pat_len - 1U; ++i) {
    if (mask[i] != 0U) {
      /* Exact byte: only this byte skips to position i. */
      if (table->skip[pattern[i]] > pat_len - 1U - i)
        table->skip[pattern[i]] = pat_len - 1U - i;
    } else {
      /* Wildcard: ANY byte could match here, so cap the skip for
         every byte to at most pat_len - 1 - i.  This prevents the
         BMH bad-character heuristic from overshooting past a
         wildcard-tolerant alignment. */
      size_t cap = pat_len - 1U - i;
      for (size_t b = 0U; b < BM_ALPHABET_SIZE; ++b)
        if (table->skip[b] > cap)
          table->skip[b] = cap;
    }
  }
}

/* ---- Match function type ---- */

typedef bool (*scan_match_fn_t)(const unsigned char *candidate,
                                const unsigned char *needle, size_t len);

typedef struct scan_builder {
  memdbg_scan_result_t *result;
  size_t capacity;
  size_t max_results;
} scan_builder_t;

typedef struct scan_context {
  int pid;
  uint32_t value_type;
  uint32_t value_len;
  uint32_t alignment;
  unsigned char needle[MEMDBG_SCAN_VALUE_MAX];
  unsigned char *buffer;
  size_t buffer_size;
  scan_match_fn_t match;
} scan_context_t;

/* ---- Clock ---- */

static uint64_t monotonic_ns(void) {
#if defined(CLOCK_MONOTONIC)
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
#endif
  return 0U;
}

/* ---- Value length helper ---- */

static uint32_t expected_value_length(uint32_t value_type,
                                      uint32_t requested_length) {
  switch ((memdbg_value_type_t)value_type) {
  case MEMDBG_VALUE_U8:  return 1U;
  case MEMDBG_VALUE_U16: return 2U;
  case MEMDBG_VALUE_U32: case MEMDBG_VALUE_F32: return 4U;
  case MEMDBG_VALUE_U64: case MEMDBG_VALUE_F64: case MEMDBG_VALUE_POINTER: return 8U;
  case MEMDBG_VALUE_BYTES: default: return requested_length;
  }
}

/* ---- Loop-unrolled match functions ---- */

static bool match_u8(const unsigned char *c, const unsigned char *n, size_t len) {
  (void)len; return c[0] == n[0];
}

static bool match_u16(const unsigned char *c, const unsigned char *n, size_t len) {
  (void)len;
  return c[0] == n[0] && c[1] == n[1];
}

static bool match_u32(const unsigned char *c, const unsigned char *n, size_t len) {
  (void)len;
  return c[0] == n[0] && c[1] == n[1] && c[2] == n[2] && c[3] == n[3];
}

static bool match_u64(const unsigned char *c, const unsigned char *n, size_t len) {
  (void)len;
  return c[0] == n[0] && c[1] == n[1] && c[2] == n[2] && c[3] == n[3] &&
         c[4] == n[4] && c[5] == n[5] && c[6] == n[6] && c[7] == n[7];
}

static bool match_bytes(const unsigned char *candidate,
                        const unsigned char *needle, size_t len) {
  return candidate[0] == needle[0] && memcmp(candidate, needle, len) == 0;
}

static scan_match_fn_t match_fn_for(uint32_t value_len) {
  switch (value_len) {
  case 1U: return match_u8;
  case 2U: return match_u16;
  case 4U: return match_u32;
  case 8U: return match_u64;
  default: return match_bytes;
  }
}

/* ---- Result builder ---- */

static memdbg_status_t scan_builder_append(scan_builder_t *builder, uint64_t address) {
  memdbg_scan_result_t *result = builder->result;
  if (result->count >= builder->max_results) {
    result->truncated = true;
    return MEMDBG_OK;
  }
  if (result->count == builder->capacity) {
    size_t next_capacity = builder->capacity == 0U ? MEMDBG_SCAN_INITIAL_CAPACITY
                                                   : builder->capacity * 2U;
    if (next_capacity < builder->capacity || next_capacity > builder->max_results)
      next_capacity = builder->max_results;
    if (next_capacity <= result->count) { result->truncated = true; return MEMDBG_OK; }
    memdbg_scan_result_entry_t *next =
        (memdbg_scan_result_entry_t *)realloc(result->entries, next_capacity * sizeof(*result->entries));
    if (next == NULL) return MEMDBG_ERR_NOMEM;
    result->entries = next;
    builder->capacity = next_capacity;
  }
  result->entries[result->count].address = address;
  result->count++;
  return MEMDBG_OK;
}

/* ---- Pre-allocate result buffer to max_results upfront ---- */

static memdbg_status_t scan_builder_prealloc(scan_builder_t *builder) {
  if (builder->max_results == 0U) return MEMDBG_ERR_PARAM;
  builder->result->entries = (memdbg_scan_result_entry_t *)malloc(
      builder->max_results * sizeof(memdbg_scan_result_entry_t));
  if (builder->result->entries == NULL) return MEMDBG_ERR_NOMEM;
  builder->capacity = builder->max_results;
  return MEMDBG_OK;
}

/* ---- Alignment ---- */

static size_t first_aligned_offset(uint64_t base, uint64_t alignment_base,
                                   uint64_t range_start, uint32_t alignment) {
  uint64_t offset = base < range_start ? range_start - base : 0U;
  if (alignment <= 1U)
    return offset > (uint64_t)SIZE_MAX ? SIZE_MAX : (size_t)offset;
  uint64_t address = base + offset;
  uint64_t misalignment = (address - alignment_base) % alignment;
  if (misalignment != 0U) offset += (uint64_t)alignment - misalignment;
  return offset > (uint64_t)SIZE_MAX ? SIZE_MAX : (size_t)offset;
}

/* ---- Window scanner ---- */

static memdbg_status_t scan_window(scan_context_t *ctx, scan_builder_t *builder,
                                   size_t window, uint64_t base_addr,
                                   uint64_t alignment_base, uint64_t range_start,
                                   uint64_t range_end) {
  const uint32_t value_len = ctx->value_len;
  if (window < value_len) return MEMDBG_OK;

  size_t searchable = window - (size_t)value_len + 1U;

  /* Fast path: u8 aligned=1 -> memchr */
  if (value_len == 1U && ctx->alignment == 1U && base_addr >= range_start) {
    size_t pos = 0U;
    while (pos < searchable && !builder->result->truncated) {
      void *hit = memchr(ctx->buffer + pos, ctx->needle[0], searchable - pos);
      if (hit == NULL) break;
      size_t i = (size_t)((unsigned char *)hit - ctx->buffer);
      memdbg_status_t st = scan_builder_append(builder, base_addr + i);
      if (st != MEMDBG_OK) return st;
      pos = i + 1U;
    }
    return MEMDBG_OK;
  }

  size_t first = first_aligned_offset(base_addr, alignment_base, range_start, ctx->alignment);
  if (first == SIZE_MAX || first >= searchable) return MEMDBG_OK;

  for (size_t i = first; i < searchable && !builder->result->truncated; i += ctx->alignment) {
    uint64_t absolute = base_addr + i;
    if (absolute + value_len > range_end) break;
    if (ctx->match(ctx->buffer + i, ctx->needle, value_len))
      { memdbg_status_t st = scan_builder_append(builder, absolute); if (st != MEMDBG_OK) return st; }
  }
  return MEMDBG_OK;
}

/* ---- Range scanner ---- */

static memdbg_status_t scan_range(scan_context_t *ctx, scan_builder_t *builder,
                                  uint64_t range_start, uint64_t range_len,
                                  uint64_t alignment_base, bool skip_read_errors) {
  size_t overlap = ctx->value_len > 1U ? (size_t)ctx->value_len - 1U : 0U;
  uint64_t scanned = 0U;
  size_t carry = 0U;
  uint64_t range_end = range_start + range_len;

  while (scanned < range_len && !builder->result->truncated) {
    uint64_t remaining = range_len - scanned;
    size_t to_read = remaining > MEMDBG_SCAN_CHUNK ? MEMDBG_SCAN_CHUNK : (size_t)remaining;
    size_t read_len = 0U;

    builder->result->read_calls++;
    memdbg_status_t st = memdbg_memory_read(ctx->pid, range_start + scanned,
        ctx->buffer + carry, to_read, &read_len);
    if (st != MEMDBG_OK) { builder->result->read_errors++; return skip_read_errors ? MEMDBG_OK : st; }
    if (read_len == 0U) break;
    builder->result->bytes_scanned += (uint64_t)read_len;

    size_t window = carry + read_len;
    uint64_t base_addr = range_start + scanned - (uint64_t)carry;
    st = scan_window(ctx, builder, window, base_addr, alignment_base, range_start, range_end);
    if (st != MEMDBG_OK) return st;

    if (overlap != 0U) {
      carry = window < overlap ? window : overlap;
      memmove(ctx->buffer, ctx->buffer + window - carry, carry);
    }
    scanned += read_len;
  }
  return MEMDBG_OK;
}

/* ---- Context init / fini ---- */

static memdbg_status_t scan_context_init(scan_context_t *ctx, int pid,
                                         uint32_t value_type, uint32_t requested_value_len,
                                         uint32_t alignment, const uint8_t *value) {
  if (ctx == NULL || pid <= 0 || value == NULL) return MEMDBG_ERR_PARAM;
  memset(ctx, 0, sizeof(*ctx));
  ctx->pid = pid;
  ctx->value_type = value_type;
  ctx->value_len = expected_value_length(value_type, requested_value_len);
  ctx->alignment = alignment == 0U ? 1U : alignment;
  if (ctx->value_len == 0U || ctx->value_len > MEMDBG_SCAN_VALUE_MAX) return MEMDBG_ERR_PARAM;
  memcpy(ctx->needle, value, ctx->value_len);
  ctx->match = match_fn_for(ctx->value_len);
  ctx->buffer_size = MEMDBG_SCAN_CHUNK + (size_t)ctx->value_len - 1U;
  ctx->buffer = (unsigned char *)malloc(ctx->buffer_size);
  if (ctx->buffer == NULL) return MEMDBG_ERR_NOMEM;
  return MEMDBG_OK;
}

static void scan_context_fini(scan_context_t *ctx) {
  if (ctx == NULL) return;
  free(ctx->buffer);
  memset(ctx, 0, sizeof(*ctx));
}

/* ---- Public API: exact scan ---- */

memdbg_status_t memdbg_scan_exact(const memdbg_scan_exact_request_t *request,
                                  memdbg_scan_result_t *out) {
  if (request == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));
  if (request->length == 0U) return MEMDBG_ERR_PARAM;

  scan_context_t ctx;
  memdbg_status_t st = scan_context_init(&ctx, request->pid, request->value_type,
      request->value_length, request->alignment, request->value);
  if (st != MEMDBG_OK) return st;
  if (ctx.value_len > request->length) { scan_context_fini(&ctx); return MEMDBG_ERR_PARAM; }

  scan_builder_t builder;
  memset(&builder, 0, sizeof(builder));
  builder.result = out;
  builder.max_results = request->max_results == 0U ? 1U : (size_t)request->max_results;
  scan_builder_prealloc(&builder);

  uint64_t start_ns = monotonic_ns();
  out->regions_scanned = 1U;
  st = scan_range(&ctx, &builder, request->start, request->length, request->start, false);
  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;

  scan_context_fini(&ctx);
  if (st != MEMDBG_OK) memdbg_scan_result_free(out);
  return st;
}

/* ---- Public API: process exact scan (uses cached maps) ---- */

memdbg_status_t memdbg_scan_process_exact(const memdbg_scan_process_exact_request_t *request,
                                          memdbg_scan_result_t *out) {
  if (request == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));

  scan_context_t ctx;
  memdbg_status_t st = scan_context_init(&ctx, request->pid, request->value_type,
      request->value_length, request->alignment, request->value);
  if (st != MEMDBG_OK) return st;

  memdbg_map_list_t maps;
  st = memdbg_process_maps_cached(request->pid, &maps);  /* <-- cached */
  if (st != MEMDBG_OK) { scan_context_fini(&ctx); return st; }

  scan_builder_t builder;
  memset(&builder, 0, sizeof(builder));
  builder.result = out;
  builder.max_results = request->max_results == 0U ? 1U : (size_t)request->max_results;
  scan_builder_prealloc(&builder);

  uint32_t prot_mask = request->protection_mask == 0U ? MEMDBG_MAP_PROT_READ : request->protection_mask;
  uint64_t start_ns = monotonic_ns();

  for (size_t i = 0U; i < maps.count && !out->truncated; ++i) {
    const memdbg_map_entry_t *map = &maps.entries[i];
    if ((map->protection & prot_mask) != prot_mask || map->end <= map->start) continue;
    uint64_t scan_start = map->start, scan_end = map->end;
    if (request->start != 0U && scan_start < request->start) scan_start = request->start;
    if (request->end   != 0U && scan_end   > request->end)   scan_end   = request->end;
    if (scan_end <= scan_start || scan_end - scan_start < ctx.value_len) continue;
    out->regions_scanned++;
    st = scan_range(&ctx, &builder, scan_start, scan_end - scan_start, scan_start, true);
    if (st != MEMDBG_OK) break;
  }

  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;

  memdbg_process_maps_free(&maps);
  scan_context_fini(&ctx);
  if (st != MEMDBG_OK) memdbg_scan_result_free(out);
  return st;
}

/* ---- Public API: AOB scan (Boyer-Moore-Horspool) ---- */

memdbg_status_t memdbg_scan_aob(const memdbg_scan_aob_request_t *request,
                                const uint8_t *pattern, const uint8_t *mask,
                                memdbg_scan_result_t *out) {
  if (request == NULL || pattern == NULL || mask == NULL || out == NULL)
    return MEMDBG_ERR_PARAM;
  if (request->pattern_length == 0U || request->length == 0U)
    return MEMDBG_ERR_PARAM;

  memset(out, 0, sizeof(*out));

  /* Buffer: chunk size + pattern overlap so patterns crossing chunk
     boundaries are never missed. */
  size_t pat_len = (size_t)request->pattern_length;
  size_t overlap = pat_len > 1U ? pat_len - 1U : 0U;
  size_t buf_size = MEMDBG_SCAN_CHUNK + overlap;
  unsigned char *buffer = (unsigned char *)malloc(buf_size);
  if (buffer == NULL) return MEMDBG_ERR_NOMEM;

  scan_builder_t builder;
  memset(&builder, 0, sizeof(builder));
  builder.result = out;
  builder.max_results = request->max_results == 0U ? 1U : (size_t)request->max_results;
  scan_builder_prealloc(&builder);

  /* Build BMH skip table with wildcard-aware shifts. */
  bm_table_t bm;
  bm_build_table(pattern, pat_len, mask, &bm);

  uint64_t scanned = 0U;
  size_t carry = 0U;
  uint64_t start_ns = monotonic_ns();

  while (scanned < request->length && !out->truncated) {
    uint64_t remaining = request->length - scanned;
    size_t to_read = remaining > MEMDBG_SCAN_CHUNK ? MEMDBG_SCAN_CHUNK : (size_t)remaining;
    size_t read_len = 0U;

    out->read_calls++;
    memdbg_status_t st = memdbg_memory_read(request->pid, request->start + scanned,
        buffer + carry, to_read, &read_len);
    if (st != MEMDBG_OK) { out->read_errors++; break; }
    if (read_len == 0U) break;
    out->bytes_scanned += (uint64_t)read_len;

    /* window = carry from previous chunk + freshly read data.
       base_addr is shifted back by carry bytes so absolute addresses
       are computed correctly. */
    size_t window = carry + read_len;
    uint64_t base_addr = request->start + scanned - (uint64_t)carry;

    /* Boyer-Moore-Horspool search with wildcard-aware match. */
    size_t i = pat_len - 1U;
    const unsigned char *hay = buffer;
    while (i < window && !out->truncated) {
      /* Full pattern check backward from current position */
      size_t j = pat_len - 1U;
      const unsigned char *h = hay + i;
      bool match = true;
      while (1) {
        if (mask[j] != 0U && *h != pattern[j]) {
          match = false; break;
        }
        if (j == 0U) break;
        --j; --h;
      }
      if (match) {
        uint64_t addr = base_addr + (uint64_t)(i - pat_len + 1U);
        memdbg_status_t as = scan_builder_append(&builder, addr);
        if (as != MEMDBG_OK) { free(buffer); return as; }
        i += 1U; /* start at next byte */
      } else {
        i += bm.skip[hay[i]];
      }
    }

    /* Preserve tail for cross-chunk continuity. */
    if (overlap != 0U) {
      carry = window < overlap ? window : overlap;
      if (carry > 0U)
        memmove(buffer, buffer + window - carry, carry);
    }
    scanned += read_len;
  }

  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;
  out->regions_scanned = 1U;
  free(buffer);
  return MEMDBG_OK;
}

/* ---- Public API: unknown initial value scan (captures every aligned address) ---- */

memdbg_status_t memdbg_scan_unknown(const memdbg_scan_process_exact_request_t *request,
                                    memdbg_scan_result_t *out) {
  if (request == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));

  uint32_t value_len = expected_value_length(request->value_type, request->value_length);
  if (value_len == 0U || value_len > MEMDBG_SCAN_VALUE_MAX) return MEMDBG_ERR_PARAM;
  uint32_t alignment = request->alignment == 0U ? value_len : request->alignment;

  /* Buffer: chunk + overlap for values crossing chunk boundaries */
  size_t overlap = value_len > 1U ? (size_t)value_len - 1U : 0U;
  size_t buf_size = MEMDBG_SCAN_CHUNK + overlap;
  unsigned char *buffer = (unsigned char *)malloc(buf_size);
  if (buffer == NULL) return MEMDBG_ERR_NOMEM;

  memdbg_map_list_t maps;
  memdbg_status_t st = memdbg_process_maps_cached(request->pid, &maps);
  if (st != MEMDBG_OK) { free(buffer); return st; }

  scan_builder_t builder;
  memset(&builder, 0, sizeof(builder));
  builder.result = out;
  builder.max_results = request->max_results == 0U ? 1U : (size_t)request->max_results;
  scan_builder_prealloc(&builder);

  uint32_t prot_mask = request->protection_mask == 0U ? MEMDBG_MAP_PROT_READ : request->protection_mask;
  uint64_t start_ns = monotonic_ns();

  for (size_t mi = 0U; mi < maps.count && !out->truncated; ++mi) {
    const memdbg_map_entry_t *map = &maps.entries[mi];
    if ((map->protection & prot_mask) != prot_mask || map->end <= map->start) continue;
    uint64_t scan_start = map->start, scan_end = map->end;
    if (request->start != 0U && scan_start < request->start) scan_start = request->start;
    if (request->end   != 0U && scan_end   > request->end)   scan_end   = request->end;
    if (scan_end <= scan_start) continue;
    uint64_t map_len = scan_end - scan_start;
    if (map_len < value_len) continue;
    out->regions_scanned++;

    uint64_t scanned = 0U;
    size_t carry = 0U;

    while (scanned < map_len && !out->truncated) {
      uint64_t remaining = map_len - scanned;
      size_t to_read = remaining > MEMDBG_SCAN_CHUNK ? MEMDBG_SCAN_CHUNK : (size_t)remaining;
      size_t read_len = 0U;

      out->read_calls++;
      st = memdbg_memory_read(request->pid, scan_start + scanned,
          buffer + carry, to_read, &read_len);
      if (st != MEMDBG_OK) { out->read_errors++; break; }
      if (read_len == 0U) break;
      out->bytes_scanned += (uint64_t)read_len;

      size_t window = carry + read_len;
      uint64_t base_addr = scan_start + scanned - (uint64_t)carry;

      /* Capture every aligned address in this window. */
      size_t first = 0U;
      if (base_addr < scan_start) {
        /* The first carry bytes are from the previous chunk — skip
           positions whose absolute address is < scan_start. */
        uint64_t off = scan_start - base_addr;
        if (off >= window) { scanned += read_len; continue; }
        first = (size_t)off;
      }
      /* Align first to the requested alignment */
      if (alignment > 1U) {
        uint64_t misalign = ((base_addr + first) - scan_start) % alignment;
        if (misalign != 0U) first += (size_t)((uint64_t)alignment - misalign);
      }

      for (size_t pos = first; pos + value_len <= window && !out->truncated; pos += alignment) {
        uint64_t addr = base_addr + (uint64_t)pos;
        if (addr + value_len > scan_end) break;
        st = scan_builder_append(&builder, addr);
        if (st != MEMDBG_OK) { free(buffer); memdbg_process_maps_free(&maps); return st; }
      }

      /* Carry tail for cross-chunk coverage. */
      if (overlap != 0U) {
        carry = window < overlap ? window : overlap;
        if (carry > 0U)
          memmove(buffer, buffer + window - carry, carry);
      }
      scanned += read_len;
    }
  }

  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;

  memdbg_process_maps_free(&maps);
  free(buffer);
  return MEMDBG_OK;
}

/* ---- Public API: pointer scan ---- */

memdbg_status_t memdbg_scan_pointer(const memdbg_scan_pointer_request_t *request,
                                    memdbg_scan_result_t *out) {
  if (request == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  if (request->length == 0U || request->max_depth == 0U) return MEMDBG_ERR_PARAM;

  memset(out, 0, sizeof(*out));

  /* Buffer: chunk size + sizeof(uint64_t)-1 so pointers crossing chunk
     boundaries are never missed. */
  static const size_t kPtrOverlap = sizeof(uint64_t) - 1U;
  unsigned char *buffer = (unsigned char *)malloc(MEMDBG_SCAN_CHUNK + kPtrOverlap);
  if (buffer == NULL) return MEMDBG_ERR_NOMEM;

  scan_builder_t builder;
  memset(&builder, 0, sizeof(builder));
  builder.result = out;
  builder.max_results = request->max_results == 0U ? 1U : (size_t)request->max_results;
  scan_builder_prealloc(&builder);

  uint32_t alignment = request->alignment == 0U ? 8U : request->alignment;
  uint64_t scanned = 0U;
  size_t carry = 0U;
  uint64_t start_ns = monotonic_ns();

  while (scanned < request->length && !out->truncated) {
    uint64_t remaining = request->length - scanned;
    size_t to_read = remaining > MEMDBG_SCAN_CHUNK ? MEMDBG_SCAN_CHUNK : (size_t)remaining;
    size_t read_len = 0U;

    out->read_calls++;
    memdbg_status_t st = memdbg_memory_read(request->pid, request->start + scanned,
        buffer + carry, to_read, &read_len);
    if (st != MEMDBG_OK) { out->read_errors++; break; }
    if (read_len == 0U) break;
    out->bytes_scanned += (uint64_t)read_len;

    /* window = carry from previous chunk + freshly read data.
       base_addr is shifted back by carry bytes so absolute addresses
       are computed correctly. */
    size_t window = carry + read_len;
    uint64_t base_addr = request->start + scanned - (uint64_t)carry;

    for (size_t i = 0U; i + sizeof(uint64_t) <= window && !out->truncated; i += alignment) {
      uint64_t candidate;
      memcpy(&candidate, buffer + i, sizeof(candidate));
      if (candidate == request->target_address) {
        uint64_t addr = base_addr + i;
        memdbg_status_t as = scan_builder_append(&builder, addr);
        if (as != MEMDBG_OK) { free(buffer); return as; }
      }
    }

    /* Preserve tail for cross-chunk continuity. */
    carry = window < kPtrOverlap ? window : kPtrOverlap;
    if (carry > 0U)
      memmove(buffer, buffer + window - carry, carry);

    scanned += read_len;
  }

  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;
  out->regions_scanned = 1U;
  free(buffer);
  return MEMDBG_OK;
}

void memdbg_scan_result_free(memdbg_scan_result_t *result) {
  if (result == NULL) return;
  free(result->entries);
  memset(result, 0, sizeof(*result));
}
