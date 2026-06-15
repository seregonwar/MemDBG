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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MEMDBG_SCAN_CHUNK (1024U * 1024U)  /* 1 MiB (was 256 KiB) */
#define MEMDBG_SCAN_INITIAL_CAPACITY 256U
#define MEMDBG_MAP_PROT_READ 1U

/* ---- Boyer-Moore-Horspool skip tables ---- */

#define BM_ALPHABET_SIZE 256U
#define BM_GS_MIN_LENGTH 4U  /* Only apply good-suffix for patterns >= 4 bytes */

typedef struct {
  size_t skip[BM_ALPHABET_SIZE];  /* Bad-character shift */
  size_t *gs_shift;               /* Good-suffix shift (NULL if not used) */
} bm_table_t;

/* ---- Bad-character (BMH) skip table ---- */

static void bm_build_bc_table(const unsigned char *pattern, size_t pat_len,
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

/* ---- Good-suffix shift table (Boyer-Moore) ----
 *
 * Only built for exact patterns (no wildcards) of length >= BM_GS_MIN_LENGTH.
 * This is O(pat_len) to build.  For wildcard patterns the gs_shift pointer
 * stays NULL and only bad-character shifts are used.
 *
 * Reference: Gusfield, "Algorithms on Strings, Trees, and Sequences", §2.2 */

static bool bm_build_gs_table(const unsigned char *pattern, size_t pat_len,
                              bm_table_t *table) {
  if (pat_len < BM_GS_MIN_LENGTH) return true;

  table->gs_shift = (size_t *)malloc(pat_len * sizeof(size_t));
  if (table->gs_shift == NULL) return false;

  /* Compute suffix lengths: suffix[i] = length of the longest suffix of P[0..i]
     that matches a suffix of P.  Goodman-Liang algorithm, O(pat_len). */
  size_t *suffix = (size_t *)malloc(pat_len * sizeof(size_t));
  if (suffix == NULL) { free(table->gs_shift); table->gs_shift = NULL; return false; }

  /* Goodman-Liang suffix algorithm uses signed arithmetic: when the
     while-loop matches all the way past position 0, g becomes -1 and
     suffix[i] = f - g = f - (-1) = f + 1, which is the correct length.
     With unsigned size_t, g would wrap to SIZE_MAX and corrupt the result. */
  suffix[pat_len - 1U] = pat_len;
  ptrdiff_t f = 0, g = (ptrdiff_t)(pat_len - 1U);
  for (ptrdiff_t i = (ptrdiff_t)(pat_len - 2U); i >= 0; --i) {
    if (i > g && suffix[i + pat_len - 1U - (size_t)f] < (size_t)(i - g)) {
      suffix[i] = suffix[i + pat_len - 1U - (size_t)f];
    } else {
      if (i < g) g = i;
      f = i;
      while (g >= 0 && pattern[g] == pattern[g + pat_len - 1U - (size_t)f])
        --g;
      suffix[i] = (size_t)(f - g);
    }
  }

  /* Build good-suffix shift table from suffix array.
     gs_shift[j] = shift to apply when a mismatch occurs at position j
     (0-indexed, j = position in pattern where mismatch happened). */
  for (size_t j = 0U; j < pat_len; ++j)
    table->gs_shift[j] = pat_len;

  /* Case 1: The matching suffix occurs elsewhere in the pattern. */
  size_t j = 0U;
  for (size_t i = pat_len - 1U; i != (size_t)-1; --i) {
    if (suffix[i] == i + 1U) {
      /* Full prefix of length i+1 matches suffix */
      for (; j < pat_len - 1U - i; ++j)
        if (table->gs_shift[j] == pat_len)
          table->gs_shift[j] = pat_len - 1U - i;
    }
  }

  /* Case 2: The longest suffix ending at i appears elsewhere. */
  for (size_t i = 0U; i <= pat_len - 2U; ++i) {
    size_t pos = pat_len - 1U - suffix[i];
    if (table->gs_shift[pos] > pat_len - 1U - i)
      table->gs_shift[pos] = pat_len - 1U - i;
  }

  free(suffix);
  return true;
}

static void bm_build_table(const unsigned char *pattern, size_t pat_len,
                           const unsigned char *mask, bm_table_t *table) {
  memset(table, 0, sizeof(*table));
  bm_build_bc_table(pattern, pat_len, mask, table);

  /* Good-suffix only for exact patterns (no wildcards). */
  bool all_exact = true;
  for (size_t i = 0U; i < pat_len; ++i) {
    if (mask[i] == 0U) { all_exact = false; break; }
  }
  if (all_exact)
    bm_build_gs_table(pattern, pat_len, table);
  else
    table->gs_shift = NULL;
}

static void bm_free_table(bm_table_t *table) {
  free(table->gs_shift);
  table->gs_shift = NULL;
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
      if (carry > 0U)
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

/* ---- AOB range scanner (BMH + good-suffix, reusable helper) ----
 *
 * Scans a single memory range [range_start, range_start + range_len)
 * using a pre-built BMH table.  Caller owns the buffer, builder, and
 * bm_table.  Returns MEMDBG_OK on success (including when truncated). */

static memdbg_status_t scan_aob_range(const bm_table_t *bm,
                                      const unsigned char *pattern,
                                      const unsigned char *mask,
                                      size_t pat_len,
                                      int pid,
                                      uint64_t range_start, uint64_t range_len,
                                      unsigned char *buffer,
                                      scan_builder_t *builder) {
  if (range_len < pat_len) return MEMDBG_OK;

  size_t overlap = pat_len > 1U ? pat_len - 1U : 0U;
  uint64_t scanned = 0U;
  size_t carry = 0U;

  while (scanned < range_len && !builder->result->truncated) {
    uint64_t remaining = range_len - scanned;
    size_t to_read = remaining > MEMDBG_SCAN_CHUNK ? MEMDBG_SCAN_CHUNK : (size_t)remaining;
    size_t read_len = 0U;

    builder->result->read_calls++;
    memdbg_status_t st = memdbg_memory_read(pid, range_start + scanned,
        buffer + carry, to_read, &read_len);
    if (st != MEMDBG_OK) { builder->result->read_errors++; break; }
    if (read_len == 0U) break;
    builder->result->bytes_scanned += (uint64_t)read_len;

    size_t window = carry + read_len;
    uint64_t base_addr = range_start + scanned - (uint64_t)carry;

    /* BMH + good-suffix search loop. */
    size_t i = pat_len - 1U;
    const unsigned char *hay = buffer;
    while (i < window && !builder->result->truncated) {
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
        memdbg_status_t as = scan_builder_append(builder, addr);
        if (as != MEMDBG_OK) return as;
        i += 1U;
      } else {
        size_t bc = bm->skip[hay[i]];
        size_t gs = 1U;
        if (bm->gs_shift != NULL && j < pat_len - 1U)
          gs = bm->gs_shift[j + 1U];
        i += bc > gs ? bc : gs;
      }
    }

    if (overlap != 0U) {
      carry = window < overlap ? window : overlap;
      if (carry > 0U)
        memmove(buffer, buffer + window - carry, carry);
    }
    scanned += read_len;
  }

  return MEMDBG_OK;
}

/* ---- Public API: AOB scan (single range, Boyer-Moore-Horspool) ---- */

memdbg_status_t memdbg_scan_aob(const memdbg_scan_aob_request_t *request,
                                const uint8_t *pattern, const uint8_t *mask,
                                memdbg_scan_result_t *out) {
  if (request == NULL || pattern == NULL || mask == NULL || out == NULL)
    return MEMDBG_ERR_PARAM;
  if (request->pattern_length == 0U || request->length == 0U)
    return MEMDBG_ERR_PARAM;

  memset(out, 0, sizeof(*out));

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

  bm_table_t bm;
  bm_build_table(pattern, pat_len, mask, &bm);

  uint64_t start_ns = monotonic_ns();
  memdbg_status_t st = scan_aob_range(&bm, pattern, mask, pat_len,
      request->pid, request->start, request->length, buffer, &builder);
  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;
  out->regions_scanned = 1U;

  bm_free_table(&bm);
  free(buffer);
  if (st != MEMDBG_OK) memdbg_scan_result_free(out);
  return st;
}

/* ---- Public API: process-wide AOB scan (BMH + good-suffix over cached maps) ---- */

memdbg_status_t memdbg_scan_process_aob(const memdbg_scan_process_aob_request_t *request,
                                        const uint8_t *pattern, const uint8_t *mask,
                                        memdbg_scan_result_t *out) {
  if (request == NULL || pattern == NULL || mask == NULL || out == NULL)
    return MEMDBG_ERR_PARAM;
  if (request->pattern_length == 0U || request->pattern_length > 256U)
    return MEMDBG_ERR_PARAM;

  memset(out, 0, sizeof(*out));

  size_t pat_len = (size_t)request->pattern_length;
  size_t overlap = pat_len > 1U ? pat_len - 1U : 0U;
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

  bm_table_t bm;
  bm_build_table(pattern, pat_len, mask, &bm);

  uint32_t prot_mask = request->protection_mask == 0U ? MEMDBG_MAP_PROT_READ : request->protection_mask;
  uint64_t start_ns = monotonic_ns();

  for (size_t i = 0U; i < maps.count && !out->truncated; ++i) {
    const memdbg_map_entry_t *map = &maps.entries[i];
    if ((map->protection & prot_mask) != prot_mask || map->end <= map->start) continue;
    uint64_t scan_start = map->start, scan_end = map->end;
    if (request->start != 0U && scan_start < request->start) scan_start = request->start;
    if (request->end   != 0U && scan_end   > request->end)   scan_end   = request->end;
    if (scan_end <= scan_start) continue;
    uint64_t map_len = scan_end - scan_start;
    if (map_len < pat_len) continue;
    out->regions_scanned++;
    st = scan_aob_range(&bm, pattern, mask, pat_len,
        request->pid, scan_start, map_len, buffer, &builder);
    if (st != MEMDBG_OK) break;
  }

  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;

  bm_free_table(&bm);
  memdbg_process_maps_free(&maps);
  free(buffer);
  if (st != MEMDBG_OK) memdbg_scan_result_free(out);
  return st;
}

/* ---- Public API: unknown initial value scan (captures every aligned address) ---- */

memdbg_status_t memdbg_scan_unknown(const memdbg_scan_process_exact_request_t *request,
                                    memdbg_scan_result_t *out) {
  if (request == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));

  uint32_t value_len = expected_value_length(request->value_type, request->value_length);
  if (value_len == 0U || value_len > MEMDBG_SCAN_VALUE_MAX) return MEMDBG_ERR_PARAM;
  /* Hoist alignment calculation outside the region loop. */
  uint32_t alignment = request->alignment == 0U ? value_len : request->alignment;
  bool need_alignment = alignment > 1U;

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
      if (need_alignment) {
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
