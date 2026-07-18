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

#include "memdbg/scanner/scan_partition.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(PLATFORM_PS4) || defined(PLATFORM_PS5) || defined(PS4) ||          \
    defined(PS5) || defined(__ORBIS__) || defined(__PROSPERO__)
#define MEMDBG_SCAN_CONSOLE 1
#endif

#if defined(MEMDBG_SCAN_CONSOLE)
/* mdbg_copyout is much less forgiving than host /proc reads when a range
   crosses a fragile page. Keep console reads small and serialized. */
#define MEMDBG_SCAN_CHUNK (64U * 1024U)
#define MEMDBG_SCAN_PARALLEL_THREADS 1U
#else
#define MEMDBG_SCAN_CHUNK MEMDBG_PROTOCOL_MAX_READ
#define MEMDBG_SCAN_PARALLEL_THREADS 4U
#endif

#define MEMDBG_SCAN_MIN_READ_CHUNK 4096U
#define MEMDBG_SCAN_MAX_LENGTH (32ULL * 1024ULL * 1024ULL * 1024ULL)
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
    if (i > g && suffix[(size_t)i + pat_len - 1U - (size_t)f] < (size_t)(i - g)) {
      suffix[(size_t)i] = suffix[(size_t)i + pat_len - 1U - (size_t)f];
    } else {
      if (i < g) g = i;
      f = i;
      while (g >= 0 && pattern[(size_t)g] == pattern[(size_t)g + pat_len - 1U - (size_t)f])
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

static memdbg_status_t process_scan_guard_begin(void) {
  return MEMDBG_OK;
}

static void process_scan_guard_end(void) {
}

static memdbg_status_t scan_process_maps_for_scan(int pid,
                                                  memdbg_map_list_t *maps) {
  return memdbg_process_maps_cached(pid, maps);
}

/* ---- Clock ---- */

static uint64_t monotonic_ns(void) {
#if defined(CLOCK_MONOTONIC)
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
#endif
  return 0U;
}

/* ---- Defensive memory reads ---- */

static void scan_metric_inc(uint32_t *value) {
  if (value != NULL && *value != UINT32_MAX) (*value)++;
}

static size_t scan_read_size(uint64_t remaining) {
  return remaining > (uint64_t)MEMDBG_SCAN_CHUNK
      ? (size_t)MEMDBG_SCAN_CHUNK
      : (size_t)remaining;
}

static size_t scan_fault_skip_size(size_t requested) {
  if (requested == 0U) return 0U;
  return requested < MEMDBG_SCAN_MIN_READ_CHUNK
      ? requested
      : (size_t)MEMDBG_SCAN_MIN_READ_CHUNK;
}

static bool scan_bounds_valid(uint64_t start, uint64_t length,
                              uint64_t min_length, uint64_t *end_out) {
  if (length == 0U || length < min_length) return false;
  if (length > MEMDBG_SCAN_MAX_LENGTH) return false;
  if (UINT64_MAX - start < length) return false;
  if (end_out != NULL) *end_out = start + length;
  return true;
}

static memdbg_status_t scan_memory_read_resilient(
    int pid, uint64_t address, void *buffer, size_t requested,
    memdbg_scan_result_t *metrics, size_t *read_out) {
  if (read_out != NULL) *read_out = 0U;
  if (requested == 0U) return MEMDBG_OK;

  size_t attempt = requested;
  while (attempt != 0U) {
    scan_metric_inc(metrics != NULL ? &metrics->read_calls : NULL);

    size_t read_len = 0U;
    memdbg_status_t st = memdbg_memory_read(pid, address, buffer, attempt, &read_len);
    if (st == MEMDBG_OK) {
      if (read_out != NULL) *read_out = read_len;
      return MEMDBG_OK;
    }

    scan_metric_inc(metrics != NULL ? &metrics->read_errors : NULL);
    if (attempt <= MEMDBG_SCAN_MIN_READ_CHUNK) return st;

    size_t next = attempt / 2U;
    if (next < MEMDBG_SCAN_MIN_READ_CHUNK) next = MEMDBG_SCAN_MIN_READ_CHUNK;
    if (next >= attempt) return st;
    attempt = next;
  }

  return MEMDBG_ERR_IO;
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
  /* Single uint16 comparison — compiler emits one load+cmp on LE targets. */
  uint16_t cv, nv;
  memcpy(&cv, c, sizeof(cv)); memcpy(&nv, n, sizeof(nv));
  return cv == nv;
}

static bool match_u32(const unsigned char *c, const unsigned char *n, size_t len) {
  (void)len;
  uint32_t cv, nv;
  memcpy(&cv, c, sizeof(cv)); memcpy(&nv, n, sizeof(nv));
  return cv == nv;
}

static bool match_u64(const unsigned char *c, const unsigned char *n, size_t len) {
  (void)len;
  uint64_t cv, nv;
  memcpy(&cv, c, sizeof(cv)); memcpy(&nv, n, sizeof(nv));
  return cv == nv;
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
    while (pos < searchable) {
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

  for (size_t i = first; i < searchable; i += ctx->alignment) {
    uint64_t absolute = base_addr + i;
    if (absolute > range_end || (uint64_t)value_len > range_end - absolute) break;
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
  uint64_t range_end = 0U;

  if (!scan_bounds_valid(range_start, range_len, ctx->value_len, &range_end))
    return MEMDBG_ERR_PARAM;

  while (scanned < range_len) {
    uint64_t remaining = range_len - scanned;
    size_t to_read = scan_read_size(remaining);
    size_t read_len = 0U;

    memdbg_status_t st = scan_memory_read_resilient(ctx->pid,
        range_start + scanned, ctx->buffer + carry, to_read,
        builder->result, &read_len);
    if (st != MEMDBG_OK) {
      if (!skip_read_errors) return st;
      scanned += scan_fault_skip_size(to_read);
      carry = 0U;
      continue;
    }
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

/* ================================================================
 *  Parallel map scanner
 * ================================================================
 *
 * Divides filtered map entries across N threads.  Each thread gets
 * its own buffer and result builder; results are merged at the end.
 *
 * map_scan_fn signature:
 *   memdbg_status_t (*)(void *ctx, int pid, uint64_t start,
 *                       uint64_t len, unsigned char *buffer,
 *                       scan_builder_t *builder)
 *
 * The callback scans one memory range, writing addresses into the
 * thread-local builder.  The caller provides the per-thread buffer
 * size (buf_size) so the orchestrator can allocate buffers. */

typedef memdbg_status_t (*parallel_map_scan_fn_t)(
    void *ctx, int pid, uint64_t start, uint64_t len,
    unsigned char *buffer, scan_builder_t *builder);

typedef struct {
  parallel_map_scan_fn_t scan_fn;
  void                 *ctx;
  int                   pid;
  size_t                max_results;
  size_t                buf_size;
  const memdbg_map_entry_t *maps;
  size_t                map_start;   /* first assigned map index */
  size_t                map_end;     /* one past last assigned map */
  uint32_t              prot_mask;
  uint64_t              start_filter;
  uint64_t              end_filter;
  size_t                min_map_len;
  /* Output — per thread */
  memdbg_scan_result_t  result;
  uint32_t              read_calls;
  uint32_t              read_errors;
  uint64_t              bytes_scanned;
  uint32_t              regions_scanned;
  memdbg_status_t       status;
  bool                  threaded;
} parallel_worker_t;

static void *parallel_worker_thread(void *arg) {
  parallel_worker_t *w = (parallel_worker_t *)arg;
  unsigned char *buffer;

  memset(&w->result, 0, sizeof(w->result));
  w->read_calls      = 0U;
  w->read_errors     = 0U;
  w->bytes_scanned   = 0U;
  w->regions_scanned = 0U;
  w->status          = MEMDBG_OK;

  /* Allocate per-thread buffer. */
  buffer = (unsigned char *)malloc(w->buf_size);
  if (buffer == NULL) {
    w->status = MEMDBG_ERR_NOMEM;
    return NULL;
  }

  /* Per-thread result builder — start small and let scan_builder_append
     grow via incremental realloc (avoids worst-case N*max_results pre-alloc). */
  scan_builder_t builder;
  builder.result       = &w->result;
  builder.max_results  = w->max_results;
  builder.capacity     = 0U;  /* first append allocates MEMDBG_SCAN_INITIAL_CAPACITY */

  for (size_t i = w->map_start; i < w->map_end; ++i) {
    const memdbg_map_entry_t *map = &w->maps[i];
    if ((map->protection & w->prot_mask) != w->prot_mask ||
        map->end <= map->start)
      continue;

    uint64_t scan_start = map->start, scan_end = map->end;
    if (w->start_filter != 0U && scan_start < w->start_filter)
      scan_start = w->start_filter;
    if (w->end_filter   != 0U && scan_end   > w->end_filter)
      scan_end   = w->end_filter;
    if (scan_end <= scan_start) continue;

    uint64_t map_len = scan_end - scan_start;
    if (map_len < w->min_map_len) continue;

    uint64_t cursor = scan_start;
    uint64_t remaining = map_len;
    while (remaining != 0U) {
      uint64_t segment_len = remaining > MEMDBG_SCAN_MAX_LENGTH
          ? MEMDBG_SCAN_MAX_LENGTH
          : remaining;
      if (segment_len < (uint64_t)w->min_map_len) break;

      w->regions_scanned++;
      w->status = w->scan_fn(w->ctx, w->pid, cursor, segment_len,
                             buffer, &builder);

      if (w->status != MEMDBG_OK) break;
      cursor += segment_len;
      remaining -= segment_len;
    }
    if (w->status != MEMDBG_OK) break;
  }

  /* Snapshot final per-thread metrics from the result struct. */
  w->read_calls    = (uint32_t)w->result.read_calls;
  w->read_errors   = w->result.read_errors;
  w->bytes_scanned = w->result.bytes_scanned;

  free(buffer);
  return NULL;
}

/* ---- Result merge helper ----
 *
 * Copies entries from per-thread result buffers directly into `out`,
 * which is already pre-allocated at max_results.  Sets `out->truncated`
 * if any thread was truncated.  No intermediate allocation. */

static memdbg_status_t merge_scan_results(
    parallel_worker_t *workers, size_t num_workers,
    memdbg_scan_result_t *out, size_t max_results) {
  size_t total_count = 0U;
  bool any_truncated = false;

  for (size_t w = 0U; w < num_workers; ++w) {
    total_count += workers[w].result.count;
    if (workers[w].result.truncated) any_truncated = true;
    out->read_calls      += workers[w].read_calls;
    out->read_errors     += workers[w].read_errors;
    out->bytes_scanned   += workers[w].bytes_scanned;
    out->regions_scanned += workers[w].regions_scanned;
  }

  /* Clamp to max_results. */
  if (total_count > max_results) {
    total_count = max_results;
    any_truncated = true;
  }

  if (total_count == 0U) { out->count = 0U; return MEMDBG_OK; }

  /* Copy directly into out->entries (already pre-allocated at max_results). */
  size_t pos = 0U;
  for (size_t w = 0U; w < num_workers && pos < total_count; ++w) {
    size_t wc = workers[w].result.count;
    if (wc == 0U) continue;
    if (pos + wc > total_count) wc = total_count - pos;
    memcpy(out->entries + pos, workers[w].result.entries,
           wc * sizeof(memdbg_scan_result_entry_t));
    pos += wc;
  }

  out->count     = total_count;
  out->truncated = any_truncated;
  return MEMDBG_OK;
}

/* ---- Parallel map scan orchestrator ---- */

static memdbg_status_t scan_maps_parallel(
    parallel_map_scan_fn_t scan_fn, void *ctx,
    int pid, const memdbg_map_entry_t *maps, size_t map_count,
    size_t max_results, size_t buf_size, size_t min_map_len,
    uint32_t prot_mask, uint64_t start_filter, uint64_t end_filter,
    memdbg_scan_result_t *out) {

  const size_t max_threads = MEMDBG_SCAN_PARALLEL_THREADS;
  size_t num_threads = max_threads < 1U ? 1U : max_threads;

  /* Partition maps by byte budget.  partition_maps_by_bytes handles
     thread-count clamping, empty-slot fill, and returns the actual
     number of used slots via out_used. */
  scan_partition_slot_t *slots = (scan_partition_slot_t *)calloc(
      num_threads, sizeof(scan_partition_slot_t));
  if (slots == NULL) return MEMDBG_ERR_NOMEM;

  size_t actual_workers = 0U;
  memdbg_status_t part_st = partition_maps_by_bytes(
      maps, map_count, prot_mask, start_filter, end_filter,
      min_map_len, num_threads, slots, &actual_workers);
  if (part_st != MEMDBG_OK) {
    free(slots);
    return part_st;
  }
  /* Allocate worker structs sized to actual used slots only. */
  parallel_worker_t *workers =
      (parallel_worker_t *)calloc(actual_workers, sizeof(parallel_worker_t));
  if (workers == NULL) {
    free(slots);
    return MEMDBG_ERR_NOMEM;
  }

  /* Pre-allocate the output buffer at max_results.  Workers get
     their own per-thread preallocated buffers inside the thread. */
  memset(out, 0, sizeof(*out));
  out->entries = (memdbg_scan_result_entry_t *)malloc(
      max_results * sizeof(memdbg_scan_result_entry_t));
  if (out->entries == NULL) {
    free(workers);
    free(slots);
    return MEMDBG_ERR_NOMEM;
  }
  out->count = 0U;

  for (size_t t = 0U; t < actual_workers; ++t) {
    workers[t].map_start = slots[t].map_start;
    workers[t].map_end   = slots[t].map_end;
  }
  free(slots);

  /* Populate shared fields and spawn threads. */
  pthread_t *threads =
      (pthread_t *)malloc(actual_workers * sizeof(pthread_t));
  bool spawn_ok = (threads != NULL);

  for (size_t t = 0U; t < actual_workers; ++t) {
    workers[t].scan_fn      = scan_fn;
    workers[t].ctx          = ctx;
    workers[t].pid          = pid;
    workers[t].max_results  = max_results;
    workers[t].buf_size     = buf_size;
    workers[t].maps         = maps;
    workers[t].prot_mask    = prot_mask;
    workers[t].start_filter = start_filter;
    workers[t].end_filter   = end_filter;
    workers[t].min_map_len  = min_map_len;

    if (spawn_ok && actual_workers > 1U &&
        workers[t].map_start < workers[t].map_end) {
      if (pthread_create(&threads[t], NULL,
                         parallel_worker_thread, &workers[t]) != 0) {
        spawn_ok = false;
        workers[t].status = MEMDBG_ERR_NET;
      } else {
        workers[t].threaded = true;
      }
    } else {
      /* Run inline for single-thread or empty range. */
      parallel_worker_thread(&workers[t]);
    }
  }

  /* Join all spawned threads. */
  for (size_t t = 0U; t < actual_workers; ++t) {
    if (workers[t].threaded)
      (void)pthread_join(threads[t], NULL);
  }

  free(threads);

  /* Merge results */
  {
    memdbg_status_t merge_st =
        merge_scan_results(workers, actual_workers, out, max_results);
    memdbg_status_t first_err = MEMDBG_OK;

    for (size_t t = 0U; t < actual_workers; ++t) {
      if (workers[t].status != MEMDBG_OK && first_err == MEMDBG_OK)
        first_err = workers[t].status;
      /* Free per-thread result entries (now copied into `out`). */
      free(workers[t].result.entries);
    }

    free(workers);

    if (merge_st != MEMDBG_OK) {
      memdbg_scan_result_free(out);
      return merge_st;
    }
    if (first_err != MEMDBG_OK) {
      memdbg_scan_result_free(out);
      return first_err;
    }
  }

  return MEMDBG_OK;
}

/* ---- Map-filter helper (shared by process-wide scans) ---- */

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
  if (!scan_bounds_valid(request->start, request->length, ctx.value_len, NULL)) {
    scan_context_fini(&ctx);
    return MEMDBG_ERR_PARAM;
  }

  scan_builder_t builder;
  memset(&builder, 0, sizeof(builder));
  builder.result = out;
  builder.max_results = request->max_results == 0U ? 1U : (size_t)request->max_results;
  st = scan_builder_prealloc(&builder);
  if (st != MEMDBG_OK) { scan_context_fini(&ctx); return st; }

  uint64_t start_ns = monotonic_ns();
  out->regions_scanned = 1U;
  st = scan_range(&ctx, &builder, request->start, request->length,
                  request->start, true);
  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;

  scan_context_fini(&ctx);
  if (st != MEMDBG_OK) memdbg_scan_result_free(out);
  return st;
}

/* ---- Callback: exact-value scan of one map range ---- */

static memdbg_status_t scan_range_cb(void *ctx, int pid, uint64_t start,
                                     uint64_t len, unsigned char *buffer,
                                     scan_builder_t *builder) {
  scan_context_t *sctx = (scan_context_t *)ctx;
  (void)pid;
  /* Each worker owns its buffer; never mutate the shared scan context. */
  scan_context_t local = *sctx;
  local.buffer = buffer;
  return scan_range(&local, builder, start, len, start, true);
}

/* ---- Public API: process exact scan (uses cached maps, parallel) ---- */

memdbg_status_t memdbg_scan_process_exact(const memdbg_scan_process_exact_request_t *request,
                                          memdbg_scan_result_t *out) {
  if (request == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));

  scan_context_t ctx;
  memdbg_status_t st = scan_context_init(&ctx, request->pid, request->value_type,
      request->value_length, request->alignment, request->value);
  if (st != MEMDBG_OK) return st;

  st = process_scan_guard_begin();
  if (st != MEMDBG_OK) {
    scan_context_fini(&ctx);
    return st;
  }

  memdbg_map_list_t maps;
  st = scan_process_maps_for_scan(request->pid, &maps);
  if (st != MEMDBG_OK) {
    process_scan_guard_end();
    scan_context_fini(&ctx);
    return st;
  }

  size_t max_results = request->max_results == 0U ? 1U : (size_t)request->max_results;
  uint32_t prot_mask = request->protection_mask == 0U ? MEMDBG_MAP_PROT_READ : request->protection_mask;
  size_t buf_size = MEMDBG_SCAN_CHUNK + (size_t)ctx.value_len - 1U;

  uint64_t start_ns = monotonic_ns();
  st = scan_maps_parallel(scan_range_cb, &ctx,
      request->pid, maps.entries, maps.count,
      max_results, buf_size, (size_t)ctx.value_len,
      prot_mask, request->start, request->end, out);
  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;

  memdbg_process_maps_free(&maps);
  process_scan_guard_end();
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

  while (scanned < range_len) {
    uint64_t remaining = range_len - scanned;
    size_t to_read = scan_read_size(remaining);
    size_t read_len = 0U;

    memdbg_status_t st = scan_memory_read_resilient(pid,
        range_start + scanned, buffer + carry, to_read,
        builder->result, &read_len);
    if (st != MEMDBG_OK) {
      scanned += scan_fault_skip_size(to_read);
      carry = 0U;
      continue;
    }
    if (read_len == 0U) break;
    builder->result->bytes_scanned += (uint64_t)read_len;

    size_t window = carry + read_len;
    uint64_t base_addr = range_start + scanned - (uint64_t)carry;

    /* BMH + good-suffix search loop. */
    size_t i = pat_len - 1U;
    const unsigned char *hay = buffer;
    while (i < window) {
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
  if (!scan_bounds_valid(request->start, request->length,
                         request->pattern_length, NULL))
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
  memdbg_status_t st = scan_builder_prealloc(&builder);
  if (st != MEMDBG_OK) { free(buffer); return st; }

  bm_table_t bm;
  bm_build_table(pattern, pat_len, mask, &bm);

  uint64_t start_ns = monotonic_ns();
  st = scan_aob_range(&bm, pattern, mask, pat_len,
      request->pid, request->start, request->length, buffer, &builder);
  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;
  out->regions_scanned = 1U;

  bm_free_table(&bm);
  free(buffer);
  if (st != MEMDBG_OK) memdbg_scan_result_free(out);
  return st;
}

/* ---- AOB parallel context ---- */

typedef struct {
  const bm_table_t    *bm;
  const unsigned char *pattern;
  const unsigned char *mask;
  size_t               pat_len;
} aob_parallel_ctx_t;

static memdbg_status_t scan_aob_cb(void *ctx, int pid, uint64_t start,
                                   uint64_t len, unsigned char *buffer,
                                   scan_builder_t *builder) {
  aob_parallel_ctx_t *ac = (aob_parallel_ctx_t *)ctx;
  return scan_aob_range(ac->bm, ac->pattern, ac->mask, ac->pat_len,
                        pid, start, len, buffer, builder);
}

/* ---- Public API: process-wide AOB scan (BMH + good-suffix over cached maps, parallel) ---- */

memdbg_status_t memdbg_scan_process_aob(const memdbg_scan_process_aob_request_t *request,
                                        const uint8_t *pattern, const uint8_t *mask,
                                        memdbg_scan_result_t *out) {
  if (request == NULL || pattern == NULL || mask == NULL || out == NULL)
    return MEMDBG_ERR_PARAM;
  if (request->pattern_length == 0U || request->pattern_length > 256U)
    return MEMDBG_ERR_PARAM;

  memset(out, 0, sizeof(*out));

  size_t pat_len = (size_t)request->pattern_length;
  size_t buf_size = MEMDBG_SCAN_CHUNK + (pat_len > 1U ? pat_len - 1U : 0U);

  memdbg_status_t st = process_scan_guard_begin();
  if (st != MEMDBG_OK) return st;

  memdbg_map_list_t maps;
  st = scan_process_maps_for_scan(request->pid, &maps);
  if (st != MEMDBG_OK) {
    process_scan_guard_end();
    return st;
  }

  bm_table_t bm;
  bm_build_table(pattern, pat_len, mask, &bm);

  aob_parallel_ctx_t ac;
  ac.bm      = &bm;
  ac.pattern = pattern;
  ac.mask    = mask;
  ac.pat_len = pat_len;

  size_t max_results = request->max_results == 0U ? 1U : (size_t)request->max_results;
  uint32_t prot_mask = request->protection_mask == 0U ? MEMDBG_MAP_PROT_READ : request->protection_mask;

  uint64_t start_ns = monotonic_ns();
  st = scan_maps_parallel(scan_aob_cb, &ac,
      request->pid, maps.entries, maps.count,
      max_results, buf_size, pat_len,
      prot_mask, request->start, request->end, out);
  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;

  bm_free_table(&bm);
  memdbg_process_maps_free(&maps);
  process_scan_guard_end();
  if (st != MEMDBG_OK) memdbg_scan_result_free(out);
  return st;
}

/* ---- Unknown initial-value scan ---- */

typedef struct {
  uint32_t value_len;
  uint32_t alignment;
  uint32_t flags;
} unknown_scan_context_t;

static bool unknown_value_is_candidate(const unsigned char *value,
                                       uint32_t value_len, uint32_t flags) {
  if ((flags & MEMDBG_SCAN_UNKNOWN_FLAG_NONZERO) == 0U) return true;
  for (uint32_t i = 0U; i < value_len; ++i)
    if (value[i] != 0U) return true;
  return false;
}

static int compare_map_start(const void *lhs, const void *rhs) {
  const memdbg_map_entry_t *a = (const memdbg_map_entry_t *)lhs;
  const memdbg_map_entry_t *b = (const memdbg_map_entry_t *)rhs;
  if (a->start < b->start) return -1;
  if (a->start > b->start) return 1;
  if (a->end < b->end) return -1;
  if (a->end > b->end) return 1;
  return 0;
}

static memdbg_status_t scan_unknown_range(
    const unknown_scan_context_t *uc, int pid, uint64_t start, uint64_t len,
    uint64_t alignment_base, unsigned char *buffer, scan_builder_t *builder) {
  size_t overlap = uc->value_len > 1U ? (size_t)uc->value_len - 1U : 0U;
  uint64_t scanned = 0U;
  size_t carry = 0U;
  uint64_t range_end = 0U;

  if (!scan_bounds_valid(start, len, uc->value_len, &range_end))
    return MEMDBG_ERR_PARAM;

  while (scanned < len) {
    uint64_t remaining = len - scanned;
    size_t to_read = scan_read_size(remaining);
    size_t read_len = 0U;

    memdbg_status_t st = scan_memory_read_resilient(pid,
        start + scanned, buffer + carry, to_read,
        builder->result, &read_len);
    if (st != MEMDBG_OK) {
      scanned += scan_fault_skip_size(to_read);
      carry = 0U;
      continue;
    }
    if (read_len == 0U) break;
    builder->result->bytes_scanned += (uint64_t)read_len;

    size_t window = carry + read_len;
    uint64_t base_addr = start + scanned - (uint64_t)carry;

    size_t first = first_aligned_offset(
        base_addr, alignment_base, start, uc->alignment);
    if (first == SIZE_MAX) return MEMDBG_ERR_OVERFLOW;

    for (size_t pos = first;
         pos <= window && uc->value_len <= window - pos;
         pos += uc->alignment) {
      uint64_t addr = base_addr + (uint64_t)pos;
      if (addr > range_end || (uint64_t)uc->value_len > range_end - addr) break;
      if (unknown_value_is_candidate(
              buffer + pos, uc->value_len, uc->flags)) {
        memdbg_status_t as = scan_builder_append(builder, addr);
        if (as != MEMDBG_OK) return as;
      }
      if (SIZE_MAX - pos < uc->alignment) break;
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

memdbg_status_t memdbg_scan_unknown(const memdbg_scan_unknown_request_t *request,
                                    memdbg_scan_result_t *out) {
  if (request == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));

  if (request->abi_magic != MEMDBG_SCAN_UNKNOWN_ABI_MAGIC ||
      request->abi_version != MEMDBG_SCAN_UNKNOWN_ABI_VERSION ||
      request->struct_size != sizeof(*request) ||
      (request->flags & ~MEMDBG_SCAN_UNKNOWN_KNOWN_FLAGS) != 0U ||
      request->reserved != 0U || request->pid <= 0)
    return MEMDBG_ERR_PARAM;
  if (request->end != 0U && request->end <= request->start)
    return MEMDBG_ERR_PARAM;
  if (request->max_bytes == 0U ||
      request->max_bytes > MEMDBG_SCAN_UNKNOWN_MAX_UNIT_BYTES)
    return MEMDBG_ERR_PARAM;

  unknown_scan_context_t uc;
  uc.value_len = expected_value_length(
      request->value_type, request->value_length);
  if (uc.value_len == 0U || uc.value_len > MEMDBG_SCAN_VALUE_MAX)
    return MEMDBG_ERR_PARAM;
  uc.alignment = request->alignment == 0U ? uc.value_len
                                          : request->alignment;
  uc.flags = request->flags;
  if (uc.alignment == 0U) return MEMDBG_ERR_PARAM;

  size_t result_limit =
      MEMDBG_SCAN_UNKNOWN_RESULT_BUDGET / sizeof(memdbg_scan_result_entry_t);
  size_t max_results = request->max_results == 0U
      ? 1U
      : (size_t)request->max_results;
  if (max_results > result_limit) max_results = result_limit;
  if ((size_t)uc.value_len - 1U > SIZE_MAX - MEMDBG_SCAN_CHUNK)
    return MEMDBG_ERR_OVERFLOW;
  size_t buf_size =
      MEMDBG_SCAN_CHUNK + (size_t)uc.value_len - 1U;
  unsigned char *buffer = (unsigned char *)malloc(buf_size);
  if (buffer == NULL) return MEMDBG_ERR_NOMEM;

  memdbg_status_t st = process_scan_guard_begin();
  if (st != MEMDBG_OK) {
    free(buffer);
    return st;
  }

  memdbg_map_list_t maps;
  st = scan_process_maps_for_scan(request->pid, &maps);
  if (st != MEMDBG_OK) {
    process_scan_guard_end();
    free(buffer);
    return st;
  }

  if (maps.count > 1U)
    qsort(maps.entries, maps.count, sizeof(*maps.entries), compare_map_start);

  scan_builder_t builder;
  memset(&builder, 0, sizeof(builder));
  builder.result = out;
  builder.max_results = max_results;

  uint32_t prot_mask = request->protection_mask | MEMDBG_MAP_PROT_READ;
  uint64_t budget_remaining = request->max_bytes;

  uint64_t start_ns = monotonic_ns();
  for (size_t i = 0U; i < maps.count; ++i) {
    const memdbg_map_entry_t *map = &maps.entries[i];
    if ((map->protection & prot_mask) != prot_mask ||
        map->end <= map->start)
      continue;

    uint64_t scan_start = map->start;
    uint64_t scan_end = map->end;
    if (request->start != 0U && scan_start < request->start)
      scan_start = request->start;
    if (request->end != 0U && scan_end > request->end)
      scan_end = request->end;
    if (scan_end <= scan_start ||
        scan_end - scan_start < (uint64_t)uc.value_len)
      continue;
    if (budget_remaining < (uint64_t)uc.value_len) {
      out->truncated = true;
      break;
    }

    uint64_t map_len = scan_end - scan_start;
    uint64_t unit_len = map_len < budget_remaining
        ? map_len
        : budget_remaining;
    if (unit_len < map_len) out->truncated = true;
    scan_metric_inc(&out->regions_scanned);
    st = scan_unknown_range(&uc, request->pid, scan_start, unit_len,
                            map->start, buffer, &builder);
    if (st != MEMDBG_OK) break;
    budget_remaining -= unit_len;
    if (budget_remaining == 0U) {
      if (i + 1U < maps.count || unit_len < map_len)
        out->truncated = true;
      break;
    }
  }
  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;

  memdbg_process_maps_free(&maps);
  process_scan_guard_end();
  free(buffer);
  if (st != MEMDBG_OK) memdbg_scan_result_free(out);
  return st;
}

/* ---- Public API: pointer scan ---- */

memdbg_status_t memdbg_scan_pointer(const memdbg_scan_pointer_request_t *request,
                                    memdbg_scan_result_t *out) {
  if (request == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  if (request->length == 0U || request->max_depth == 0U) return MEMDBG_ERR_PARAM;
  if (request->pid <= 0) return MEMDBG_ERR_PARAM;
  uint64_t scan_end = 0U;
  if (!scan_bounds_valid(request->start, request->length,
                         sizeof(uint64_t), &scan_end))
    return MEMDBG_ERR_PARAM;

  memset(out, 0, sizeof(*out));

  /* Validate PID is still alive before touching its memory. */
  {
    memdbg_process_list_t plist;
    memdbg_status_t check = memdbg_process_list(&plist);
    if (check == MEMDBG_OK) {
      bool alive = false;
      for (size_t i = 0U; i < plist.count; ++i)
        if (plist.entries[i].pid == request->pid) { alive = true; break; }
      memdbg_process_list_free(&plist);
      if (!alive) return MEMDBG_ERR_NOT_FOUND;
    }
  }

  memdbg_status_t st = process_scan_guard_begin();
  if (st != MEMDBG_OK) return st;

  /* Restrict scan to mapped regions so we don't hit unmapped/guarded pages
   * that trigger data aborts on console. */
  memdbg_map_list_t maps;
  st = scan_process_maps_for_scan(request->pid, &maps);
  if (st != MEMDBG_OK) {
    process_scan_guard_end();
    return st;
  }

  static const size_t kPtrOverlap = sizeof(uint64_t) - 1U;
  unsigned char *buffer = (unsigned char *)malloc(MEMDBG_SCAN_CHUNK + kPtrOverlap);
  if (buffer == NULL) {
    memdbg_process_maps_free(&maps);
    process_scan_guard_end();
    return MEMDBG_ERR_NOMEM;
  }

  scan_builder_t builder;
  memset(&builder, 0, sizeof(builder));
  builder.result = out;
  builder.max_results = request->max_results == 0U ? 1U : (size_t)request->max_results;
  st = scan_builder_prealloc(&builder);
  if (st != MEMDBG_OK) {
    free(buffer);
    memdbg_process_maps_free(&maps);
    process_scan_guard_end();
    return st;
  }

  uint32_t alignment = request->alignment == 0U ? 8U : request->alignment;
  uint64_t start_ns = monotonic_ns();

  for (size_t mi = 0U; mi < maps.count; ++mi) {
    const memdbg_map_entry_t *map = &maps.entries[mi];
    if (map->end <= map->start) continue;
    if ((map->protection & MEMDBG_MAP_PROT_READ) != MEMDBG_MAP_PROT_READ)
      continue;
    if (map->start >= scan_end || map->end <= request->start) continue;

    uint64_t mstart = map->start > request->start ? map->start : request->start;
    uint64_t mend   = map->end < scan_end ? map->end : scan_end;
    if (mend <= mstart) continue;
    scan_metric_inc(&out->regions_scanned);

    size_t carry = 0U;
    uint64_t scanned = 0U;
    uint64_t map_len = mend - mstart;

    while (scanned < map_len) {
      uint64_t remaining = map_len - scanned;
      size_t to_read = scan_read_size(remaining);
      size_t read_len = 0U;

      st = scan_memory_read_resilient(request->pid,
          mstart + scanned, buffer + carry, to_read, out, &read_len);
      if (st != MEMDBG_OK) {
        scanned += scan_fault_skip_size(to_read);
        carry = 0U;
        continue;
      }
      if (read_len == 0U) break;
      out->bytes_scanned += (uint64_t)read_len;

      size_t window = carry + read_len;
      uint64_t base_addr = mstart + scanned - (uint64_t)carry;

      size_t first = first_aligned_offset(base_addr, mstart, mstart, alignment);
      if (first < window) {
        for (size_t i = first;
             i + sizeof(uint64_t) <= window;
             i += alignment) {
          uint64_t addr = base_addr + (uint64_t)i;
          if (addr > mend || sizeof(uint64_t) > mend - addr) break;

          uint64_t candidate;
          memcpy(&candidate, buffer + i, sizeof(candidate));
          if (candidate == request->target_address) {
            memdbg_status_t as = scan_builder_append(&builder, addr);
            if (as != MEMDBG_OK) {
              free(buffer);
              memdbg_process_maps_free(&maps);
              process_scan_guard_end();
              return as;
            }
          }
        }
      }

      carry = window < kPtrOverlap ? window : kPtrOverlap;
      if (carry > 0U)
        memmove(buffer, buffer + window - carry, carry);

      scanned += read_len;
    }
  }

  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;
  free(buffer);
  memdbg_process_maps_free(&maps);
  process_scan_guard_end();
  return MEMDBG_OK;
}

void memdbg_scan_result_free(memdbg_scan_result_t *result) {
  if (result == NULL) return;
  free(result->entries);
  memset(result, 0, sizeof(*result));
}
