/*
 * memDBG - Memory debugger payload for jailbroken consoles.
 * Copyright (C) 2026 SeregonWar
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * BM tables + match funcs → scan_match.c
 * Builder/context/window   → scan_builder.c
 * Parallel orchestrator     → scan_parallel.c
 * Shared internals          → memdbg_scan_internal.h
 */

#include "scan_internal.h"

#include <math.h>


/* ---- Map-filter helper (shared by process-wide scans) ---- */

/* ---- Public API: exact scan ---- */

memdbg_status_t memdbg_scan_exact(const memdbg_scan_exact_request_t *request,
                                  memdbg_scan_result_t *out) {
  if (request == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));
  if (request->length == 0U) return MEMDBG_ERR_PARAM;

  scan_context_t ctx;
  memdbg_status_t st = scan_context_init(&ctx, request->pid, request->value_type,
      request->value_length, request->alignment, request->value,
      MEMDBG_SCAN_EXACT_RANGE_CHUNK, true);
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
      request->value_length, request->alignment, request->value,
      MEMDBG_SCAN_CHUNK, false);
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
  size_t buf_size = ctx.read_chunk + (size_t)ctx.value_len - 1U;

  uint64_t start_ns = monotonic_ns();
  st = scan_maps_parallel(scan_range_cb, &ctx,
      request->pid, maps.entries, maps.count,
      max_results, buf_size, (size_t)ctx.value_len,
      prot_mask, request->start, request->end, NULL, out);
  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;

  memdbg_process_maps_free(&maps);
  process_scan_guard_end();
  scan_context_fini(&ctx);
  if (st != MEMDBG_OK) memdbg_scan_result_free(out);
  return st;
}

memdbg_status_t memdbg_scan_process_exact_tracked(
    const memdbg_scan_process_exact_request_t *request,
    memdbg_scan_progress_t *progress, memdbg_scan_result_t *out) {
  if (request == NULL || progress == NULL || out == NULL)
    return MEMDBG_ERR_PARAM;

  scan_context_t ctx;
  memdbg_status_t st = scan_context_init(&ctx, request->pid, request->value_type,
      request->value_length, request->alignment, request->value,
      MEMDBG_SCAN_CHUNK, false);
  if (st != MEMDBG_OK) return st;
  st = process_scan_guard_begin();
  if (st != MEMDBG_OK) { scan_context_fini(&ctx); return st; }

  memdbg_map_list_t maps;
  st = scan_process_maps_for_scan(request->pid, &maps);
  if (st != MEMDBG_OK) {
    process_scan_guard_end();
    scan_context_fini(&ctx);
    return st;
  }

  const size_t max_results = request->max_results == 0U
      ? 1U : (size_t)request->max_results;
  const uint32_t prot_mask = request->protection_mask == 0U
      ? MEMDBG_MAP_PROT_READ : request->protection_mask;
  const size_t buf_size = ctx.read_chunk + (size_t)ctx.value_len - 1U;
  const uint64_t start_ns = monotonic_ns();
  st = scan_maps_parallel(scan_range_cb, &ctx, request->pid, maps.entries,
      maps.count, max_results, buf_size, (size_t)ctx.value_len, prot_mask,
      request->start, request->end, progress, out);
  const uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) out->elapsed_ns = end_ns - start_ns;
  if (atomic_load_explicit(&progress->cancel_requested, memory_order_relaxed)) {
    out->truncated = true;
    out->cancelled = true;
  }

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
    size_t to_read = scan_read_size(remaining, MEMDBG_SCAN_CHUNK);
    size_t read_len = 0U;

    memdbg_status_t st = scan_memory_read_resilient(pid,
        range_start + scanned, buffer + carry, to_read,
        builder->result, builder->progress, &read_len);
    if (st != MEMDBG_OK) {
      scanned += scan_fault_skip_size(to_read);
      carry = 0U;
      continue;
    }
    if (read_len == 0U) break;
    builder->result->bytes_scanned += (uint64_t)read_len;
    if (builder->progress != NULL)
      atomic_fetch_add_explicit(&builder->progress->bytes_done,
                                (uint64_t)read_len, memory_order_relaxed);

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
      prot_mask, request->start, request->end, NULL, out);
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
    size_t to_read = scan_read_size(remaining, MEMDBG_SCAN_CHUNK);
    size_t read_len = 0U;

    memdbg_status_t st = scan_memory_read_resilient(pid,
        start + scanned, buffer + carry, to_read,
        builder->result, builder->progress, &read_len);
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
      size_t to_read = scan_read_size(remaining, MEMDBG_SCAN_CHUNK);
      size_t read_len = 0U;

      st = scan_memory_read_resilient(request->pid,
          mstart + scanned, buffer + carry, to_read, out, NULL, &read_len);
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
