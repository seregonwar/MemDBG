/*
 * memDBG - Scan builder, context, window and range scanner.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scan_internal.h"

memdbg_status_t process_scan_guard_begin(void) {
  return MEMDBG_OK;
}

void process_scan_guard_end(void) {
}

memdbg_status_t scan_process_maps_for_scan(int pid,
                                                  memdbg_map_list_t *maps) {
  return memdbg_process_maps_cached(pid, maps);
}

/* ---- Clock ---- */

uint64_t monotonic_ns(void) {
#if defined(CLOCK_MONOTONIC)
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
#endif
  return 0U;
}

/* ---- Defensive memory reads ---- */

void scan_metric_inc(uint32_t *value) {
  if (value != NULL && *value != UINT32_MAX) (*value)++;
}

size_t scan_read_size(uint64_t remaining, size_t chunk_size) {
  return remaining > (uint64_t)chunk_size
      ? chunk_size
      : (size_t)remaining;
}

size_t scan_fault_skip_size(size_t requested) {
  if (requested == 0U) return 0U;
  return requested < MEMDBG_SCAN_MIN_READ_CHUNK
      ? requested
      : (size_t)MEMDBG_SCAN_MIN_READ_CHUNK;
}

bool scan_bounds_valid(uint64_t start, uint64_t length,
                              uint64_t min_length, uint64_t *end_out) {
  if (length == 0U || length < min_length) return false;
  if (length > MEMDBG_SCAN_MAX_LENGTH) return false;
  if (UINT64_MAX - start < length) return false;
  if (end_out != NULL) *end_out = start + length;
  return true;
}

memdbg_status_t scan_memory_read_resilient(
    int pid, uint64_t address, void *buffer, size_t requested,
    memdbg_scan_result_t *metrics, memdbg_scan_progress_t *progress,
    size_t *read_out) {
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
    if (progress != NULL)
      atomic_fetch_add_explicit(&progress->read_errors, 1U,
                                memory_order_relaxed);
    if (attempt <= MEMDBG_SCAN_MIN_READ_CHUNK) return st;

    size_t next = attempt / 2U;
    if (next < MEMDBG_SCAN_MIN_READ_CHUNK) next = MEMDBG_SCAN_MIN_READ_CHUNK;
    if (next >= attempt) return st;
    attempt = next;
  }

  return MEMDBG_ERR_IO;
}

/* ---- Result builder ---- */

memdbg_status_t scan_builder_append(scan_builder_t *builder, uint64_t address) {
  memdbg_scan_result_t *result = builder->result;
  if (builder->progress != NULL)
    atomic_fetch_add_explicit(&builder->progress->results_found, 1U,
                              memory_order_relaxed);
  if (unlikely(result->count >= builder->max_results)) {
    result->truncated = true;
    return MEMDBG_OK;
  }
  if (unlikely(result->count == builder->capacity)) {
    size_t next_capacity = builder->capacity == 0U ? MEMDBG_SCAN_INITIAL_CAPACITY
                                                   : builder->capacity * 2U;
    if (next_capacity < builder->capacity || next_capacity > builder->max_results)
      next_capacity = builder->max_results;
    if (next_capacity <= result->count) { result->truncated = true; return MEMDBG_OK; }
    memdbg_scan_result_entry_t *next =
        (memdbg_scan_result_entry_t *)realloc(result->entries, next_capacity * sizeof(*result->entries));
  if (unlikely(next == NULL)) return MEMDBG_ERR_NOMEM;
    result->entries = next;
    builder->capacity = next_capacity;
  }
  result->entries[result->count].address = address;
  result->count++;
  return MEMDBG_OK;
}

/* ---- Pre-allocate result buffer to max_results upfront ---- */

memdbg_status_t scan_builder_prealloc(scan_builder_t *builder) {
  if (builder->max_results == 0U) return MEMDBG_ERR_PARAM;
  builder->result->entries = (memdbg_scan_result_entry_t *)malloc(
      builder->max_results * sizeof(memdbg_scan_result_entry_t));
  if (builder->result->entries == NULL) return MEMDBG_ERR_NOMEM;
  builder->capacity = builder->max_results;
  return MEMDBG_OK;
}

/* ---- Alignment ---- */

size_t first_aligned_offset(uint64_t base, uint64_t alignment_base,
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

memdbg_status_t scan_window(scan_context_t *ctx, scan_builder_t *builder,
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

memdbg_status_t scan_range(scan_context_t *ctx, scan_builder_t *builder,
                                  uint64_t range_start, uint64_t range_len,
                                  uint64_t alignment_base, bool skip_read_errors) {
  size_t overlap = ctx->value_len > 1U ? (size_t)ctx->value_len - 1U : 0U;
  uint64_t scanned = 0U;
  size_t carry = 0U;
  uint64_t range_end = 0U;

  if (unlikely(!scan_bounds_valid(range_start, range_len, ctx->value_len, &range_end)))
    return MEMDBG_ERR_PARAM;

  while (scanned < range_len) {
    if (builder->progress != NULL && atomic_load_explicit(
            &builder->progress->cancel_requested, memory_order_relaxed)) {
      builder->result->truncated = true;
      break;
    }
    uint64_t remaining = range_len - scanned;
    size_t to_read = scan_read_size(remaining, ctx->read_chunk);
    size_t read_len = 0U;

    memdbg_status_t st = scan_memory_read_resilient(ctx->pid,
        range_start + scanned, ctx->buffer + carry, to_read,
        builder->result, builder->progress, &read_len);
    if (unlikely(st != MEMDBG_OK)) {
      if (!skip_read_errors) return st;
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

memdbg_status_t scan_context_init(scan_context_t *ctx, int pid,
                                         uint32_t value_type, uint32_t requested_value_len,
                                         uint32_t alignment, const uint8_t *value,
                                         size_t read_chunk,
                                         bool allocate_buffer) {
  if (ctx == NULL || pid <= 0 || value == NULL) return MEMDBG_ERR_PARAM;
  memset(ctx, 0, sizeof(*ctx));
  ctx->pid = pid;
  ctx->value_type = value_type;
  ctx->value_len = expected_value_length(value_type, requested_value_len);
  ctx->alignment = alignment == 0U ? 1U : alignment;
  ctx->read_chunk = read_chunk;
  if (ctx->value_len == 0U || ctx->value_len > MEMDBG_SCAN_VALUE_MAX) return MEMDBG_ERR_PARAM;
  memcpy(ctx->needle, value, ctx->value_len);
  ctx->match = match_fn_for(ctx->value_len);
  ctx->buffer_size = ctx->read_chunk + (size_t)ctx->value_len - 1U;
  if (allocate_buffer) {
    ctx->buffer = (unsigned char *)malloc(ctx->buffer_size);
    if (ctx->buffer == NULL) return MEMDBG_ERR_NOMEM;
  }
  return MEMDBG_OK;
}

void scan_context_fini(scan_context_t *ctx) {
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

