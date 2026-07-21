/*
 * memDBG - Scanner internal state and helpers.
 * Shared across memdbg_scan.c, scan_match.c, scan_builder.c, scan_parallel.c.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_SCAN_INTERNAL_H
#define MEMDBG_SCAN_INTERNAL_H

#include "memdbg/scanner/scan.h"

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
#define MEMDBG_SCAN_CHUNK (4U * 1024U * 1024U)
#define MEMDBG_SCAN_EXACT_RANGE_CHUNK (8U * 1024U * 1024U)
#define MEMDBG_SCAN_PARALLEL_THREADS 4U
#else
#define MEMDBG_SCAN_CHUNK MEMDBG_PROTOCOL_MAX_READ
#define MEMDBG_SCAN_EXACT_RANGE_CHUNK MEMDBG_PROTOCOL_MAX_READ
#define MEMDBG_SCAN_PARALLEL_THREADS 4U
#endif

#define MEMDBG_SCAN_MIN_READ_CHUNK 4096U
#define MEMDBG_SCAN_MAX_LENGTH (32ULL * 1024ULL * 1024ULL * 1024ULL)
#define MEMDBG_SCAN_INITIAL_CAPACITY 256U
#define MEMDBG_MAP_PROT_READ 1U

/* ---- Boyer-Moore ---- */

#define BM_ALPHABET_SIZE 256U
#define BM_GS_MIN_LENGTH 4U

typedef struct {
  size_t skip[BM_ALPHABET_SIZE];
  size_t *gs_shift;
} bm_table_t;

void bm_build_table(const unsigned char *pattern, size_t pat_len,
                    const unsigned char *mask, bm_table_t *table);
void bm_free_table(bm_table_t *table);

/* ---- Match function type ---- */

typedef bool (*scan_match_fn_t)(const unsigned char *candidate,
                                const unsigned char *needle, size_t len);
scan_match_fn_t match_fn_for(uint32_t value_len);

/* ---- Scan builder ---- */

typedef struct scan_builder {
  memdbg_scan_result_t *result;
  size_t capacity;
  size_t max_results;
  memdbg_scan_progress_t *progress;
} scan_builder_t;

typedef struct scan_context {
  int pid;
  uint32_t value_type;
  uint32_t value_len;
  uint32_t alignment;
  unsigned char needle[MEMDBG_SCAN_VALUE_MAX];
  unsigned char *buffer;
  size_t buffer_size;
  size_t read_chunk;
  scan_match_fn_t match;
} scan_context_t;

memdbg_status_t scan_builder_append(scan_builder_t *builder, uint64_t address);
memdbg_status_t scan_builder_prealloc(scan_builder_t *builder);
memdbg_status_t scan_context_init(scan_context_t *ctx, int pid,
                                  uint32_t value_type, uint32_t requested_value_len,
                                  uint32_t alignment, const uint8_t *value,
                                  size_t read_chunk, bool allocate_buffer);
void scan_context_fini(scan_context_t *ctx);

/* ---- Scanning primitives ---- */

uint32_t expected_value_length(uint32_t value_type, uint32_t requested_length);
memdbg_status_t scan_memory_read_resilient(
    int pid, uint64_t address, void *buffer, size_t requested,
    memdbg_scan_result_t *metrics, memdbg_scan_progress_t *progress,
    size_t *read_out);
memdbg_status_t scan_window(scan_context_t *ctx, scan_builder_t *builder,
                            size_t window, uint64_t base_addr,
                            uint64_t alignment_base, uint64_t range_start,
                            uint64_t range_end);
memdbg_status_t scan_range(scan_context_t *ctx, scan_builder_t *builder,
                           uint64_t range_start, uint64_t range_len,
                           uint64_t alignment_base, bool skip_read_errors);

/* ---- Guards / process maps ---- */

memdbg_status_t process_scan_guard_begin(void);
void process_scan_guard_end(void);
memdbg_status_t scan_process_maps_for_scan(int pid, memdbg_map_list_t *maps);

/* ---- Metrics ---- */

uint64_t monotonic_ns(void);
void scan_metric_inc(uint32_t *value);
size_t scan_read_size(uint64_t remaining, size_t chunk_size);
size_t scan_fault_skip_size(size_t requested);
bool scan_bounds_valid(uint64_t start, uint64_t length, uint64_t min_length,
                       uint64_t *end_out);
size_t first_aligned_offset(uint64_t base, uint64_t alignment_base,
                            uint64_t range_start, uint32_t alignment);

/* ---- Parallel scan ---- */

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
  size_t                map_start;
  size_t                map_end;
  uint32_t              prot_mask;
  uint64_t              start_filter;
  uint64_t              end_filter;
  size_t                min_map_len;
  memdbg_scan_result_t  result;
  uint32_t              read_calls;
  uint32_t              read_errors;
  uint64_t              bytes_scanned;
  uint32_t              regions_scanned;
  memdbg_status_t       status;
  bool                  threaded;
  memdbg_scan_progress_t *progress;
} parallel_worker_t;

memdbg_status_t merge_scan_results(
    parallel_worker_t *workers, size_t num_workers,
    memdbg_scan_result_t *out, size_t max_results);
memdbg_status_t scan_maps_parallel(
    parallel_map_scan_fn_t scan_fn, void *ctx,
    int pid, const memdbg_map_entry_t *maps, size_t map_count,
    size_t max_results, size_t buf_size, size_t min_map_len,
    uint32_t prot_mask, uint64_t start_filter, uint64_t end_filter,
    memdbg_scan_progress_t *progress, memdbg_scan_result_t *out);

#endif /* MEMDBG_SCAN_INTERNAL_H */
