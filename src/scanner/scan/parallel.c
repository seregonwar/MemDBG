/*
 * memDBG - Parallel worker and map scan orchestrator.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scan_internal.h"

void *parallel_worker_thread(void *arg) {
  parallel_worker_t *w = (parallel_worker_t *)arg;
  unsigned char *buffer;

  memset(&w->result, 0, sizeof(w->result));
  w->read_calls      = 0U;
  w->read_errors     = 0U;
  w->bytes_scanned   = 0U;
  w->regions_scanned = 0U;
  w->status          = MEMDBG_OK;
  if (w->progress != NULL)
    atomic_fetch_add_explicit(&w->progress->workers_active, 1U,
                              memory_order_relaxed);

  /* Allocate per-thread buffer. */
  buffer = (unsigned char *)malloc(w->buf_size);
  if (unlikely(buffer == NULL)) {
    w->status = MEMDBG_ERR_NOMEM;
    if (w->progress != NULL)
      atomic_fetch_sub_explicit(&w->progress->workers_active, 1U,
                                memory_order_relaxed);
    return NULL;
  }

  /* Per-thread result builder — start small and let scan_builder_append
     grow via incremental realloc (avoids worst-case N*max_results pre-alloc). */
  scan_builder_t builder;
  builder.result       = &w->result;
  builder.max_results  = w->max_results;
  builder.capacity     = 0U;  /* first append allocates MEMDBG_SCAN_INITIAL_CAPACITY */
  builder.progress     = w->progress;

  for (size_t i = w->map_start; i < w->map_end; ++i) {
    if (w->progress != NULL && atomic_load_explicit(
            &w->progress->cancel_requested, memory_order_relaxed))
      break;
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
      if (w->progress != NULL && atomic_load_explicit(
              &w->progress->cancel_requested, memory_order_relaxed))
        break;
      cursor += segment_len;
      remaining -= segment_len;
    }
    if (w->status != MEMDBG_OK) break;
    if (w->progress != NULL && atomic_load_explicit(
            &w->progress->cancel_requested, memory_order_relaxed))
      break;
    if (w->progress != NULL)
      atomic_fetch_add_explicit(&w->progress->maps_done, 1U,
                                memory_order_relaxed);
  }

  /* Snapshot final per-thread metrics from the result struct. */
  w->read_calls    = (uint32_t)w->result.read_calls;
  w->read_errors   = w->result.read_errors;
  w->bytes_scanned = w->result.bytes_scanned;

  free(buffer);
  if (w->progress != NULL)
    atomic_fetch_sub_explicit(&w->progress->workers_active, 1U,
                              memory_order_relaxed);
  return NULL;
}

/* ---- Result merge helper ----
 *
 * Copies entries from per-thread result buffers directly into `out`,
 * which is already pre-allocated at max_results.  Sets `out->truncated`
 * if any thread was truncated.  No intermediate allocation. */

memdbg_status_t merge_scan_results(
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

memdbg_status_t scan_maps_parallel(
    parallel_map_scan_fn_t scan_fn, void *ctx,
    int pid, const memdbg_map_entry_t *maps, size_t map_count,
    size_t max_results, size_t buf_size, size_t min_map_len,
    uint32_t prot_mask, uint64_t start_filter, uint64_t end_filter,
    memdbg_scan_progress_t *progress, memdbg_scan_result_t *out) {

  const size_t max_threads = MEMDBG_SCAN_PARALLEL_THREADS;
  size_t num_threads = max_threads < 1U ? 1U : max_threads;

  /* Partition maps by byte budget.  partition_maps_by_bytes handles
     thread-count clamping, empty-slot fill, and returns the actual
     number of used slots via out_used. */
  scan_partition_slot_t *slots = (scan_partition_slot_t *)calloc(
      num_threads, sizeof(scan_partition_slot_t));
  if (unlikely(slots == NULL)) return MEMDBG_ERR_NOMEM;

  size_t actual_workers = 0U;
  memdbg_status_t part_st = partition_maps_by_bytes(
      maps, map_count, prot_mask, start_filter, end_filter,
      min_map_len, num_threads, slots, &actual_workers);
  if (part_st != MEMDBG_OK) {
    free(slots);
    return part_st;
  }
  if (progress != NULL) {
    uint64_t total_bytes = 0U;
    uint32_t total_maps = 0U;
    for (size_t i = 0U; i < map_count; ++i) {
      const memdbg_map_entry_t *map = &maps[i];
      if ((map->protection & prot_mask) != prot_mask || map->end <= map->start)
        continue;
      uint64_t map_start = map->start;
      uint64_t map_end = map->end;
      if (start_filter != 0U && map_start < start_filter) map_start = start_filter;
      if (end_filter != 0U && map_end > end_filter) map_end = end_filter;
      if (map_end <= map_start || map_end - map_start < min_map_len) continue;
      const uint64_t map_bytes = map_end - map_start;
      total_bytes = UINT64_MAX - total_bytes < map_bytes
          ? UINT64_MAX : total_bytes + map_bytes;
      if (total_maps != UINT32_MAX) total_maps++;
    }
    atomic_store_explicit(&progress->bytes_total, total_bytes,
                          memory_order_relaxed);
    atomic_store_explicit(&progress->maps_total, total_maps,
                          memory_order_relaxed);
    atomic_store_explicit(&progress->workers_total, (unsigned)actual_workers,
                          memory_order_relaxed);
  }
  /* Allocate worker structs sized to actual used slots only. */
  parallel_worker_t *workers = NULL;
  if (unlikely(posix_memalign((void **)&workers, 64,
          actual_workers * sizeof(parallel_worker_t)) != 0)) {
    free(slots);
    return MEMDBG_ERR_NOMEM;
  }

  /* Pre-allocate the output buffer at max_results.  Workers get
     their own per-thread preallocated buffers inside the thread. */
  memset(out, 0, sizeof(*out));
  out->entries = (memdbg_scan_result_entry_t *)malloc(
      max_results * sizeof(memdbg_scan_result_entry_t));
  if (unlikely(out->entries == NULL)) {
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

  /* Populate shared fields. */
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
    workers[t].progress     = progress;

  }

  /* Keep partition zero on the caller, so a four-way scan creates only three
     extra threads.  Thread creation failure degrades inline rather than
     failing an otherwise valid scan. */
  for (size_t t = 1U; t < actual_workers; ++t) {
    if (spawn_ok && workers[t].map_start < workers[t].map_end) {
      if (pthread_create(&threads[t], NULL,
                         parallel_worker_thread, &workers[t]) != 0) {
        parallel_worker_thread(&workers[t]);
      } else {
        workers[t].threaded = true;
      }
    } else {
      parallel_worker_thread(&workers[t]);
    }
  }
  parallel_worker_thread(&workers[0]);

  /* Join all spawned threads. */
  for (size_t t = 1U; t < actual_workers; ++t) {
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

