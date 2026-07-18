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

#ifndef MEMDBG_SCANNER_SCAN_H
#define MEMDBG_SCANNER_SCAN_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct memdbg_scan_result {
  memdbg_scan_result_entry_t *entries;
  size_t count;
  bool truncated;
  bool cancelled;
  uint64_t bytes_scanned;
  uint64_t elapsed_ns;
  uint32_t read_calls;
  uint32_t regions_scanned;
  uint32_t read_errors;
} memdbg_scan_result_t;

/* Shared counters for a tracked process scan. Workers only perform relaxed
 * atomic updates; a separate protocol connection may query/cancel the job. */
typedef struct memdbg_scan_progress {
  atomic_uint_fast64_t bytes_done;
  atomic_uint_fast64_t bytes_total;
  atomic_uint_fast64_t results_found;
  atomic_uint maps_done;
  atomic_uint maps_total;
  atomic_uint workers_active;
  atomic_uint workers_total;
  atomic_uint read_errors;
  atomic_bool cancel_requested;
} memdbg_scan_progress_t;

memdbg_status_t memdbg_scan_exact(const memdbg_scan_exact_request_t *request,
                                  memdbg_scan_result_t *out);
memdbg_status_t
memdbg_scan_process_exact(const memdbg_scan_process_exact_request_t *request,
                          memdbg_scan_result_t *out);
memdbg_status_t memdbg_scan_process_exact_tracked(
    const memdbg_scan_process_exact_request_t *request,
    memdbg_scan_progress_t *progress, memdbg_scan_result_t *out);
memdbg_status_t
memdbg_scan_aob(const memdbg_scan_aob_request_t *request,
                const uint8_t *pattern, const uint8_t *mask,
                memdbg_scan_result_t *out);
memdbg_status_t
memdbg_scan_process_aob(const memdbg_scan_process_aob_request_t *request,
                        const uint8_t *pattern, const uint8_t *mask,
                        memdbg_scan_result_t *out);
memdbg_status_t
memdbg_scan_pointer(const memdbg_scan_pointer_request_t *request,
                    memdbg_scan_result_t *out);
memdbg_status_t
memdbg_scan_unknown(const memdbg_scan_unknown_request_t *request,
                    memdbg_scan_result_t *out);
void memdbg_scan_result_free(memdbg_scan_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SCANNER_SCAN_H */
