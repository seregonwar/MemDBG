/*
 * memDBG - Size-weighted map partitioner for parallel scanning.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from scan_maps_parallel() so the partitioning algorithm can
 * be unit-tested independently of the full scan pipeline.
 */

#ifndef MEMDBG_SCANNER_SCAN_PARTITION_H
#define MEMDBG_SCANNER_SCAN_PARTITION_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One slot in the partition output — maps [map_start, map_end) are
   assigned to a single thread. */
typedef struct {
  size_t map_start;
  size_t map_end;
} scan_partition_slot_t;

/* Partition `maps` across `num_threads` by byte budget rather than by
 * map count.  Each thread receives a contiguous slice of the maps array
 * whose total byte size is ~= total_bytes / num_threads.
 *
 * The caller provides `slots` (capacity >= num_threads).  On success
 * each slot is populated; empty slots get map_start = map_end = map_count.
 *
 * `out_used` (optional) receives the number of slots that actually contain
 * maps.  Callers can use this to size worker pools.  Pass NULL to ignore.
 *
 * Returns MEMDBG_OK on success, MEMDBG_ERR_NOMEM if allocation fails. */
memdbg_status_t partition_maps_by_bytes(
    const memdbg_map_entry_t *maps, size_t map_count,
    uint32_t prot_mask, uint64_t start_filter, uint64_t end_filter,
    size_t min_map_len, size_t num_threads,
    scan_partition_slot_t *slots,
    size_t *out_used);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SCANNER_SCAN_PARTITION_H */
