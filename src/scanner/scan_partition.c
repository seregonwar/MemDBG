/*
 * memDBG - Size-weighted map partitioner for parallel scanning.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scan_partition.h"

#include <stdlib.h>
#include <string.h>

memdbg_status_t partition_maps_by_bytes(
    const memdbg_map_entry_t *maps, size_t map_count,
    uint32_t prot_mask, uint64_t start_filter, uint64_t end_filter,
    size_t min_map_len, size_t num_threads,
    scan_partition_slot_t *slots,
    size_t *out_used)
{
  size_t effective_maps = 0U;
  size_t *eff_indices;
  uint64_t *eff_bytes;
  uint64_t total_bytes;
  size_t ei;
  uint64_t bytes_per_thread;
  size_t t;
  uint64_t t_bytes;
  size_t u;

  if (maps == NULL || slots == NULL || num_threads < 1U)
    return MEMDBG_ERR_PARAM;

  memset(slots, 0, num_threads * sizeof(*slots));

  for (size_t i = 0U; i < map_count; ++i) {
    const memdbg_map_entry_t *map = &maps[i];
    if ((map->protection & prot_mask) != prot_mask || map->end <= map->start)
      continue;
    uint64_t ms = map->start, me = map->end;
    if (start_filter != 0U && ms < start_filter) ms = start_filter;
    if (end_filter   != 0U && me > end_filter)   me = end_filter;
    if (me <= ms) continue;
    if ((uint64_t)(me - ms) < (uint64_t)min_map_len) continue;
    effective_maps++;
  }

  if (num_threads <= 1U || effective_maps < 4U) {
    slots[0].map_start = 0U;
    slots[0].map_end   = map_count;
    for (u = 1U; u < num_threads; ++u) {
      slots[u].map_start = map_count;
      slots[u].map_end   = map_count;
    }
    if (out_used != NULL) *out_used = 1U;
    return MEMDBG_OK;
  }

  if (num_threads > effective_maps / 2U)
    num_threads = effective_maps / 2U;
  if (num_threads < 1U) num_threads = 1U;

  eff_indices = (size_t *)malloc(effective_maps * sizeof(size_t));
  eff_bytes   = (uint64_t *)malloc(effective_maps * sizeof(uint64_t));
  if (eff_indices == NULL || eff_bytes == NULL) {
    free(eff_indices);
    free(eff_bytes);
    return MEMDBG_ERR_NOMEM;
  }

  ei = 0U;
  total_bytes = 0U;
  for (size_t i = 0U; i < map_count; ++i) {
    const memdbg_map_entry_t *map = &maps[i];
    if ((map->protection & prot_mask) != prot_mask || map->end <= map->start)
      continue;
    uint64_t ms = map->start, me = map->end;
    if (start_filter != 0U && ms < start_filter) ms = start_filter;
    if (end_filter   != 0U && me > end_filter)   me = end_filter;
    if (me <= ms) continue;
    uint64_t mbytes = me - ms;
    if (mbytes < (uint64_t)min_map_len) continue;
    eff_indices[ei] = i;
    eff_bytes[ei]   = mbytes;
    total_bytes = UINT64_MAX - total_bytes < mbytes
        ? UINT64_MAX
        : total_bytes + mbytes;
    ++ei;
  }

  bytes_per_thread = total_bytes / (uint64_t)num_threads;
  if (bytes_per_thread == 0U) bytes_per_thread = 1U;

  t = 0U;
  t_bytes = 0U;
  slots[0].map_start = eff_indices[0];

  for (size_t i = 0U; i < effective_maps; ++i) {
    if (t + 1U < num_threads &&
        t_bytes + eff_bytes[i] > bytes_per_thread && t_bytes > 0U) {
      slots[t].map_end = eff_indices[i];
      ++t;
      slots[t].map_start = eff_indices[i];
      t_bytes = 0U;
    }
    t_bytes += eff_bytes[i];
  }
  slots[t].map_end = map_count;

  for (u = t + 1U; u < num_threads; ++u) {
    slots[u].map_start = map_count;
    slots[u].map_end   = map_count;
  }

  free(eff_bytes);
  free(eff_indices);
  if (out_used != NULL) *out_used = t + 1U;
  return MEMDBG_OK;
}
