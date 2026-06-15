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

#ifndef MEMDBG_DEBUG_PROCESS_H
#define MEMDBG_DEBUG_PROCESS_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct memdbg_process_list {
  memdbg_process_entry_t *entries;
  size_t count;
} memdbg_process_list_t;

typedef struct memdbg_map_list {
  memdbg_map_entry_t *entries;
  size_t count;
} memdbg_map_list_t;

memdbg_status_t memdbg_process_list(memdbg_process_list_t *out);
void memdbg_process_list_free(memdbg_process_list_t *list);

memdbg_status_t memdbg_process_maps(int pid, memdbg_map_list_t *out);
void memdbg_process_maps_free(memdbg_map_list_t *list);

/* Cached variant — returns cached maps if still fresh (5s TTL), avoids
   expensive sysctl/proc reads on every scan refine.  Thread-safe. */
memdbg_status_t memdbg_process_maps_cached(int pid, memdbg_map_list_t *out);

/* Flush a single PID from the cache, or all entries if pid <= 0. */
void memdbg_process_maps_cache_flush(int pid);

memdbg_status_t memdbg_process_info(int pid, memdbg_process_info_response_t *out);

/* Cache statistics for telemetry. */
void memdbg_process_cache_stats(uint32_t *hits, uint32_t *misses);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DEBUG_PROCESS_H */
