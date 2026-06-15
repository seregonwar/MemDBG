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
memdbg_status_t memdbg_process_info(int pid, memdbg_process_info_response_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DEBUG_PROCESS_H */
