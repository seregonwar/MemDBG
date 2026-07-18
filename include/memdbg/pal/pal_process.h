/*
 * memDBG - PAL: Cross-platform process listing, maps, and info.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Platform dispatch:
 *   __ORBIS__    → PS4  (sceDbg*)
 *   __PROSPERO__ → PS5  (sceDbg* Prospero)
 *   __linux__    → Host (/proc)
 *   __APPLE__    → Host (sysctl KERN_PROC_ALL)
 *   __FreeBSD__  → Host (sysctl KERN_PROC_PROC)
 *   default      → MEMDBG_ERR_UNSUPPORTED
 */

#ifndef MEMDBG_PAL_PROCESS_H
#define MEMDBG_PAL_PROCESS_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Process list ---- */

typedef struct pal_process_entry { int pid; int ppid; char name[48]; } pal_process_entry_t;

typedef struct pal_process_list {
  pal_process_entry_t *entries;
  size_t               count;
  size_t               capacity;
} pal_process_list_t;

memdbg_status_t pal_process_list(pal_process_list_t *out);
void            pal_process_list_free(pal_process_list_t *list);

/* ---- Memory maps ---- */

typedef struct pal_map_entry {
  uint64_t start, end;
  uint32_t protection, flags;
  char     name[64];
} pal_map_entry_t;

typedef struct pal_map_list {
  pal_map_entry_t *entries;
  size_t           count;
  size_t           capacity;
} pal_map_list_t;

const char *pal_map_type_name(uint32_t type);
uint32_t pal_map_pack_flags(uint32_t native_flags, uint32_t type);
void pal_map_format_name(char *out, size_t out_size, const char *native_name,
                         uint32_t type);
memdbg_status_t pal_process_maps(int pid, pal_map_list_t *out);
void            pal_process_maps_free(pal_map_list_t *list);

/* ---- Executable path ---- */
memdbg_status_t pal_process_path(int pid, char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PAL_PROCESS_H */
