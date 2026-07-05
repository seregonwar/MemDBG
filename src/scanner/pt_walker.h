/*
 * memDBG - Page-table walker: DMAP discovery, PT enumeration, direct physical access.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_SCANNER_PT_WALKER_H
#define MEMDBG_SCANNER_PT_WALKER_H

#include "memdbg/core/memdbg_protocol.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- DMAP discovery ------------------------------------------------------
 * On PS5/FreeBSD, the kernel identity-maps physical memory at a base called
 * DMAP (direct map). This module discovers that base by walking the payload's
 * own page tables and matching a known value at a known virtual address
 * against its physical counterpart.
 *
 * Once discovered, DMAP enables:
 *  - Direct physical memory access (ptw_read/ptw_write)
 *  - Full page-table enumeration for augmented VM maps
 *  - PTE resolution for the alias engine
 */

/* Try to discover the DMAP base for the current process. Returns 0 on success.
 * Populates dmap_base and pmap_offset within the vmspace structure. */
int ptw_discover(uint64_t *dmap_base_out, uint64_t *pmap_offset_out);

/* Query whether DMAP has been successfully discovered. */
int ptw_is_available(void);

/* Return the cached DMAP base, or 0 if not yet discovered. */
uint64_t ptw_dmap_base(void);

/* ---- Physical address resolution ---- */

/* Resolve a single VA to its physical address, page size, and leaf PTE.
 * Returns 0 on success. pid uses kernel process handle (kernel_get_proc). */
int ptw_probe(uint32_t pid, uint64_t va,
              uint64_t *phys_out, int *level_out,
              uint64_t *pagesize_out, uint64_t *pte_out);

/* Resolve a 2MB-aligned span. Returns whether it's a huge page (1GB or 2MB),
 * the physical base of the span, and the leaf PT page kernel address
 * (for 4K-paged spans so the caller can bulk-read all 512 entries).
 * pid uses kernel process handle. */
int ptw_span_resolve(uint32_t pid, uint64_t span_2m, int *is_huge,
                     uint64_t *phys_base, uint64_t *leaf_pt_kaddr,
                     uint64_t *pte_out);

/* Get the kernel virtual address of the leaf PTE for a given VA.
 * Returns 0 for a 4K leaf. Returns 2 if an upper level is not present,
 * 3 if a huge page (no 4K leaf). */
int ptw_leaf_addr(uint32_t pid, uint64_t va,
                  uint64_t *pte_kaddr_out, uint64_t *pte_val_out,
                  int *level_out);

/* ---- Direct physical access (via DMAP) ---- */

/* Read `length` bytes from VA `addr` in process `pid` via direct DMAP access.
 * Much faster than mdbg_copyout for large reads.
 * Returns 0 on success. pid uses kernel process handle. */
int ptw_read(uint32_t pid, uint64_t addr, uint64_t length, void *dst);

/* Write `length` bytes to VA `addr` in process `pid` via DMAP.
 * Returns 0 on success. pid uses kernel process handle. */
int ptw_write(uint32_t pid, uint64_t addr, uint64_t length, const void *src);

/* ---- Augmented VM maps ---- */

/* Walk the target's full page table and merge discovered entries with the
 * standard vm_map entries. This reveals hidden/auxiliary regions that the
 * kernel's vm_map API does not report (e.g., pages mapped outside vm_map's
 * tracking). The merged result includes both sets.
 *
 * Returns 0 on success. *out_maps and *out_count point to malloc'd storage
 * that the caller must free. Uses proc_vm_map_entry format. */
int ptw_augment_maps(uint32_t pid,
                     memdbg_map_entry_t *vmaps, int vmap_count,
                     memdbg_map_entry_t **out_maps, int *out_count);

/* ---- Auxiliary region cache ---- */

/* Check whether an address range falls entirely within auxiliary regions
 * discovered by ptw_augment_maps. Returns non-zero if yes. */
int ptw_aux_contains(uint32_t pid, uint64_t addr, uint64_t len);

/* ---- Flush cached state ---- */

void ptw_flush(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SCANNER_PT_WALKER_H */
