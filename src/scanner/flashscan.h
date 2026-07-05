/*
 * memDBG - FlashScan engine: server-resident scanning with snapshots.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * FlashScan keeps scan results on the server side (in-memory or on disk),
 * enabling fast rescans without re-reading the target's memory. Supports:
 *
 *  - Server-resident survivor lists (per-connection mmap buffers)
 *  - Unknown-initial-value snapshots (full value capture on first scan)
 *  - Disjoint multi-segment scans within one session
 *  - First-scan and previous-scan value retention for 3-value records
 *  - Snapshot-to-list materialization for small survivor sets
 *  - Server-side parallel compare via multiple worker threads
 *  - Region classification with throughput measurement
 *  - Configurable RAM threshold with spill-to-file
 */

#ifndef MEMDBG_SCANNER_FLASHSCAN_H
#define MEMDBG_SCANNER_FLASHSCAN_H

#include "memdbg/core/memdbg_protocol.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum concurrent sessions (one per client slot). */
#define FLASHSCAN_MAX_SESSIONS 12U

/* ---- Initialisation and cleanup ---- */

void flashscan_init(void);

/* Remove orphaned spill files from previous runs. */
void flashscan_cleanup_orphans(void);

/* Free all resources for a given client slot. */
void flashscan_free_slot(unsigned int slot);

/* ---- Capabilities ---- */

int flashscan_handle_caps(int fd);

/* ---- Configuration ---- */

int flashscan_handle_config(int fd, const memdbg_quickscan_config_request_t *req,
                            const uint8_t *extra, uint32_t path_len);

/* ---- Region classification ---- */

int flashscan_handle_regions(int fd, const memdbg_quickscan_regions_request_t *req);

/* ---- Start (streaming, resident, or snapshot) ---- */

int flashscan_handle_start(int fd,
                           const memdbg_quickscan_start_request_t *req,
                           const uint8_t *compare_data, const uint8_t *mask,
                           unsigned int client_slot);

/* ---- Narrow / rescan ---- */

int flashscan_handle_count(int fd,
                           const memdbg_quickscan_count_request_t *req,
                           const uint8_t *compare_data, const uint8_t *mask,
                           unsigned int client_slot);

/* ---- Fetch survivors ---- */

int flashscan_handle_fetch(int fd,
                           const memdbg_quickscan_fetch_request_t *req,
                           unsigned int client_slot);

/* ---- End session ---- */

int flashscan_handle_end(int fd, unsigned int client_slot);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SCANNER_FLASHSCAN_H */
