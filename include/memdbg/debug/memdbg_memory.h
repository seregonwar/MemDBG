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

#ifndef MEMDBG_DEBUG_MEMORY_H
#define MEMDBG_DEBUG_MEMORY_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

memdbg_status_t memdbg_memory_read(int pid, uint64_t address, void *buffer,
                                   size_t length, size_t *read_out);
memdbg_status_t memdbg_memory_write(int pid, uint64_t address,
                                    const void *buffer, size_t length,
                                    size_t *written_out);

/* Batch read: up to 64 addresses in one request. Uses the PAL memory
   batch API for platform-optimal batching (single fd on Linux, per-call
   on FreeBSD). Results include per-address status. */
memdbg_status_t memdbg_memory_batch_read(
    int pid, const memdbg_batch_read_item_t *items, uint32_t count,
    memdbg_batch_read_result_entry_t *results, uint8_t *data_out,
    uint32_t data_capacity, uint32_t *data_used);

/* Populate telemetry counters (bytes read/written, call counts). */
void memdbg_memory_telemetry(memdbg_telemetry_response_t *out);

/* Batch write: write up to 64 addresses in one PAL session.
   Uses a single fd on Linux, individual writes on other platforms.
   Results include per-address written count and status. */
memdbg_status_t memdbg_memory_batch_write(
    int pid, const memdbg_batch_write_item_t *items, const uint8_t *data,
    uint32_t count, memdbg_batch_write_result_entry_t *results);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DEBUG_MEMORY_H */
