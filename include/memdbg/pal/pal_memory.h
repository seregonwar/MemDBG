/*
 * memDBG - PAL: Cross-platform memory access.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This header declares the platform-independent memory read/write API.
 * Each target (Linux, FreeBSD/macOS, PS4/Orbis, PS5/Prospero) provides
 * its own implementation behind the same function signatures.
 */

#ifndef MEMDBG_PAL_MEMORY_H
#define MEMDBG_PAL_MEMORY_H

#include "memdbg/core/memdbg.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Read `length` bytes from `address` in process `pid` into `buffer`.
   On success, sets `*read_out` to the number of bytes actually read.
   Returns MEMDBG_OK or an error code. */
memdbg_status_t pal_memory_read(int pid, uint64_t address, void *buffer,
                                size_t length, size_t *read_out);

/* Write `length` bytes from `buffer` to `address` in process `pid`.
   On success, sets `*written_out` to the number of bytes actually written. */
memdbg_status_t pal_memory_write(int pid, uint64_t address,
                                 const void *buffer, size_t length,
                                 size_t *written_out);

/* Maximum number of items in a single batch read request. */
#define PAL_MEMORY_BATCH_MAX 64U

/* Opaque handle for batch read operations (platform-specific).
   Created by pal_memory_batch_begin, consumed by pal_memory_batch_item,
   destroyed by pal_memory_batch_end. */
typedef struct pal_memory_batch pal_memory_batch_t;

/* Begin a batch read session for `pid`.  Returns NULL on error.
   The returned handle must be passed to pal_memory_batch_item for each
   address, then destroyed with pal_memory_batch_end. */
pal_memory_batch_t *pal_memory_batch_begin(int pid);

/* Read `length` bytes from `address` into `buffer`.
   Returns the number of bytes actually read (0 on error/EOF). */
size_t pal_memory_batch_item(pal_memory_batch_t *batch, uint64_t address,
                             void *buffer, size_t length);

/* End the batch session and free all resources. */
void pal_memory_batch_end(pal_memory_batch_t *batch);

/* ---- Batch write ---- */

typedef struct pal_memory_batch_write pal_memory_batch_write_t;

/* Begin a batch write session for `pid`. Returns NULL on error. */
pal_memory_batch_write_t *pal_memory_batch_write_begin(int pid);

/* Write `length` bytes from `buffer` to `address`.
   Returns the number of bytes actually written (0 on error). */
size_t pal_memory_batch_write_item(pal_memory_batch_write_t *batch,
                                   uint64_t address, const void *buffer,
                                   size_t length);

/* End the batch write session and free all resources. */
void pal_memory_batch_write_end(pal_memory_batch_write_t *batch);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PAL_MEMORY_H */
