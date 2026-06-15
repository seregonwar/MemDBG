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

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DEBUG_MEMORY_H */
