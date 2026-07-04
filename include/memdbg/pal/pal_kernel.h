/*
 * memDBG - PAL: kernel memory primitives.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_PAL_KERNEL_H
#define MEMDBG_PAL_KERNEL_H

#include "memdbg/core/memdbg.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool pal_kernel_supported(void);
memdbg_status_t pal_kernel_base(uint64_t *text_base, uint64_t *data_base);
memdbg_status_t pal_kernel_read(uint64_t address, void *buffer, size_t length);
memdbg_status_t pal_kernel_write(uint64_t address, const void *buffer,
                                 size_t length);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PAL_KERNEL_H */
