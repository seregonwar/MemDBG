/*
 * memDBG - x86-64 assembler (Keystone wrapper).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Server-side assembly of x86-64 instructions using the Keystone engine.
 * Clients send assembly source text and receive encoded machine code.
 */

#ifndef MEMDBG_DEBUG_MEMDBG_ASSEMBLER_H
#define MEMDBG_DEBUG_MEMDBG_ASSEMBLER_H

#include "memdbg/core/memdbg_protocol.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int memdbg_asm_encode(int fd, const uint8_t *body, uint32_t body_len);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DEBUG_MEMDBG_ASSEMBLER_H */
