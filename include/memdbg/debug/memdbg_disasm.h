/*
 * memDBG - x86-64 disassembler and cross-reference engine.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Server-side disassembly using Zydis.  Provides per-instruction metadata,
 * RIP-relative targets, memory operand breakdown, and a cross-reference
 * scanner that finds all pointers to a given address.
 */

#ifndef MEMDBG_DEBUG_MEMDBG_DISASM_H
#define MEMDBG_DEBUG_MEMDBG_DISASM_H

#include "memdbg/core/memdbg_protocol.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Disassembly ---- */

int memdbg_disasm_multiple(int fd, const uint8_t *body, uint32_t body_len);

/* ---- Cross-reference ---- */

int memdbg_xrefs_multiple(int fd, const uint8_t *body, uint32_t body_len);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DEBUG_MEMDBG_DISASM_H */
