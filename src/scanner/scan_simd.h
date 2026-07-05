/*
 * memDBG - SIMD-accelerated scan comparisons.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Provides AVX/SSE-accelerated exact-match value comparisons for the scan
 * engine. Used by the QuickScan engine for fast streaming scans.
 */

#ifndef MEMDBG_SCANNER_SCAN_SIMD_H
#define MEMDBG_SCANNER_SCAN_SIMD_H

#include "memdbg/core/memdbg_protocol.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum SIMD offsets returned per call. Caller provides the buffer. */
#define MEMDBG_SIMD_MAX_OFFSETS 8192U

/* Check whether SIMD-accelerated exact match is available for the given
 * value type and length combination. Returns non-zero if usable.
 *
 * Preconditions: compare_type == 0 (exact), step == value_length, and
 * the needle pointer is non-NULL. */
int memdbg_simd_exact_available(uint32_t value_type, uint32_t value_length);

/* Find all occurrences of `needle` in `haystack` using SIMD instructions.
 *
 * Writes matching offsets (0-based within haystack) into simd_offsets[].
 * haystack_len must be large enough to contain at least one needle.
 *
 * Returns the number of matches found (may be 0). */
size_t memdbg_simd_find_exact(uint32_t value_type,
                              const uint8_t *haystack, size_t haystack_len,
                              const uint8_t *needle, uint32_t value_length,
                              uint32_t *simd_offsets, size_t max_offsets);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SCANNER_SCAN_SIMD_H */
