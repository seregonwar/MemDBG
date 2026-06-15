/*
 * LZ4 - Fast LZ compression algorithm
 * Header-only minimal implementation for memDBG payload.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This is a minimal subset of the reference LZ4 implementation,
 * adapted for embedded/payload use with no external dependencies.
 */

#ifndef MEMDBG_LZ4_H
#define MEMDBG_LZ4_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LZ4_MAX_INPUT_SIZE 0x7E000000U /* 2 GB - 32 MB */

/* Compress 'src_size' bytes from 'src' into 'dst' (max 'dst_capacity').
   Returns the number of bytes written to dst, or 0 if compression fails
   or would exceed dst_capacity. */
int lz4_compress_default(const char *src, char *dst, int src_size,
                         int dst_capacity);

/* Decompress 'compressed_size' bytes from 'src' into 'dst' (max 'dst_capacity').
   Returns the number of decompressed bytes, or negative on error. */
int lz4_decompress_safe(const char *src, char *dst, int compressed_size,
                        int dst_capacity);

/* Returns the maximum compressed size for input of 'input_size' bytes. */
int lz4_compress_bound(int input_size);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_LZ4_H */
