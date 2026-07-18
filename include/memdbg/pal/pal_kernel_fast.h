/*
 * memDBG - Fast PS5 kernel read/write primitive and process cache.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef MEMDBG_PAL_KERNEL_FAST_H
#define MEMDBG_PAL_KERNEL_FAST_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int memdbg_kernel_fast_available(void);
int32_t memdbg_kernel_copyin_fast(const void *source, intptr_t destination,
                                  size_t length);
int32_t memdbg_kernel_copyout_fast(intptr_t source, void *destination,
                                   size_t length);
intptr_t memdbg_kernel_get_proc_fast(pid_t pid);
void memdbg_kernel_proc_cache_flush(void);
void memdbg_kernel_proc_cache_invalidate(pid_t pid);

/* Coordinate SDK helpers which use the same jailbreak rwpipe/rwpair. */
int memdbg_kernel_external_begin(void);
void memdbg_kernel_external_end(void);

#ifdef __cplusplus
}
#endif

#endif
