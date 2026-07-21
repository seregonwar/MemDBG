/*
 * memDBG - PAL: PS5 kernel-direct debug register helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Overrides ptrace-based register access with direct kernel PCB/trapframe
 * reads/writes via kernel_copyout/kernel_copyin
 */

#ifndef MEMDBG_PAL_DEBUG_PS5_H
#define MEMDBG_PAL_DEBUG_PS5_H

#include "memdbg/core/memdbg_protocol.h"
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void kern_thread_cache_flush(void);

intptr_t kern_thread_addr(int pid, int lwpid);

int kern_get_dbregs(int pid, int lwpid, memdbg_debug_dbregs_t *dbregs_out);
int kern_set_dbregs(int pid, int lwpid, const memdbg_debug_dbregs_t *dbregs);

int kern_get_regs(int pid, int lwpid, memdbg_debug_regs_t *regs_out);
int kern_set_regs(int pid, int lwpid, const memdbg_debug_regs_t *regs);

int kern_get_fpregs(int pid, int lwpid, memdbg_debug_fpregs_t *fpregs_out);
int kern_set_fpregs(int pid, int lwpid, const memdbg_debug_fpregs_t *fpregs);

int kern_get_fsgsbase(int pid, int lwpid, memdbg_debug_fsgsbase_t *base_out);
int kern_set_fsgsbase(int pid, int lwpid, const memdbg_debug_fsgsbase_t *base);

int kern_get_thread_list(int pid, int32_t *lwps, int max_count);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PAL_DEBUG_PS5_H */
