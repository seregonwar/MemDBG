/*
 * memDBG - PAL: Cross-platform debugger primitives.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This header declares platform-independent ptrace-style debugger operations.
 */

#ifndef MEMDBG_PAL_DEBUG_H
#define MEMDBG_PAL_DEBUG_H

#include "memdbg/core/memdbg_protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns true if the current platform supports debugger operations. */
bool pal_debug_supported(void);

/* Raw ptrace-style call.  On success returns the ptrace return value (often 0);
 * on error returns -1 and sets errno. */
long pal_debug_ptrace(int op, int pid, void *addr, long data);

/* Attach to a process.  Blocks until the initial SIGTRAP is delivered or the
 * wait times out.  Returns 0 on success, -1 on error. */
int pal_debug_attach(int pid);

/* Detach from a process.  Returns 0 on success, -1 on error. */
int pal_debug_detach(int pid);

/* Wait for a stop event.  If nohang is true, returns immediately. */
int pal_debug_wait(int pid, int *status, bool nohang);

/* Resume the whole process (all LWPs).  Returns 0 on success, -1 on error. */
int pal_debug_continue(int pid);

/* Stop the whole process.  Uses SIGSTOP on the process group. */
int pal_debug_stop(int pid);

/* Single-step the given LWP. */
int pal_debug_single_step(int pid, int32_t lwp);

/* Suspend/resume a single LWP. */
int pal_debug_suspend_thread(int pid, int32_t lwp);
int pal_debug_resume_thread(int pid, int32_t lwp);

/* Thread enumeration.  get_thread_count returns the number of LWPs or -1. */
int pal_debug_get_thread_count(int pid);
int pal_debug_get_thread_list(int pid, int32_t *lwps, int max_count);

/* Register access.  lwp is the kernel thread id (not the pid). */
int pal_debug_get_regs(int pid, int32_t lwp, memdbg_debug_regs_t *regs);
int pal_debug_set_regs(int pid, int32_t lwp, const memdbg_debug_regs_t *regs);

/* Attempt to retrieve the kernel thread name for the given LWP.
 * On platforms that support it (FreeBSD 13+), uses PT_GET_THREAD_NAME.
 * On success, copies the name (up to name_len-1 chars + null) and returns 0.
 * On failure or if unsupported, sets name[0] = '\0' and returns -1.
 * Callers should fall back to a synthetic name like "lwp-NNN". */
int pal_debug_get_thread_name(int pid, int32_t lwp, char *name, size_t name_len);

/* Debug register access (used for hardware breakpoints/watchpoints). */
int pal_debug_get_dbregs(int pid, int32_t lwp, memdbg_debug_dbregs_t *dbregs);
int pal_debug_set_dbregs(int pid, int32_t lwp,
                         const memdbg_debug_dbregs_t *dbregs);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PAL_DEBUG_H */
