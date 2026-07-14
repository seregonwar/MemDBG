/*
 * MemDBG - SPRX injector (load shared-library ELF into a target process and
 *          invoke its initialization function via remote procedure call).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef MEMDBG_SPRX_INJECTOR_H
#define MEMDBG_SPRX_INJECTOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Inject an SPRX (shared-library ELF) from `path` into process `target_pid`.
 * The ELF is loaded into the target's address space, relocations are applied,
 * and the entry-point (e_entry) is invoked in the target context.
 *
 * Returns 0 on success, negative on error:
 *   -1  file read / ELF parse error
 *   -2  ELF load failed
 *   -3  remote call (init) failed
 *   -4  target process not found
 *
 * On the host platform this is a no-op stub that returns 0. */
int sprx_inject_file(const char *path, int target_pid);

/* Extended variant: also returns the entry address and load base via
 * out-parameters (set to 0 on failure).  Used by the protocol handler
 * so the frontend can see where the SPRX landed. */
int sprx_inject_file_ex(const char *path, int target_pid,
                         uint64_t *entry_out, uint64_t *base_out);

/* Find the first PID whose process name contains `partial_name` (case-insensitive).
 * Returns positive PID on success, 0 if not found, negative on error.
 * On the host platform returns 0. */
int sprx_find_pid_by_name(const char *partial_name);

/* Inject MemDBG's shellui SPRX into SceShellUI automatically.
 * Called once during daemon startup on PS5.
 * Returns 0 on success, negative on error. */
int sprx_inject_auto(void);

/* Low-level: execute a remote function call in a target process using the
 * debugger (ptrace-based).  The function at `addr` is called with up to
 * 6 arguments (x86_64 calling convention: RDI, RSI, RDX, RCX, R8, R9).
 * The target thread is stopped, registers are saved, the call is set up
 * with an INT3 trampoline return, continued, and restored when the INT3
 * is hit (or after a 5-second timeout).
 *
 * Returns 0 on success (rax == 0), negative on error.
 *
 * This is the core primitive used by sprx_inject_file for calling the
 * SPRX entry point and also usable directly by callers that need to
 * invoke arbitrary functions in a target process. */
int sprx_remote_call(int pid, uint64_t addr, int argc, const uint64_t *argv);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SPRX_INJECTOR_H */
