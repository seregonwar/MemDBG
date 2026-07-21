/*
 * memDBG - Debugger internal state and helpers.
 * Shared across memdbg_debugger.c, debugger_regs.c, debugger_breakpoints.c.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_DEBUGGER_INTERNAL_H
#define MEMDBG_DEBUGGER_INTERNAL_H

#include "memdbg/debug/debugger.h"
#include "memdbg/pal/pal_memory.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define INT3_OPCODE 0xCCU
#define X86_TRAP_FLAG 0x100U

/* ---- Global state (defined in memdbg_debugger.c) ---- */

typedef struct memdbg_debugger_state {
  int32_t pid;
  bool attached;
  bool stopped;
  int32_t stop_lwp;
  memdbg_breakpoint_t breakpoints[MEMDBG_DEBUGGER_MAX_BREAKPOINTS];
  memdbg_watchpoint_t watchpoints[MEMDBG_DEBUGGER_MAX_WATCHPOINTS];
  memdbg_debug_dbregs_t dbregs;
  bool dbregs_valid;
} memdbg_debugger_state_t;

extern pthread_mutex_t g_dbg_mtx;
extern pthread_once_t g_dbg_once;
extern memdbg_debugger_state_t g_dbg;

/* ---- Locking (memdbg_debugger.c) ---- */

void debugger_lock(void);
void debugger_unlock(void);
void debugger_init_mutex(void);
void debugger_sleep_ms(unsigned int ms);

/* ---- Error conversion (memdbg_debugger.c) ---- */

memdbg_status_t pal_status_from_errno_code(int code);
memdbg_status_t pal_status_from_errno(void);

/* ---- Memory helpers (memdbg_debugger.c) ---- */

memdbg_status_t debugger_memory_read(uint64_t address, void *buffer,
                                     size_t length);
memdbg_status_t debugger_memory_write(uint64_t address, const void *buffer,
                                      size_t length);

/* ---- Condition evaluation (debugger_regs.c) ---- */

int64_t get_reg_value_by_cond_reg(const memdbg_debug_regs_t *regs,
                                  uint32_t cond_reg);
bool evaluate_bp_condition(const memdbg_breakpoint_t *bp,
                           const memdbg_debug_regs_t *regs);

/* ---- Thread enumeration (debugger_regs.c) ---- */

memdbg_status_t get_threads_locked(int32_t *lwps, char (*names)[24],
                                   uint32_t *states,
                                   uint32_t *count, uint32_t max);

/* ---- Breakpoint slot management (debugger_breakpoints.c) ---- */

int find_breakpoint_slot(uint64_t address);
int alloc_breakpoint_slot(void);
int find_watchpoint_slot(uint64_t address);
int alloc_hw_slot(void);

/* ---- Software breakpoints (debugger_breakpoints.c) ---- */

memdbg_status_t install_sw_breakpoint(memdbg_breakpoint_t *bp);
memdbg_status_t uninstall_sw_breakpoint(memdbg_breakpoint_t *bp);

/* ---- Hardware debug registers (debugger_breakpoints.c) ---- */

void build_dr7(uint32_t *dr7_out);
memdbg_status_t apply_dbregs_to_all(void);
memdbg_status_t refresh_dbregs_from_thread(int32_t lwp);
memdbg_status_t step_over_sw_breakpoint_locked(int32_t lwp);
memdbg_status_t sync_hardware_dbregs_locked(void);

#endif /* MEMDBG_DEBUGGER_INTERNAL_H */
