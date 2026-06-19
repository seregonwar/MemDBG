/*
 * memDBG - Payload debugger backend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * High-level debugger API built on top of pal_debug.  Supports ptrace attach,
 * software/hardware breakpoints, hardware watchpoints, thread control and
 * register access.
 */

#ifndef MEMDBG_DEBUG_MEMDBG_DEBUGGER_H
#define MEMDBG_DEBUG_MEMDBG_DEBUGGER_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEMDBG_DEBUGGER_MAX_BREAKPOINTS 16U
#define MEMDBG_DEBUGGER_MAX_WATCHPOINTS 4U
#define MEMDBG_DEBUGGER_MAX_THREADS 256U

typedef enum memdbg_breakpoint_kind {
  MEMDBG_BP_SOFTWARE = 0,
  MEMDBG_BP_HARDWARE = 1
} memdbg_breakpoint_kind_t;

typedef struct memdbg_breakpoint {
  uint64_t address;
  uint32_t kind;
  uint8_t original_byte; /* valid for software breakpoints */
  bool installed;
  bool active;

  /* Condition: break only when pred(reg_value, cond_value) is true.
   * cond_reg = 0 (MEMDBG_BP_COND_NONE) means unconditional. */
  uint32_t cond_reg;
  uint32_t cond_op;
  uint64_t cond_value;
} memdbg_breakpoint_t;

typedef struct memdbg_watchpoint {
  uint64_t address;
  uint32_t length;
  uint32_t type; /* 0=exec, 1=write, 2=read, 3=read-write */
  uint32_t slot; /* 0..3 */
  bool installed;
} memdbg_watchpoint_t;

bool memdbg_debugger_supported(void);

memdbg_status_t memdbg_debugger_attach(int32_t pid);
memdbg_status_t memdbg_debugger_detach(void);

bool memdbg_debugger_is_attached(void);
int32_t memdbg_debugger_attached_pid(void);
bool memdbg_debugger_is_stopped(void);
int32_t memdbg_debugger_get_stop_lwp(void);
bool memdbg_debugger_is_elevated(int32_t pid);

memdbg_status_t memdbg_debugger_stop(void);
memdbg_status_t memdbg_debugger_continue(void);
memdbg_status_t memdbg_debugger_step(int32_t lwp);

memdbg_status_t memdbg_debugger_suspend_thread(int32_t lwp);
memdbg_status_t memdbg_debugger_resume_thread(int32_t lwp);

memdbg_status_t memdbg_debugger_get_threads(int32_t *lwps, char (*names)[24],
                                            uint32_t *states,
                                            uint32_t *count, uint32_t max);

memdbg_status_t memdbg_debugger_get_regs(int32_t lwp,
                                         memdbg_debug_regs_t *regs);
memdbg_status_t memdbg_debugger_set_regs(int32_t lwp,
                                         const memdbg_debug_regs_t *regs);
memdbg_status_t memdbg_debugger_get_dbregs(int32_t lwp,
                                           memdbg_debug_dbregs_t *dbregs);
memdbg_status_t memdbg_debugger_set_dbregs(int32_t lwp,
                                           const memdbg_debug_dbregs_t *dbregs);

memdbg_status_t memdbg_debugger_set_breakpoint(uint64_t address,
                                               uint32_t kind);
memdbg_status_t memdbg_debugger_set_breakpoint_cond(
    uint64_t address, uint32_t kind,
    uint32_t cond_reg, uint32_t cond_op, uint64_t cond_value);
memdbg_status_t memdbg_debugger_clear_breakpoint(uint64_t address);
memdbg_status_t memdbg_debugger_clear_all_breakpoints(uint32_t *cleared);
memdbg_status_t memdbg_debugger_breakpoints_snapshot(
    memdbg_breakpoint_t *out, uint32_t max, uint32_t *count);

memdbg_status_t memdbg_debugger_set_watchpoint(uint64_t address,
                                               uint32_t length,
                                               uint32_t type);
memdbg_status_t memdbg_debugger_clear_watchpoint(uint64_t address);
memdbg_status_t memdbg_debugger_clear_all_watchpoints(uint32_t *cleared);
memdbg_status_t memdbg_debugger_watchpoints_snapshot(
    memdbg_watchpoint_t *out, uint32_t max, uint32_t *count);

/* Consumes any pending wait event and updates the internal stopped flag.
 * Call this before querying state if you are polling. */
memdbg_status_t memdbg_debugger_poll_events(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DEBUG_MEMDBG_DEBUGGER_H */
