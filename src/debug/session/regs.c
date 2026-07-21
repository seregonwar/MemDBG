/*
 * memDBG - Debugger register and thread operations.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "internal.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/pal/debug.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

// Condition evaluation

int64_t get_reg_value_by_cond_reg(const memdbg_debug_regs_t *regs,
                                         uint32_t cond_reg) {
  switch ((memdbg_bp_cond_reg_t)cond_reg) {
  case MEMDBG_BP_COND_RAX: return regs->r_rax;
  case MEMDBG_BP_COND_RBX: return regs->r_rbx;
  case MEMDBG_BP_COND_RCX: return regs->r_rcx;
  case MEMDBG_BP_COND_RDX: return regs->r_rdx;
  case MEMDBG_BP_COND_RSI: return regs->r_rsi;
  case MEMDBG_BP_COND_RDI: return regs->r_rdi;
  case MEMDBG_BP_COND_RBP: return regs->r_rbp;
  case MEMDBG_BP_COND_RSP: return regs->r_rsp;
  case MEMDBG_BP_COND_R8:  return regs->r_r8;
  case MEMDBG_BP_COND_R9:  return regs->r_r9;
  case MEMDBG_BP_COND_R10: return regs->r_r10;
  case MEMDBG_BP_COND_R11: return regs->r_r11;
  case MEMDBG_BP_COND_R12: return regs->r_r12;
  case MEMDBG_BP_COND_R13: return regs->r_r13;
  case MEMDBG_BP_COND_R14: return regs->r_r14;
  case MEMDBG_BP_COND_R15: return regs->r_r15;
  case MEMDBG_BP_COND_RIP: return regs->r_rip;
  default: return 0;
  }
}

bool evaluate_bp_condition(const memdbg_breakpoint_t *bp,
                                  const memdbg_debug_regs_t *regs) {
  if (bp->cond_reg == MEMDBG_BP_COND_NONE) return true;
  int64_t rv = get_reg_value_by_cond_reg(regs, bp->cond_reg);
  int64_t cv = (int64_t)bp->cond_value;
  switch ((memdbg_bp_cond_op_t)bp->cond_op) {
  case MEMDBG_BP_COND_EQ: return rv == cv;
  case MEMDBG_BP_COND_NE: return rv != cv;
  case MEMDBG_BP_COND_LT: return rv <  cv;
  case MEMDBG_BP_COND_LE: return rv <= cv;
  case MEMDBG_BP_COND_GT: return rv >  cv;
  case MEMDBG_BP_COND_GE: return rv >= cv;
  default: return true;
  }
}

memdbg_status_t get_threads_locked(int32_t *lwps, char (*names)[24],
                                         uint32_t *states,
                                         uint32_t *count, uint32_t max) {
  if (count == NULL || lwps == NULL) return MEMDBG_ERR_PARAM;
  if (!g_dbg.attached) return MEMDBG_ERR_STATE;

  int n = pal_debug_get_thread_list((int)g_dbg.pid, lwps, (int)max);
  bool using_main_lwp_fallback = false;
  if (n < 0) {
    const int thread_list_errno = errno;
    /*
     * Some PS4 firmware/debugger combinations return EIO for
     * PT_GETLWPLIST even though the target is still attached and its main
     * LWP can be inspected.  Do not turn a thread-list refresh into a
     * fatal debugger error in that case: keep the session usable with the
     * process id as its main-LWP fallback.  Other failures still propagate
     * so a vanished target or a permission problem is never hidden.
     */
    if (thread_list_errno != EIO || max == 0U) return pal_status_from_errno();
    lwps[0] = g_dbg.pid;
    n = 1;
    using_main_lwp_fallback = true;
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "debugger: LWP enumeration failed pid=%d errno=%d; "
                     "using main LWP fallback",
                     (int)g_dbg.pid, thread_list_errno);
  }
  *count = (uint32_t)n;

  if (names != NULL) {
    for (uint32_t i = 0; i < *count; ++i) {
      char buf[24] = {0};
      if (using_main_lwp_fallback && i == 0U) {
        (void)snprintf(buf, sizeof(buf), "main (fallback)");
        memcpy(names[i], buf, sizeof(buf));
        continue;
      }
      /* Try the real thread name first; fall back to lwp-NNN if empty. */
      if (pal_debug_get_thread_name((int)g_dbg.pid, lwps[i], buf,
                                    sizeof(buf)) != 0 ||
          buf[0] == '\0') {
        (void)snprintf(buf, sizeof(buf), "lwp-%d", (int)lwps[i]);
      }
      memcpy(names[i], buf, sizeof(buf));
    }
  }

  if (states != NULL) {
    for (uint32_t i = 0; i < *count; ++i) {
      if (using_main_lwp_fallback && i == 0U) {
        states[i] = g_dbg.stopped ? MEMDBG_THREAD_STOPPED
                                  : MEMDBG_THREAD_RUNNING;
        continue;
      }
      int st = (int)MEMDBG_THREAD_UNKNOWN;
      (void)pal_debug_get_thread_state((int)g_dbg.pid, lwps[i], &st);
      states[i] = (uint32_t)st;
    }
  }
  return MEMDBG_OK;
}

memdbg_status_t memdbg_debugger_get_threads(int32_t *lwps, char (*names)[24],
                                            uint32_t *states,
                                            uint32_t *count, uint32_t max) {
  debugger_lock();
  memdbg_status_t st = get_threads_locked(lwps, names, states, count, max);
  debugger_unlock();
  return st;
}

memdbg_status_t get_regs_locked(int32_t lwp,
                                       memdbg_debug_regs_t *regs) {
  if (regs == NULL) return MEMDBG_ERR_PARAM;
  if (!g_dbg.attached) return MEMDBG_ERR_STATE;
  if (pal_debug_get_regs((int)g_dbg.pid, lwp, regs) != 0) {
    return pal_status_from_errno();
  }
  return MEMDBG_OK;
}

memdbg_status_t memdbg_debugger_get_regs(int32_t lwp,
                                         memdbg_debug_regs_t *regs) {
  debugger_lock();
  memdbg_status_t st = get_regs_locked(lwp, regs);
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_set_regs(int32_t lwp,
                                         const memdbg_debug_regs_t *regs) {
  debugger_lock();
  if (regs == NULL) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }
  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_set_regs((int)g_dbg.pid, lwp, regs) != 0) {
    st = pal_status_from_errno();
  }
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_get_dbregs(int32_t lwp,
                                           memdbg_debug_dbregs_t *dbregs) {
  debugger_lock();
  if (dbregs == NULL) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }
  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_get_dbregs((int)g_dbg.pid, lwp, dbregs) != 0) {
    st = pal_status_from_errno();
  }
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_set_dbregs(int32_t lwp,
                                           const memdbg_debug_dbregs_t *dbregs) {
  debugger_lock();
  if (dbregs == NULL) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }
  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_set_dbregs((int)g_dbg.pid, lwp, dbregs) != 0) {
    st = pal_status_from_errno();
  } else {
    g_dbg.dbregs = *dbregs;
    g_dbg.dbregs_valid = true;
  }
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_get_fpregs(int32_t lwp,
                                           memdbg_debug_fpregs_t *fpregs) {
  debugger_lock();
  if (fpregs == NULL) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }
  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_get_fpregs((int)g_dbg.pid, lwp, fpregs) != 0) {
    st = pal_status_from_errno();
  }
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_set_fpregs(
    int32_t lwp, const memdbg_debug_fpregs_t *fpregs) {
  debugger_lock();
  if (fpregs == NULL) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }
  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_set_fpregs((int)g_dbg.pid, lwp, fpregs) != 0) {
    st = pal_status_from_errno();
  }
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_get_fsgsbase(
    int32_t lwp, memdbg_debug_fsgsbase_t *base) {
  debugger_lock();
  if (base == NULL) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }
  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_get_fsgsbase((int)g_dbg.pid, lwp, base) != 0) {
    st = pal_status_from_errno();
  }
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_set_fsgsbase(
    int32_t lwp, const memdbg_debug_fsgsbase_t *base) {
  debugger_lock();
  if (base == NULL) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }
  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_set_fsgsbase((int)g_dbg.pid, lwp, base) != 0) {
    st = pal_status_from_errno();
  }
  debugger_unlock();
  return st;
}

