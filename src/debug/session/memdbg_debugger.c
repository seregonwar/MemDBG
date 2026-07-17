/*
 * memDBG - Payload debugger backend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/debug/memdbg_debugger.h"

#include "memdbg/core/memdbg_log.h"
#include "memdbg/pal/pal_debug.h"
#include "memdbg/pal/pal_memory.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>

#define INT3_OPCODE 0xCCU
#define X86_TRAP_FLAG 0x100U

static pthread_mutex_t g_dbg_mtx;
static pthread_once_t g_dbg_once = PTHREAD_ONCE_INIT;

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

static memdbg_debugger_state_t g_dbg = {0};

/* Forward declarations for static helpers used before their definitions. */
static void debugger_lock(void);
static void debugger_unlock(void);
static void debugger_init_mutex(void);
static memdbg_status_t get_threads_locked(int32_t *lwps, char (*names)[24],
                                         uint32_t *states,
                                         uint32_t *count, uint32_t max);

bool memdbg_debugger_supported(void) { return pal_debug_supported(); }

bool memdbg_debugger_is_elevated(int32_t pid) {
#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
  extern int memdbg_is_privileged(void);
  (void)pid;
  return memdbg_is_privileged();
#else
  (void)pid;
  return false;
#endif
}

// Internal helpers

static memdbg_status_t pal_status_from_errno_code(int code) {
  switch (code) {
  case EACCES:
  case EPERM:
    return MEMDBG_ERR_PERMISSION;
  case ESRCH:
  case ENOENT:
    return MEMDBG_ERR_NOT_FOUND;
  case EINVAL:
    return MEMDBG_ERR_PARAM;
#ifdef ETIMEDOUT
  case ETIMEDOUT:
    return MEMDBG_ERR_STATE;
#endif
#ifdef ECONNRESET
  case ECONNRESET:
    return MEMDBG_ERR_NET;
#endif
#ifdef EBUSY
  case EBUSY:
    return MEMDBG_ERR_STATE;
#endif
#ifdef EALREADY
  case EALREADY:
    return MEMDBG_ERR_STATE;
#endif
#ifdef ENOTSUP
  case ENOTSUP:
    return MEMDBG_ERR_UNSUPPORTED;
#endif
#if defined(EOPNOTSUPP) && (!defined(ENOTSUP) || EOPNOTSUPP != ENOTSUP)
  case EOPNOTSUPP:
    return MEMDBG_ERR_UNSUPPORTED;
#endif
  default:
    return MEMDBG_ERR_IO;
  }
}

static memdbg_status_t pal_status_from_errno(void) {
  return pal_status_from_errno_code(errno);
}

// Condition evaluation

static int64_t get_reg_value_by_cond_reg(const memdbg_debug_regs_t *regs,
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

static bool evaluate_bp_condition(const memdbg_breakpoint_t *bp,
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

static void debugger_lock(void) {
  (void)pthread_once(&g_dbg_once, debugger_init_mutex);
  (void)pthread_mutex_lock(&g_dbg_mtx);
}

static void debugger_unlock(void) { (void)pthread_mutex_unlock(&g_dbg_mtx); }

static void debugger_init_mutex(void) {
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&g_dbg_mtx, &attr);
  pthread_mutexattr_destroy(&attr);
}

static void debugger_sleep_ms(unsigned int ms) {
  struct timespec ts;
  ts.tv_sec = (time_t)(ms / 1000U);
  ts.tv_nsec = (long)((ms % 1000U) * 1000000U);
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
  }
}

static int find_breakpoint_slot(uint64_t address) {
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_BREAKPOINTS; ++i) {
    if (g_dbg.breakpoints[i].active &&
        g_dbg.breakpoints[i].address == address) {
      return (int)i;
    }
  }
  return -1;
}

static int alloc_breakpoint_slot(void) {
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_BREAKPOINTS; ++i) {
    if (!g_dbg.breakpoints[i].active) return (int)i;
  }
  return -1;
}

static int find_watchpoint_slot(uint64_t address) {
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_WATCHPOINTS; ++i) {
    if (g_dbg.watchpoints[i].installed &&
        g_dbg.watchpoints[i].address == address) {
      return (int)i;
    }
  }
  return -1;
}

static int alloc_hw_slot(void) {
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_WATCHPOINTS; ++i) {
    if (!g_dbg.watchpoints[i].installed) return (int)i;
  }
  return -1;
}

// Memory helpers (bypass memdbg_memory elevation to avoid nesting)

static memdbg_status_t debugger_memory_read(uint64_t address, void *buffer,
                                            size_t length) {
  size_t n = 0;
  memdbg_status_t st = pal_memory_read((int)g_dbg.pid, address, buffer,
                                       length, &n);
  if (st != MEMDBG_OK) return st;
  if (n != length) return MEMDBG_ERR_IO;
  return MEMDBG_OK;
}

static memdbg_status_t debugger_memory_write(uint64_t address,
                                             const void *buffer,
                                             size_t length) {
  size_t n = 0;
  memdbg_status_t st = pal_memory_write((int)g_dbg.pid, address, buffer,
                                        length, &n);
  if (st != MEMDBG_OK) return st;
  if (n != length) return MEMDBG_ERR_IO;
  return MEMDBG_OK;
}

// Software breakpoint install/uninstall

static memdbg_status_t install_sw_breakpoint(memdbg_breakpoint_t *bp) {
  if (bp->installed) return MEMDBG_OK;
  uint8_t byte = 0;
  memdbg_status_t st = debugger_memory_read(bp->address, &byte, 1);
  if (st != MEMDBG_OK) return st;
  bp->original_byte = byte;
  uint8_t int3 = INT3_OPCODE;
  st = debugger_memory_write(bp->address, &int3, 1);
  if (st != MEMDBG_OK) return st;
  bp->installed = true;
  return MEMDBG_OK;
}

static memdbg_status_t uninstall_sw_breakpoint(memdbg_breakpoint_t *bp) {
  if (!bp->installed) return MEMDBG_OK;
  memdbg_status_t st = debugger_memory_write(bp->address, &bp->original_byte,
                                             1);
  if (st != MEMDBG_OK) return st;
  bp->installed = false;
  return MEMDBG_OK;
}

// Hardware breakpoint/watchpoint helpers

static void build_dr7(uint32_t *dr7_out) {
  uint32_t dr7 = 0;
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_WATCHPOINTS; ++i) {
    const memdbg_watchpoint_t *wp = &g_dbg.watchpoints[i];
    if (!wp->installed) continue;
    uint32_t rw = 0;
    uint32_t len = 0;
    switch (wp->type) {
    case 0:
      rw = 0;
      break; /* exec */
    case 1:
      rw = 1;
      break; /* write */
    case 2:
      rw = 3;
      break; /* read */
    case 3:
      rw = 3;
      break; /* read-write */
    default:
      rw = 3;
      break;
    }
    switch (wp->length) {
    case 1:
      len = 0;
      break;
    case 2:
      len = 1;
      break;
    case 4:
      len = 3;
      break;
    case 8:
      len = 2;
      break;
    default:
      len = 3;
      break;
    }
    uint32_t shift = 16 + (i * 4);
    dr7 |= (rw << shift) | (len << (shift + 2));
    dr7 |= (1U << (i * 2));     /* local enable */
    dr7 |= (1U << (i * 2 + 1)); /* global enable */
  }
  *dr7_out = dr7;
}

static memdbg_status_t apply_dbregs_to_all(void) {
  int32_t lwps[MEMDBG_DEBUGGER_MAX_THREADS];
  uint32_t count = 0;    memdbg_status_t st = get_threads_locked(lwps, NULL, NULL, &count,
                                          MEMDBG_DEBUGGER_MAX_THREADS);
  if (st != MEMDBG_OK) return st;
  for (uint32_t i = 0; i < count; ++i) {
    if (pal_debug_set_dbregs((int)g_dbg.pid, lwps[i], &g_dbg.dbregs) != 0) {
      return pal_status_from_errno();
    }
  }
  return MEMDBG_OK;
}

static memdbg_status_t refresh_dbregs_from_thread(int32_t lwp) {
  if (pal_debug_get_dbregs((int)g_dbg.pid, lwp, &g_dbg.dbregs) != 0) {
    return pal_status_from_errno();
  }
  g_dbg.dbregs_valid = true;
  return MEMDBG_OK;
}

// Internal single-step over a software breakpoint

static memdbg_status_t step_over_sw_breakpoint_locked(int32_t lwp) {
  memdbg_debug_regs_t regs;
  memset(&regs, 0, sizeof(regs));
  if (pal_debug_get_regs((int)g_dbg.pid, lwp, &regs) != 0) {
    return pal_status_from_errno();
  }

  uint64_t bp_addr = (uint64_t)(regs.r_rip - 1);
  int slot = find_breakpoint_slot(bp_addr);
  if (slot < 0 || g_dbg.breakpoints[slot].kind != MEMDBG_BP_SOFTWARE) {
    /* No software breakpoint under RIP; just single-step. */
    if (pal_debug_single_step((int)g_dbg.pid, lwp) != 0) {
      return pal_status_from_errno();
    }
    return MEMDBG_OK;
  }

  memdbg_breakpoint_t *bp = &g_dbg.breakpoints[slot];
  memdbg_status_t st = uninstall_sw_breakpoint(bp);
  if (st != MEMDBG_OK) return st;

  regs.r_rip -= 1;
  if (pal_debug_set_regs((int)g_dbg.pid, lwp, &regs) != 0) {
    (void)install_sw_breakpoint(bp);
    return pal_status_from_errno();
  }

  if (pal_debug_single_step((int)g_dbg.pid, lwp) != 0) {
    (void)install_sw_breakpoint(bp);
    return pal_status_from_errno();
  }

  /* Wait for the single-step SIGTRAP. */
  for (int i = 0; i < 500; ++i) {
    int status = 0;
    int r = pal_debug_wait((int)g_dbg.pid, &status, true);
    if (r == 1 && WIFSTOPPED(status)) break;
    debugger_sleep_ms(10);
  }

  st = install_sw_breakpoint(bp);
  return st;
}

// Internal hardware debug-register synchronisation

static memdbg_status_t sync_hardware_dbregs_locked(void) {
  if (!g_dbg.dbregs_valid) {
    int32_t lwps[1];
    uint32_t count = 0;
    if (get_threads_locked(lwps, NULL, NULL, &count, 1) != MEMDBG_OK ||
        count == 0) {
      return MEMDBG_ERR_IO;
    }
    if (refresh_dbregs_from_thread(lwps[0]) != MEMDBG_OK) {
      return pal_status_from_errno();
    }
  }

  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_WATCHPOINTS; ++i) {
    const memdbg_watchpoint_t *wp = &g_dbg.watchpoints[i];
    if (wp->installed) {
      g_dbg.dbregs.dr[i] = wp->address;
    } else {
      g_dbg.dbregs.dr[i] = 0;
    }
  }

  uint32_t dr7 = 0;
  build_dr7(&dr7);
  g_dbg.dbregs.dr[7] = (uint64_t)dr7;

  return apply_dbregs_to_all();
}

// Public API

bool memdbg_debugger_is_attached(void) {
  bool r;
  debugger_lock();
  r = g_dbg.attached;
  debugger_unlock();
  return r;
}

int32_t memdbg_debugger_attached_pid(void) {
  int32_t r;
  debugger_lock();
  r = g_dbg.pid;
  debugger_unlock();
  return r;
}

bool memdbg_debugger_is_stopped(void) {
  bool r;
  debugger_lock();
  r = g_dbg.stopped;
  debugger_unlock();
  return r;
}

int32_t memdbg_debugger_get_stop_lwp(void) {
  int32_t r;
  debugger_lock();
  r = g_dbg.stop_lwp;
  debugger_unlock();
  return r;
}

memdbg_status_t memdbg_debugger_attach(int32_t pid) {
  if (!pal_debug_supported()) return MEMDBG_ERR_UNSUPPORTED;
  if (pid <= 1) return MEMDBG_ERR_PERMISSION;

  debugger_lock();
  if (g_dbg.attached) {
    if (g_dbg.pid == pid) {
      memdbg_log_write(MEMDBG_LOG_INFO,
                       "debugger: attach request reused existing session pid=%d",
                       (int)pid);
      debugger_unlock();
      return MEMDBG_OK;
    }
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  memset(&g_dbg, 0, sizeof(g_dbg));
  g_dbg.pid = pid;

  if (pal_debug_attach((int)pid) != 0) {
    int attach_errno = errno;
    memdbg_status_t st = pal_status_from_errno_code(attach_errno);
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "debugger: attach failed pid=%d errno=%d (%s) status=%d",
                     (int)pid, attach_errno, strerror(attach_errno), (int)st);
    memset(&g_dbg, 0, sizeof(g_dbg));
    debugger_unlock();
    return st;
  }

  g_dbg.attached = true;
  g_dbg.stopped = true;
  g_dbg.stop_lwp = 0;

  memdbg_log_write(MEMDBG_LOG_INFO, "debugger: attached pid=%d", (int)pid);
  debugger_unlock();
  return MEMDBG_OK;
}

memdbg_status_t memdbg_debugger_conditional_attach(int32_t pid,
                                                    bool *need_detach_out) {
  debugger_lock();
  if (g_dbg.attached) {
    if (g_dbg.pid == pid) {
      if (need_detach_out) *need_detach_out = false;
      debugger_unlock();
      return MEMDBG_OK;
    }
    /* Different process attached — detach first, then attach new. */
    (void)memdbg_debugger_detach();
  }
  memdbg_status_t st = memdbg_debugger_attach(pid);
  if (st == MEMDBG_OK && need_detach_out) {
    *need_detach_out = true;
  }
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_detach(void) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  /* Remove all software breakpoints before detaching. */
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_BREAKPOINTS; ++i) {
    if (g_dbg.breakpoints[i].active &&
        g_dbg.breakpoints[i].kind == MEMDBG_BP_SOFTWARE) {
      (void)uninstall_sw_breakpoint(&g_dbg.breakpoints[i]);
    }
  }

  /* Clear hardware breakpoints/watchpoints. */
  memset(&g_dbg.dbregs, 0, sizeof(g_dbg.dbregs));
  if (g_dbg.dbregs_valid) {
    (void)apply_dbregs_to_all();
  }

  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_detach((int)g_dbg.pid) != 0) {
    st = pal_status_from_errno();
  }

  memdbg_log_write(MEMDBG_LOG_INFO, "debugger: detached pid=%d",
                   (int)g_dbg.pid);
  memset(&g_dbg, 0, sizeof(g_dbg));
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_stop(void) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }
  if (g_dbg.stopped) {
    debugger_unlock();
    return memdbg_debugger_poll_events();
  }
  if (pal_debug_stop((int)g_dbg.pid) != 0) {
    debugger_unlock();
    return pal_status_from_errno();
  }
  debugger_unlock();

  /* Wait for the target to actually enter the stopped state.
   * SIGSTOP delivery is asynchronous on console firmware; a single
   * WNOHANG poll is not enough.  Timeout after 5 seconds. */
  const uint32_t timeout_ms = 5000U;
  uint32_t waited_ms = 0U;
  while (waited_ms < timeout_ms) {
    memdbg_status_t st = memdbg_debugger_poll_events();
    if (st != MEMDBG_OK) {
      return st;
    }
    if (memdbg_debugger_is_stopped()) {
      return MEMDBG_OK;
    }
    debugger_sleep_ms(10U);
    waited_ms += 10U;
    if (!memdbg_debugger_is_attached()) {
      return MEMDBG_ERR_STATE;
    }
  }

  return MEMDBG_ERR_STATE;
}

memdbg_status_t memdbg_debugger_continue(void) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  int32_t lwps[MEMDBG_DEBUGGER_MAX_THREADS];
  uint32_t count = 0;
  if (memdbg_debugger_get_threads(lwps, NULL, NULL, &count,
                                  MEMDBG_DEBUGGER_MAX_THREADS) == MEMDBG_OK) {
    for (uint32_t i = 0; i < count; ++i) {
      memdbg_debug_regs_t regs;
      memset(&regs, 0, sizeof(regs));
      if (pal_debug_get_regs((int)g_dbg.pid, lwps[i], &regs) != 0) continue;
      if (find_breakpoint_slot((uint64_t)(regs.r_rip - 1)) >= 0) {
        memdbg_status_t st = step_over_sw_breakpoint_locked(lwps[i]);
        if (st != MEMDBG_OK) {
          debugger_unlock();
          return st;
        }
      }
    }
  }

  if (pal_debug_continue((int)g_dbg.pid) != 0) {
    debugger_unlock();
    return pal_status_from_errno();
  }
  g_dbg.stopped = false;
  g_dbg.stop_lwp = 0;
  debugger_unlock();
  return MEMDBG_OK;
}

memdbg_status_t memdbg_debugger_step(int32_t lwp) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  memdbg_status_t st = step_over_sw_breakpoint_locked(lwp);

  if (st == MEMDBG_OK) {
    g_dbg.stopped = false;
    g_dbg.stop_lwp = 0;
  }
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_suspend_thread(int32_t lwp) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }
  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_suspend_thread((int)g_dbg.pid, lwp) != 0) {
    st = pal_status_from_errno();
  }
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_resume_thread(int32_t lwp) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }
  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_resume_thread((int)g_dbg.pid, lwp) != 0) {
    st = pal_status_from_errno();
  }
  debugger_unlock();
  return st;
}

static memdbg_status_t get_threads_locked(int32_t *lwps, char (*names)[24],
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

static memdbg_status_t get_regs_locked(int32_t lwp,
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

memdbg_status_t memdbg_debugger_set_breakpoint(uint64_t address,
                                               uint32_t kind) {
  return memdbg_debugger_set_breakpoint_cond(address, kind,
      MEMDBG_BP_COND_NONE, MEMDBG_BP_COND_EQ, 0ULL);
}

memdbg_status_t memdbg_debugger_set_breakpoint_cond(
    uint64_t address, uint32_t kind,
    uint32_t cond_reg, uint32_t cond_op, uint64_t cond_value) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  if (cond_reg > MEMDBG_BP_COND_RIP) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }
  if (cond_op > MEMDBG_BP_COND_GE) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }

  if (find_breakpoint_slot(address) >= 0) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }

  int slot = alloc_breakpoint_slot();
  if (slot < 0) {
    debugger_unlock();
    return MEMDBG_ERR_NOMEM;
  }

  memdbg_breakpoint_t *bp = &g_dbg.breakpoints[slot];
  memset(bp, 0, sizeof(*bp));
  bp->address = address;
  bp->kind = kind;
  bp->active = true;
  bp->cond_reg = cond_reg;
  bp->cond_op = cond_op;
  bp->cond_value = cond_value;

  memdbg_status_t st = MEMDBG_OK;
  if (kind == MEMDBG_BP_SOFTWARE) {
    st = install_sw_breakpoint(bp);
  } else if (kind == MEMDBG_BP_HARDWARE) {
    int hw = alloc_hw_slot();
    if (hw < 0) {
      st = MEMDBG_ERR_NOMEM;
    } else {
      memdbg_watchpoint_t fake;
      memset(&fake, 0, sizeof(fake));
      fake.address = address;
      fake.length = 1;
      fake.type = 0; /* exec */
      fake.slot = (uint32_t)hw;
      fake.installed = true;
      g_dbg.watchpoints[hw] = fake;
      st = sync_hardware_dbregs_locked();
      if (st != MEMDBG_OK) {
        memset(&g_dbg.watchpoints[hw], 0,
               sizeof(g_dbg.watchpoints[hw]));
      }
    }
  } else {
    st = MEMDBG_ERR_PARAM;
  }

  if (st != MEMDBG_OK) {
    memset(bp, 0, sizeof(*bp));
  }

  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_clear_breakpoint(uint64_t address) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  int slot = find_breakpoint_slot(address);
  if (slot < 0) {
    debugger_unlock();
    return MEMDBG_ERR_NOT_FOUND;
  }

  memdbg_breakpoint_t *bp = &g_dbg.breakpoints[slot];
  memdbg_status_t st = MEMDBG_OK;
  if (bp->kind == MEMDBG_BP_SOFTWARE) {
    st = uninstall_sw_breakpoint(bp);
  } else if (bp->kind == MEMDBG_BP_HARDWARE) {
    int hw = find_watchpoint_slot(address);
    if (hw >= 0) {
      memset(&g_dbg.watchpoints[hw], 0, sizeof(g_dbg.watchpoints[hw]));
      st = sync_hardware_dbregs_locked();
    }
  }

  memset(bp, 0, sizeof(*bp));
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_clear_all_breakpoints(uint32_t *cleared) {
  uint32_t c = 0;
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    if (cleared != NULL) *cleared = 0;
    return MEMDBG_ERR_STATE;
  }
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_BREAKPOINTS; ++i) {
    if (!g_dbg.breakpoints[i].active) continue;
    memdbg_breakpoint_t *bp = &g_dbg.breakpoints[i];
    if (bp->kind == MEMDBG_BP_SOFTWARE) {
      (void)uninstall_sw_breakpoint(bp);
    } else if (bp->kind == MEMDBG_BP_HARDWARE) {
      int hw = find_watchpoint_slot(bp->address);
      if (hw >= 0) {
        memset(&g_dbg.watchpoints[hw], 0, sizeof(g_dbg.watchpoints[hw]));
      }
    }
    memset(bp, 0, sizeof(*bp));
    ++c;
  }
  if (c > 0) (void)sync_hardware_dbregs_locked();
  if (cleared != NULL) *cleared = c;
  debugger_unlock();
  return MEMDBG_OK;
}

memdbg_status_t memdbg_debugger_breakpoints_snapshot(
    memdbg_breakpoint_t *out, uint32_t max, uint32_t *count) {
  if (count == NULL || (out == NULL && max > 0U)) {
    return MEMDBG_ERR_PARAM;
  }

  uint32_t n = max;
  if (n > MEMDBG_DEBUGGER_MAX_BREAKPOINTS) {
    n = MEMDBG_DEBUGGER_MAX_BREAKPOINTS;
  }

  debugger_lock();
  if (n > 0U) {
    memcpy(out, g_dbg.breakpoints, n * sizeof(out[0]));
  }
  debugger_unlock();

  *count = n;
  return MEMDBG_OK;
}

memdbg_status_t memdbg_debugger_set_watchpoint(uint64_t address,
                                               uint32_t length,
                                               uint32_t type) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  if (length != 1 && length != 2 && length != 4 && length != 8) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }
  if (type > 3) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }

  if (find_watchpoint_slot(address) >= 0) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }

  int slot = alloc_hw_slot();
  if (slot < 0) {
    debugger_unlock();
    return MEMDBG_ERR_NOMEM;
  }

  memdbg_watchpoint_t *wp = &g_dbg.watchpoints[slot];
  memset(wp, 0, sizeof(*wp));
  wp->address = address;
  wp->length = length;
  wp->type = type;
  wp->slot = (uint32_t)slot;
  wp->installed = true;

  memdbg_status_t st = sync_hardware_dbregs_locked();
  if (st != MEMDBG_OK) {
    memset(wp, 0, sizeof(*wp));
  }

  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_clear_watchpoint(uint64_t address) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  int slot = find_watchpoint_slot(address);
  if (slot < 0) {
    debugger_unlock();
    return MEMDBG_ERR_NOT_FOUND;
  }

  memset(&g_dbg.watchpoints[slot], 0, sizeof(g_dbg.watchpoints[slot]));
  memdbg_status_t st = sync_hardware_dbregs_locked();
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_clear_all_watchpoints(uint32_t *cleared) {
  uint32_t c = 0;
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    if (cleared != NULL) *cleared = 0;
    return MEMDBG_ERR_STATE;
  }
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_WATCHPOINTS; ++i) {
    if (!g_dbg.watchpoints[i].installed) continue;
    memset(&g_dbg.watchpoints[i], 0, sizeof(g_dbg.watchpoints[i]));
    ++c;
  }
  if (c > 0) (void)sync_hardware_dbregs_locked();
  if (cleared != NULL) *cleared = c;
  debugger_unlock();
  return MEMDBG_OK;
}

memdbg_status_t memdbg_debugger_watchpoints_snapshot(
    memdbg_watchpoint_t *out, uint32_t max, uint32_t *count) {
  if (count == NULL || (out == NULL && max > 0U)) {
    return MEMDBG_ERR_PARAM;
  }

  uint32_t n = max;
  if (n > MEMDBG_DEBUGGER_MAX_WATCHPOINTS) {
    n = MEMDBG_DEBUGGER_MAX_WATCHPOINTS;
  }

  debugger_lock();
  if (n > 0U) {
    memcpy(out, g_dbg.watchpoints, n * sizeof(out[0]));
  }
  debugger_unlock();

  *count = n;
  return MEMDBG_OK;
}

memdbg_status_t memdbg_debugger_poll_events(void) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  int status = 0;
  int r = pal_debug_wait((int)g_dbg.pid, &status, true);
  if (r == 1) {
    if (WIFSTOPPED(status)) {
      g_dbg.stopped = true;
      g_dbg.stop_lwp = 0;
      /* Try to identify the stopped LWP. */
      int32_t lwps[MEMDBG_DEBUGGER_MAX_THREADS];
      uint32_t count = 0;
      if (get_threads_locked(lwps, NULL, NULL, &count,
                             MEMDBG_DEBUGGER_MAX_THREADS) ==
          MEMDBG_OK) {
        for (uint32_t i = 0; i < count; ++i) {
          memdbg_debug_regs_t regs;
          if (pal_debug_get_regs((int)g_dbg.pid, lwps[i], &regs) == 0) {
            int slot = find_breakpoint_slot((uint64_t)(regs.r_rip - 1));
            if (slot >= 0) {
              /* Evaluate condition.  If it fails, auto-continue and
               * report no stop to the frontend. */
              const memdbg_breakpoint_t *bp = &g_dbg.breakpoints[slot];
              if (!evaluate_bp_condition(bp, &regs)) {
                g_dbg.stopped = false;
                g_dbg.stop_lwp = 0;
                (void)pal_debug_continue((int)g_dbg.pid);
                debugger_unlock();
                return MEMDBG_OK;
              }
              g_dbg.stop_lwp = lwps[i];
              break;
            }
          }
        }
      }
    } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
      g_dbg.attached = false;
      g_dbg.stopped = false;
      memset(&g_dbg, 0, sizeof(g_dbg));
      debugger_unlock();
      return MEMDBG_ERR_NOT_FOUND;
    }
  } else if (r == -1 && errno != ECHILD) {
    debugger_unlock();
    return pal_status_from_errno();
  }

  debugger_unlock();
  return MEMDBG_OK;
}
