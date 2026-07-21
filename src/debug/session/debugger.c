/*
 * memDBG - Payload debugger backend (core state + lifecycle).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Register access    → debugger_regs.c
 * Breakpoints / WP   → debugger_breakpoints.c
 * Shared internals   → memdbg_debugger_internal.h
 */

#include "internal.h"

#include "memdbg/core/memdbg_log.h"
#include "memdbg/pal/debug.h"

#include <errno.h>
#include <string.h>
#include <sys/wait.h>

/* ---- Global state ---- */

pthread_mutex_t         g_dbg_mtx;
pthread_once_t          g_dbg_once = PTHREAD_ONCE_INIT;
memdbg_debugger_state_t g_dbg = {0};

/* ---- Locking ---- */

void debugger_lock(void) {
  (void)pthread_once(&g_dbg_once, debugger_init_mutex);
  (void)pthread_mutex_lock(&g_dbg_mtx);
}

void debugger_unlock(void) { (void)pthread_mutex_unlock(&g_dbg_mtx); }

void debugger_init_mutex(void) {
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&g_dbg_mtx, &attr);
  pthread_mutexattr_destroy(&attr);
}

void debugger_sleep_ms(unsigned int ms) {
  struct timespec ts;
  ts.tv_sec = (time_t)(ms / 1000U);
  ts.tv_nsec = (long)((ms % 1000U) * 1000000U);
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
  }
}

/* ---- Error conversion ---- */

memdbg_status_t pal_status_from_errno_code(int code) {
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

memdbg_status_t pal_status_from_errno(void) {
  return pal_status_from_errno_code(errno);
}

/* ---- Memory helpers (bypass memdbg_memory elevation) ---- */

memdbg_status_t debugger_memory_read(uint64_t address, void *buffer,
                                     size_t length) {
  size_t n = 0;
  memdbg_status_t st = pal_memory_read((int)g_dbg.pid, address, buffer,
                                       length, &n);
  if (st != MEMDBG_OK) return st;
  if (n != length) return MEMDBG_ERR_IO;
  return MEMDBG_OK;
}

memdbg_status_t debugger_memory_write(uint64_t address, const void *buffer,
                                      size_t length) {
  size_t n = 0;
  memdbg_status_t st = pal_memory_write((int)g_dbg.pid, address, buffer,
                                        length, &n);
  if (st != MEMDBG_OK) return st;
  if (n != length) return MEMDBG_ERR_IO;
  return MEMDBG_OK;
}

/* ---- Platform probes ---- */

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

/* ---- State queries ---- */

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

/* ---- Lifecycle ---- */

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
    (void)memdbg_debugger_detach();
  }
  memdbg_status_t st = memdbg_debugger_attach(pid);
  if (st == MEMDBG_OK && need_detach_out) *need_detach_out = true;
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_detach(void) {
  debugger_lock();
  if (!g_dbg.attached) { debugger_unlock(); return MEMDBG_ERR_STATE; }

  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_BREAKPOINTS; ++i) {
    if (g_dbg.breakpoints[i].active &&
        g_dbg.breakpoints[i].kind == MEMDBG_BP_SOFTWARE) {
      (void)uninstall_sw_breakpoint(&g_dbg.breakpoints[i]);
    }
  }

  memset(&g_dbg.dbregs, 0, sizeof(g_dbg.dbregs));
  if (g_dbg.dbregs_valid) (void)apply_dbregs_to_all();

  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_detach((int)g_dbg.pid) != 0) st = pal_status_from_errno();

  memdbg_log_write(MEMDBG_LOG_INFO, "debugger: detached pid=%d",
                   (int)g_dbg.pid);
  memset(&g_dbg, 0, sizeof(g_dbg));
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_stop(void) {
  debugger_lock();
  if (!g_dbg.attached) { debugger_unlock(); return MEMDBG_ERR_STATE; }
  if (g_dbg.stopped) { debugger_unlock(); return memdbg_debugger_poll_events(); }
  if (pal_debug_stop((int)g_dbg.pid) != 0) {
    debugger_unlock();
    return pal_status_from_errno();
  }
  debugger_unlock();

  const uint32_t timeout_ms = 5000U;
  uint32_t waited_ms = 0U;
  while (waited_ms < timeout_ms) {
    memdbg_status_t st = memdbg_debugger_poll_events();
    if (st != MEMDBG_OK) return st;
    if (memdbg_debugger_is_stopped()) return MEMDBG_OK;
    debugger_sleep_ms(10U);
    waited_ms += 10U;
    if (!memdbg_debugger_is_attached()) return MEMDBG_ERR_STATE;
  }
  return MEMDBG_ERR_STATE;
}

memdbg_status_t memdbg_debugger_continue(void) {
  debugger_lock();
  if (!g_dbg.attached) { debugger_unlock(); return MEMDBG_ERR_STATE; }

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
        if (st != MEMDBG_OK) { debugger_unlock(); return st; }
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
  if (!g_dbg.attached) { debugger_unlock(); return MEMDBG_ERR_STATE; }
  memdbg_status_t st = step_over_sw_breakpoint_locked(lwp);
  if (st == MEMDBG_OK) { g_dbg.stopped = false; g_dbg.stop_lwp = 0; }
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_suspend_thread(int32_t lwp) {
  debugger_lock();
  if (!g_dbg.attached) { debugger_unlock(); return MEMDBG_ERR_STATE; }
  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_suspend_thread((int)g_dbg.pid, lwp) != 0)
    st = pal_status_from_errno();
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_resume_thread(int32_t lwp) {
  debugger_lock();
  if (!g_dbg.attached) { debugger_unlock(); return MEMDBG_ERR_STATE; }
  memdbg_status_t st = MEMDBG_OK;
  if (pal_debug_resume_thread((int)g_dbg.pid, lwp) != 0)
    st = pal_status_from_errno();
  debugger_unlock();
  return st;
}

/* ---- Event polling ---- */

memdbg_status_t memdbg_debugger_poll_events(void) {
  debugger_lock();
  if (!g_dbg.attached) { debugger_unlock(); return MEMDBG_ERR_STATE; }

  int status = 0;
  int r = pal_debug_wait((int)g_dbg.pid, &status, true);
  if (r == 1) {
    if (WIFSTOPPED(status)) {
      g_dbg.stopped = true;
      g_dbg.stop_lwp = 0;
      int32_t lwps[MEMDBG_DEBUGGER_MAX_THREADS];
      uint32_t count = 0;
      if (get_threads_locked(lwps, NULL, NULL, &count,
                             MEMDBG_DEBUGGER_MAX_THREADS) == MEMDBG_OK) {
        for (uint32_t i = 0; i < count; ++i) {
          memdbg_debug_regs_t regs;
          if (pal_debug_get_regs((int)g_dbg.pid, lwps[i], &regs) == 0) {
            int slot = find_breakpoint_slot((uint64_t)(regs.r_rip - 1));
            if (slot >= 0) {
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
