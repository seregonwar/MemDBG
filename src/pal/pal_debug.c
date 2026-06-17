/*
 * memDBG - PAL: Cross-platform debugger primitives.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/pal/pal_debug.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__) ||          \
    defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#define MEMDBG_PAL_DEBUG_CONSOLE 1
#elif defined(__FreeBSD__)
#define MEMDBG_PAL_DEBUG_FREEBSD 1
#endif

#if defined(MEMDBG_PAL_DEBUG_FREEBSD) || defined(MEMDBG_PAL_DEBUG_CONSOLE)

#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/wait.h>

#if defined(MEMDBG_PAL_DEBUG_CONSOLE)
#include <sys/syscall.h>
#endif

#if defined(MEMDBG_PAL_DEBUG_FREEBSD)

static long pal_debug_ptrace_raw(int op, int pid, void *addr, long data) {
  return ptrace(op, pid, addr, data);
}

#elif defined(MEMDBG_PAL_DEBUG_CONSOLE)

static long pal_debug_ptrace_raw(int op, int pid, void *addr, long data) {
  return (long)__syscall((quad_t)SYS_ptrace, op, pid, addr, data);
}

#endif

bool pal_debug_supported(void) { return true; }

long pal_debug_ptrace(int op, int pid, void *addr, long data) {
  return pal_debug_ptrace_raw(op, pid, addr, data);
}

int pal_debug_wait(int pid, int *status, bool nohang) {
  int st = 0;
  if (status == NULL) status = &st;
  int flags = nohang ? WNOHANG : 0;
  pid_t r = waitpid((pid_t)pid, status, flags);
  if (r == -1) return -1;
  if (nohang && r == 0) {
    *status = 0;
    return 0;
  }
  return 1;
}

int pal_debug_attach(int pid) {
  if (pal_debug_ptrace_raw(PT_ATTACH, pid, NULL, 0) == -1) return -1;

  /* Wait for the initial SIGTRAP with a safety timeout. */
  for (int i = 0; i < 500; ++i) {
    int status = 0;
    int r = pal_debug_wait(pid, &status, true);
    if (r == 1 && WIFSTOPPED(status)) {
      return 0;
    }
    (void)usleep(10000); /* 10 ms */
  }

  errno = ETIMEDOUT;
  return -1;
}

int pal_debug_detach(int pid) {
  return (pal_debug_ptrace_raw(PT_DETACH, pid, NULL, 0) == -1) ? -1 : 0;
}

int pal_debug_continue(int pid) {
  return (pal_debug_ptrace_raw(PT_CONTINUE, pid, (void *)(uintptr_t)1, 0) ==
          -1)
             ? -1
             : 0;
}

int pal_debug_stop(int pid) { return (kill((pid_t)pid, SIGSTOP) == 0) ? 0 : -1; }

int pal_debug_single_step(int pid, int32_t lwp) {
  (void)pid;
  return (pal_debug_ptrace_raw(PT_STEP, (int)lwp, (void *)(uintptr_t)1, 0) ==
          -1)
             ? -1
             : 0;
}

int pal_debug_suspend_thread(int pid, int32_t lwp) {
  (void)pid;
  return (pal_debug_ptrace_raw(PT_SUSPEND, (int)lwp, NULL, 0) == -1) ? -1 : 0;
}

int pal_debug_resume_thread(int pid, int32_t lwp) {
  (void)pid;
  return (pal_debug_ptrace_raw(PT_RESUME, (int)lwp, NULL, 0) == -1) ? -1 : 0;
}

int pal_debug_get_thread_count(int pid) {
  long r = pal_debug_ptrace_raw(PT_GETNUMLWPS, pid, NULL, 0);
  return (r == -1) ? -1 : (int)r;
}

int pal_debug_get_thread_list(int pid, int32_t *lwps, int max_count) {
  if (lwps == NULL || max_count <= 0) {
    errno = EINVAL;
    return -1;
  }
  int count = pal_debug_get_thread_count(pid);
  if (count <= 0) return count;
  if (count > max_count) count = max_count;
  lwpid_t *buf = (lwpid_t *)calloc((size_t)count, sizeof(lwpid_t));
  if (buf == NULL) return -1;
  long r = pal_debug_ptrace_raw(PT_GETLWPLIST, pid, buf, (long)count);
  if (r == -1) {
    free(buf);
    return -1;
  }
  for (int i = 0; i < count; ++i) lwps[i] = (int32_t)buf[i];
  free(buf);
  return count;
}

/* ---- Register helpers ---- */

#include <machine/reg.h>

static void pal_debug_regs_from_native(const struct reg *src,
                                       memdbg_debug_regs_t *dst) {
  memset(dst, 0, sizeof(*dst));
  dst->r_r15 = (int64_t)src->r_r15;
  dst->r_r14 = (int64_t)src->r_r14;
  dst->r_r13 = (int64_t)src->r_r13;
  dst->r_r12 = (int64_t)src->r_r12;
  dst->r_r11 = (int64_t)src->r_r11;
  dst->r_r10 = (int64_t)src->r_r10;
  dst->r_r9 = (int64_t)src->r_r9;
  dst->r_r8 = (int64_t)src->r_r8;
  dst->r_rdi = (int64_t)src->r_rdi;
  dst->r_rsi = (int64_t)src->r_rsi;
  dst->r_rbp = (int64_t)src->r_rbp;
  dst->r_rbx = (int64_t)src->r_rbx;
  dst->r_rdx = (int64_t)src->r_rdx;
  dst->r_rcx = (int64_t)src->r_rcx;
  dst->r_rax = (int64_t)src->r_rax;
  dst->r_trapno = (uint32_t)src->r_trapno;
  dst->r_fs = (uint16_t)src->r_fs;
  dst->r_gs = (uint16_t)src->r_gs;
  dst->r_err = (uint32_t)src->r_err;
  dst->r_es = (uint16_t)src->r_es;
  dst->r_ds = (uint16_t)src->r_ds;
  dst->r_rip = (int64_t)src->r_rip;
  dst->r_cs = (int64_t)src->r_cs;
  dst->r_rflags = (int64_t)src->r_rflags;
  dst->r_rsp = (int64_t)src->r_rsp;
  dst->r_ss = (int64_t)src->r_ss;
}

static void pal_debug_regs_to_native(const memdbg_debug_regs_t *src,
                                     struct reg *dst) {
  dst->r_r15 = (register_t)src->r_r15;
  dst->r_r14 = (register_t)src->r_r14;
  dst->r_r13 = (register_t)src->r_r13;
  dst->r_r12 = (register_t)src->r_r12;
  dst->r_r11 = (register_t)src->r_r11;
  dst->r_r10 = (register_t)src->r_r10;
  dst->r_r9 = (register_t)src->r_r9;
  dst->r_r8 = (register_t)src->r_r8;
  dst->r_rdi = (register_t)src->r_rdi;
  dst->r_rsi = (register_t)src->r_rsi;
  dst->r_rbp = (register_t)src->r_rbp;
  dst->r_rbx = (register_t)src->r_rbx;
  dst->r_rdx = (register_t)src->r_rdx;
  dst->r_rcx = (register_t)src->r_rcx;
  dst->r_rax = (register_t)src->r_rax;
  dst->r_trapno = (register_t)src->r_trapno;
  dst->r_fs = (register_t)src->r_fs;
  dst->r_gs = (register_t)src->r_gs;
  dst->r_err = (register_t)src->r_err;
  dst->r_es = (register_t)src->r_es;
  dst->r_ds = (register_t)src->r_ds;
  dst->r_rip = (register_t)src->r_rip;
  dst->r_cs = (register_t)src->r_cs;
  dst->r_rflags = (register_t)src->r_rflags;
  dst->r_rsp = (register_t)src->r_rsp;
  dst->r_ss = (register_t)src->r_ss;
}

int pal_debug_get_regs(int pid, int32_t lwp, memdbg_debug_regs_t *regs) {
  (void)pid;
  struct reg r;
  memset(&r, 0, sizeof(r));
  if (pal_debug_ptrace_raw(PT_GETREGS, (int)lwp, &r, 0) == -1) return -1;
  pal_debug_regs_from_native(&r, regs);
  return 0;
}

int pal_debug_set_regs(int pid, int32_t lwp, const memdbg_debug_regs_t *regs) {
  (void)pid;
  struct reg r;
  memset(&r, 0, sizeof(r));
  pal_debug_regs_to_native(regs, &r);
  return (pal_debug_ptrace_raw(PT_SETREGS, (int)lwp, &r, 0) == -1) ? -1 : 0;
}

int pal_debug_get_dbregs(int pid, int32_t lwp,
                         memdbg_debug_dbregs_t *dbregs) {
  (void)pid;
  struct dbreg d;
  memset(&d, 0, sizeof(d));
  if (pal_debug_ptrace_raw(PT_GETDBREGS, (int)lwp, &d, 0) == -1) return -1;
  for (int i = 0; i < 16; ++i) dbregs->dr[i] = (uint64_t)d.dr[i];
  return 0;
}

int pal_debug_set_dbregs(int pid, int32_t lwp,
                         const memdbg_debug_dbregs_t *dbregs) {
  (void)pid;
  struct dbreg d;
  memset(&d, 0, sizeof(d));
  for (int i = 0; i < 16; ++i) d.dr[i] = (long)dbregs->dr[i];
  return (pal_debug_ptrace_raw(PT_SETDBREGS, (int)lwp, &d, 0) == -1) ? -1 : 0;
}

int pal_debug_get_thread_name(int pid, int32_t lwp, char *name,
                              size_t name_len) {
  (void)pid;
  if (name == NULL || name_len == 0) {
    errno = EINVAL;
    return -1;
  }

  /* Try PT_GET_THREAD_NAME if the platform defines it (FreeBSD 13+). */
#ifdef PT_GET_THREAD_NAME
  if (pal_debug_ptrace_raw(PT_GET_THREAD_NAME, (int)lwp, name,
                           (long)name_len) == 0) {
    name[name_len - 1] = '\0'; /* ensure null termination */
    return 0;
  }
#endif

  /* Fallback: empty name signals caller to use a synthetic label. */
  name[0] = '\0';
  return -1;
}

#else /* Unsupported platform */

bool pal_debug_supported(void) { return false; }

long pal_debug_ptrace(int op, int pid, void *addr, long data) {
  (void)op;
  (void)pid;
  (void)addr;
  (void)data;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_wait(int pid, int *status, bool nohang) {
  (void)pid;
  (void)status;
  (void)nohang;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_attach(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_detach(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_continue(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_stop(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_single_step(int pid, int32_t lwp) {
  (void)pid;
  (void)lwp;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_suspend_thread(int pid, int32_t lwp) {
  (void)pid;
  (void)lwp;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_resume_thread(int pid, int32_t lwp) {
  (void)pid;
  (void)lwp;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_count(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_list(int pid, int32_t *lwps, int max_count) {
  (void)pid;
  (void)lwps;
  (void)max_count;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_regs(int pid, int32_t lwp, memdbg_debug_regs_t *regs) {
  (void)pid;
  (void)lwp;
  (void)regs;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_set_regs(int pid, int32_t lwp, const memdbg_debug_regs_t *regs) {
  (void)pid;
  (void)lwp;
  (void)regs;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_dbregs(int pid, int32_t lwp,
                         memdbg_debug_dbregs_t *dbregs) {
  (void)pid;
  (void)lwp;
  (void)dbregs;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_set_dbregs(int pid, int32_t lwp,
                         const memdbg_debug_dbregs_t *dbregs) {
  (void)pid;
  (void)lwp;
  (void)dbregs;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_name(int pid, int32_t lwp, char *name,
                              size_t name_len) {
  (void)pid;
  (void)lwp;
  if (name != NULL && name_len > 0) name[0] = '\0';
  errno = ENOTSUP;
  return -1;
}

#endif
