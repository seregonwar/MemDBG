/*
 * memDBG - PAL: Cross-platform debugger primitives.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/pal/pal_debug.h"

#include "memdbg/privilege/privilege.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#define MEMDBG_PAL_DEBUG_CONSOLE 1
#define MEMDBG_PAL_DEBUG_PS5 1
#include "memdbg/pal/pal_debug_ps5.h"
#elif defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
#define MEMDBG_PAL_DEBUG_CONSOLE 1
#elif defined(__FreeBSD__)
#define MEMDBG_PAL_DEBUG_FREEBSD 1
#elif defined(__APPLE__)
#define MEMDBG_PAL_DEBUG_MACOS 1
#endif

#if defined(MEMDBG_PAL_DEBUG_FREEBSD) || defined(MEMDBG_PAL_DEBUG_CONSOLE)

#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#if defined(MEMDBG_PAL_DEBUG_PS5)
#include <ps5/kernel.h>
#include "memdbg/pal/pal_kernel_fast.h"

static int pal_debug_kernel_copyout(intptr_t source, void *destination,
                                    size_t length) {
  return memdbg_kernel_fast_available()
             ? memdbg_kernel_copyout_fast(source, destination, length)
             : kernel_copyout(source, destination, length);
}

static intptr_t pal_debug_kernel_get_proc(pid_t pid) {
  return memdbg_kernel_fast_available()
             ? memdbg_kernel_get_proc_fast(pid)
             : kernel_get_proc(pid);
}

#define kernel_copyout pal_debug_kernel_copyout
#define kernel_get_proc pal_debug_kernel_get_proc
#endif

#if defined(MEMDBG_PAL_DEBUG_FREEBSD)

static long pal_debug_ptrace_raw(int op, int pid, void *addr, long data) {
  return ptrace(op, pid, addr, data);
}

#elif defined(MEMDBG_PAL_DEBUG_CONSOLE)

static long pal_debug_ptrace_raw(int op, int pid, void *addr, long data) {
  /*
   * Use __syscall() to bypass the libc ptrace wrapper.  The libc wrapper on
   * PS4 can corrupt the tracing state of the target process, causing crashes
   * in subsequent mdbg_copyout/mdbg_copyin calls.  __syscall() exposes the
   * raw ABI, so we must handle the errno=0 case explicitly: the kernel
   * rejects a denied PT_ATTACH without setting errno, so we synthesize
   * EPERM to give callers an actionable error instead of "No error".
   */
#if defined(MEMDBG_PAL_DEBUG_CONSOLE)
  memdbg_ucred_backup_t backup;
  if (memdbg_privilege_begin_ptrace(&backup) != 0) return -1;
#endif

  errno = 0;
  long result = (long)__syscall((quad_t)SYS_ptrace, op, pid, addr, data);
  int operation_errno = errno;
  if (result == -1 && operation_errno == 0) operation_errno = EPERM;

#if defined(MEMDBG_PAL_DEBUG_CONSOLE)
  if (memdbg_privilege_end_ptrace(&backup) != 0) {
    if (result != -1) return -1;
  }
#endif

  errno = operation_errno;
  return result;
}

#endif

bool pal_debug_supported(void) { return true; }

bool pal_debug_fpregs_supported(void) {
#if (defined(PT_GETXSTATE_INFO) && defined(PT_GETXSTATE) &&                 \
     defined(PT_SETXSTATE)) ||                                               \
    (defined(PT_GETFPREGS) && defined(PT_SETFPREGS))
  return true;
#else
  return false;
#endif
}

bool pal_debug_fsgsbase_supported(void) {
#if defined(PT_GETFSBASE) && defined(PT_SETFSBASE) &&                         \
    defined(PT_GETGSBASE) && defined(PT_SETGSBASE)
  return true;
#else
  return false;
#endif
}

long pal_debug_ptrace(int op, int pid, void *addr, long data) {
  return pal_debug_ptrace_raw(op, pid, addr, data);
}

static void pal_debug_sleep_ms(uint32_t ms) {
  struct timespec ts;
  ts.tv_sec = (time_t)(ms / 1000U);
  ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
  }
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
  int wait_errno = 0;
  for (int i = 0; i < 500; ++i) {
    int status = 0;
    int r = pal_debug_wait(pid, &status, true);
    if (r == 1 && WIFSTOPPED(status)) {
      return 0;
    }
    if (r == -1) {
      wait_errno = errno;
#if defined(MEMDBG_PAL_DEBUG_CONSOLE)
      if (wait_errno == ECHILD) {
        /* On console firmware, PT_ATTACH can succeed without exposing the
         * traced process through waitpid() as a child of this payload.  Treat
         * the successful ptrace attach as authoritative and let higher layers
         * issue an explicit stop/poll if needed. */
        return 0;
      }
      /* ECONNRESET can occur when the console's internal debugger daemon
       * momentarily resets the connection.  Retry instead of failing
       * immediately; a subsequent poll usually succeeds. */
      if (wait_errno == ECONNRESET) {
        pal_debug_sleep_ms(50U);
        continue;
      }
#endif
      if (wait_errno != EINTR) break;
    }
    pal_debug_sleep_ms(10U);
  }

#if defined(MEMDBG_PAL_DEBUG_CONSOLE)
  if (wait_errno == 0) {
    return 0;
  }
#endif

  (void)pal_debug_ptrace_raw(PT_DETACH, pid, NULL, 0);
  errno = wait_errno != 0 ? wait_errno : ETIMEDOUT;
  return -1;
}

int pal_debug_detach(int pid) {
#if defined(MEMDBG_PAL_DEBUG_PS5)
  kern_thread_cache_flush();
#endif
  return (pal_debug_ptrace_raw(PT_DETACH, pid, NULL, 0) == -1) ? -1 : 0;
}

int pal_debug_continue(int pid) {
#if defined(MEMDBG_PAL_DEBUG_PS5)
  kern_thread_cache_flush();
#endif
  return (pal_debug_ptrace_raw(PT_CONTINUE, pid, (void *)(uintptr_t)1, 0) ==
          -1)
             ? -1
             : 0;
}

int pal_debug_syscall(int pid) {
#if defined(PT_SYSCALL)
  return (pal_debug_ptrace_raw(PT_SYSCALL, pid, (void *)(uintptr_t)1, 0) ==
          -1)
             ? -1
             : 0;
#else
  (void)pid;
  errno = ENOTSUP;
  return -1;
#endif
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
#if defined(MEMDBG_PAL_DEBUG_PS5)
  {
    intptr_t kproc = kernel_get_proc((pid_t)pid);
    if (!kproc) return -1;
    uint8_t chain_hdr[0x30];
    if (kernel_copyout(kproc + 0x10, chain_hdr, 0x30) != 0) return -1;
    intptr_t kthread = *(intptr_t *)chain_hdr;
    int count = 0;
    uint8_t tbuf[0x680];
    while (kthread) {
      if (count >= 16384) break;
      if (kernel_copyout((intptr_t)kthread, tbuf, 0x680) != 0) break;
      count++;
      kthread = *(intptr_t *)(tbuf + 0x10);
    }
    return count;
  }
#else
  long r = pal_debug_ptrace_raw(PT_GETNUMLWPS, pid, NULL, 0);
  return (r == -1) ? -1 : (int)r;
#endif
}

int pal_debug_get_thread_list(int pid, int32_t *lwps, int max_count) {
  if (lwps == NULL || max_count <= 0) { errno = EINVAL; return -1; }
#if defined(MEMDBG_PAL_DEBUG_PS5)
  return kern_get_thread_list(pid, lwps, max_count);
#else
  int count = pal_debug_get_thread_count(pid);
  if (count <= 0) return count;
  if (count > max_count) count = max_count;
  lwpid_t *buf = (lwpid_t *)calloc((size_t)count, sizeof(lwpid_t));
  if (buf == NULL) return -1;
  long r = pal_debug_ptrace_raw(PT_GETLWPLIST, pid, buf, (long)count);
  if (r == -1) { free(buf); return -1; }
  for (int i = 0; i < count; ++i) lwps[i] = (int32_t)buf[i];
  free(buf);
  return count;
#endif
}

/* ---- Register helpers ---- */

#if !defined(MEMDBG_PAL_DEBUG_PS5)

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

#endif /* !MEMDBG_PAL_DEBUG_PS5 */

int pal_debug_get_regs(int pid, int32_t lwp, memdbg_debug_regs_t *regs) {
#if defined(MEMDBG_PAL_DEBUG_PS5)
  return kern_get_regs(pid, (int)lwp, regs) == 0 ? 0 : -1;
#else
  (void)pid;
  struct reg r;
  memset(&r, 0, sizeof(r));
  if (pal_debug_ptrace_raw(PT_GETREGS, (int)lwp, &r, 0) == -1) return -1;
  pal_debug_regs_from_native(&r, regs);
  return 0;
#endif
}

int pal_debug_set_regs(int pid, int32_t lwp, const memdbg_debug_regs_t *regs) {
#if defined(MEMDBG_PAL_DEBUG_PS5)
  return kern_set_regs(pid, (int)lwp, regs) == 0 ? 0 : -1;
#else
  (void)pid;
  struct reg r;
  memset(&r, 0, sizeof(r));
  pal_debug_regs_to_native(regs, &r);
  return (pal_debug_ptrace_raw(PT_SETREGS, (int)lwp, &r, 0) == -1) ? -1 : 0;
#endif
}

int pal_debug_get_fpregs(int pid, int32_t lwp,
                         memdbg_debug_fpregs_t *fpregs) {
  (void)pid;
  if (fpregs == NULL) { errno = EINVAL; return -1; }
#if defined(MEMDBG_PAL_DEBUG_PS5)
  return kern_get_fpregs(pid, (int)lwp, fpregs) == 0 ? 0 : -1;
#elif defined(PT_GETXSTATE_INFO) && defined(PT_GETXSTATE)
  {
    struct ptrace_xstate_info info;
    memset(&info, 0, sizeof(info));
    if (pal_debug_ptrace_raw(PT_GETXSTATE_INFO, (int)lwp, &info,
                             (long)sizeof(info)) == 0 &&
        info.xsave_len > 0U &&
        info.xsave_len <= MEMDBG_DEBUG_FPREGS_MAX) {
      memset(fpregs, 0, sizeof(*fpregs));
      if (pal_debug_ptrace_raw(PT_GETXSTATE, (int)lwp, fpregs->data,
                               (long)info.xsave_len) == 0) {
        fpregs->length = info.xsave_len;
        fpregs->flags = MEMDBG_DEBUG_FPREGS_FLAG_XSTATE;
        return 0;
      }
    }
  }
  /* fall-through to PT_GETFPREGS */
#endif
#if defined(PT_GETFPREGS)
  {
    struct fpreg f;
    memset(&f, 0, sizeof(f));
    if (sizeof(f) > MEMDBG_DEBUG_FPREGS_MAX) { errno = EOVERFLOW; return -1; }
    if (pal_debug_ptrace_raw(PT_GETFPREGS, (int)lwp, &f, 0) == -1) return -1;
    memset(fpregs, 0, sizeof(*fpregs));
    fpregs->length = (uint32_t)sizeof(f);
    memcpy(fpregs->data, &f, sizeof(f));
    return 0;
  }
#elif !defined(MEMDBG_PAL_DEBUG_PS5)
  errno = ENOTSUP;
  return -1;
#endif
}

int pal_debug_set_fpregs(int pid, int32_t lwp,
                         const memdbg_debug_fpregs_t *fpregs) {
  (void)pid;
  if (fpregs == NULL || fpregs->length == 0U ||
      fpregs->length > MEMDBG_DEBUG_FPREGS_MAX) { errno = EINVAL; return -1; }
#if defined(MEMDBG_PAL_DEBUG_PS5)
  return kern_set_fpregs(pid, (int)lwp, fpregs) == 0 ? 0 : -1;
#elif defined(PT_SETXSTATE)
  if ((fpregs->flags & MEMDBG_DEBUG_FPREGS_FLAG_XSTATE) != 0U) {
    return (pal_debug_ptrace_raw(PT_SETXSTATE, (int)lwp,
                                 (void *)fpregs->data,
                                 (long)fpregs->length) == -1) ? -1 : 0;
  }
  /* fall-through */
#endif
#if defined(PT_SETFPREGS) && !defined(MEMDBG_PAL_DEBUG_PS5)
  {
    struct fpreg f;
    if (fpregs->length != sizeof(f)) { errno = EINVAL; return -1; }
    memset(&f, 0, sizeof(f));
    memcpy(&f, fpregs->data, sizeof(f));
    return (pal_debug_ptrace_raw(PT_SETFPREGS, (int)lwp, &f, 0) == -1) ? -1 : 0;
  }
#elif !defined(MEMDBG_PAL_DEBUG_PS5)
  errno = ENOTSUP;
  return -1;
#endif
}

int pal_debug_get_fsgsbase(int pid, int32_t lwp,
                           memdbg_debug_fsgsbase_t *base) {
  (void)pid;
  if (base == NULL) { errno = EINVAL; return -1; }
  memset(base, 0, sizeof(*base));
#if defined(MEMDBG_PAL_DEBUG_PS5)
  return kern_get_fsgsbase(pid, (int)lwp, base) == 0 ? 0 : -1;
#elif defined(PT_GETFSBASE) && defined(PT_GETGSBASE)
  {
    unsigned long fs_base = 0, gs_base = 0;
    if (pal_debug_ptrace_raw(PT_GETFSBASE, (int)lwp, &fs_base, 0) == -1) return -1;
    if (pal_debug_ptrace_raw(PT_GETGSBASE, (int)lwp, &gs_base, 0) == -1) return -1;
    base->fs_base = (uint64_t)fs_base;
    base->gs_base = (uint64_t)gs_base;
    return 0;
  }
#else
  (void)lwp;
  errno = ENOTSUP;
  return -1;
#endif
}

int pal_debug_set_fsgsbase(int pid, int32_t lwp,
                           const memdbg_debug_fsgsbase_t *base) {
  (void)pid;
  if (base == NULL) { errno = EINVAL; return -1; }
#if defined(MEMDBG_PAL_DEBUG_PS5)
  return kern_set_fsgsbase(pid, (int)lwp, base) == 0 ? 0 : -1;
#elif defined(PT_SETFSBASE) && defined(PT_SETGSBASE)
  {
    unsigned long fs_base = (unsigned long)base->fs_base;
    unsigned long gs_base = (unsigned long)base->gs_base;
    if ((uint64_t)fs_base != base->fs_base || (uint64_t)gs_base != base->gs_base) {
      errno = EOVERFLOW; return -1;
    }
    if (pal_debug_ptrace_raw(PT_SETFSBASE, (int)lwp, &fs_base, 0) == -1) return -1;
    if (pal_debug_ptrace_raw(PT_SETGSBASE, (int)lwp, &gs_base, 0) == -1) return -1;
    return 0;
  }
#else
  (void)lwp;
  errno = ENOTSUP;
  return -1;
#endif
}

int pal_debug_get_dbregs(int pid, int32_t lwp,
                         memdbg_debug_dbregs_t *dbregs) {
  (void)pid;
#if defined(MEMDBG_PAL_DEBUG_PS5)
  return kern_get_dbregs(pid, (int)lwp, dbregs) == 0 ? 0 : -1;
#else
  struct dbreg d;
  memset(&d, 0, sizeof(d));
  if (pal_debug_ptrace_raw(PT_GETDBREGS, (int)lwp, &d, 0) == -1) return -1;
  for (int i = 0; i < 16; ++i) dbregs->dr[i] = (uint64_t)d.dr[i];
  return 0;
#endif
}

int pal_debug_set_dbregs(int pid, int32_t lwp,
                         const memdbg_debug_dbregs_t *dbregs) {
  (void)pid;
#if defined(MEMDBG_PAL_DEBUG_PS5)
  return kern_set_dbregs(pid, (int)lwp, dbregs) == 0 ? 0 : -1;
#else
  struct dbreg d;
  memset(&d, 0, sizeof(d));
  for (int i = 0; i < 16; ++i) d.dr[i] = (long)dbregs->dr[i];
  return (pal_debug_ptrace_raw(PT_SETDBREGS, (int)lwp, &d, 0) == -1) ? -1 : 0;
#endif
}

int pal_debug_get_thread_name(int pid, int32_t lwp, char *name,
                              size_t name_len) {
  (void)pid;
  (void)lwp;
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

int pal_debug_get_thread_state(int pid, int32_t lwp, int *state_out) {
  (void)pid;
  if (state_out == NULL) {
    errno = EINVAL;
    return -1;
  }

#ifdef PT_LWPINFO
  {
    struct ptrace_lwpinfo lwpinfo;
    memset(&lwpinfo, 0, sizeof(lwpinfo));
    long r = pal_debug_ptrace_raw(PT_LWPINFO, (int)lwp,
                                  (void *)&lwpinfo, (long)sizeof(lwpinfo));
    if (r == -1) {
      /* LWP is likely running or cannot be queried right now. */
      *state_out = (int)MEMDBG_THREAD_RUNNING;
      return -1;
    }
    if (lwpinfo.pl_flags &
        (PL_FLAG_SCE | PL_FLAG_SCX | PL_FLAG_EXEC | PL_FLAG_FORKED)) {
      /* Thread is stopped at a kernel event (syscall, exec, fork). */
      *state_out = (int)MEMDBG_THREAD_WAITING;
    } else if (lwpinfo.pl_event == PL_EVENT_SIGNAL) {
      /* Stopped by a signal (SIGSTOP, SIGTRAP, etc.) — genuine debugger stop. */
      *state_out = (int)MEMDBG_THREAD_STOPPED;
    } else {
      /* Stopped but not by a signal — kernel-suspended via PT_SUSPEND or
       * a scheduling-level suspend (TDF_SUSPEND). */
      *state_out = (int)MEMDBG_THREAD_SUSPENDED;
    }
    return 0;
  }
#else
  *state_out = (int)MEMDBG_THREAD_UNKNOWN;
  return -1;
#endif
}

int pal_debug_get_thread_stop_info(int pid, int32_t lwp,
                                   int *pl_event, int *stop_signal,
                                   int *pl_flags,
                                   uint64_t *pl_sigmask_lo,
                                   uint64_t *pl_sigmask_hi,
                                   uint64_t *pl_siglist_lo,
                                   uint64_t *pl_siglist_hi) {
  (void)pid;

#ifdef PT_LWPINFO
  {
    struct ptrace_lwpinfo lwpinfo;
    memset(&lwpinfo, 0, sizeof(lwpinfo));
    long r = pal_debug_ptrace_raw(PT_LWPINFO, (int)lwp,
                                  (void *)&lwpinfo, (long)sizeof(lwpinfo));
    if (r == -1) return -1;

    if (pl_event != NULL)
      *pl_event = (int)lwpinfo.pl_event;
    if (pl_flags != NULL)
      *pl_flags = (int)lwpinfo.pl_flags;
    if (stop_signal != NULL) {
      if ((lwpinfo.pl_flags & PL_FLAG_SI) &&
          lwpinfo.pl_event == PL_EVENT_SIGNAL) {
        *stop_signal = (int)lwpinfo.pl_siginfo.si_signo;
      } else {
        *stop_signal = 0;
      }
    }
    /* sigset_t is typically 128 bits (4 x uint32_t) on FreeBSD x86-64.
     * Copy as two uint64_t fields for the wire protocol. */
    if (pl_sigmask_lo != NULL || pl_sigmask_hi != NULL) {
      uint32_t mask[4];
      memcpy(mask, &lwpinfo.pl_sigmask, sizeof(mask));
      if (pl_sigmask_lo != NULL)
        *pl_sigmask_lo = (uint64_t)mask[0] | ((uint64_t)mask[1] << 32);
      if (pl_sigmask_hi != NULL)
        *pl_sigmask_hi = (uint64_t)mask[2] | ((uint64_t)mask[3] << 32);
    }
    if (pl_siglist_lo != NULL || pl_siglist_hi != NULL) {
      uint32_t list[4];
      memcpy(list, &lwpinfo.pl_siglist, sizeof(list));
      if (pl_siglist_lo != NULL)
        *pl_siglist_lo = (uint64_t)list[0] | ((uint64_t)list[1] << 32);
      if (pl_siglist_hi != NULL)
        *pl_siglist_hi = (uint64_t)list[2] | ((uint64_t)list[3] << 32);
    }
    return 0;
  }
#else
  (void)pl_event; (void)stop_signal; (void)pl_flags;
  (void)pl_sigmask_lo; (void)pl_sigmask_hi;
  (void)pl_siglist_lo; (void)pl_siglist_hi;
  return -1;
#endif
}

int pal_debug_get_thread_extra_info(int pid, const int32_t *lwps, uint32_t count,
                                    int *priorities, uint64_t *runtimes_us,
                                    int *pctcpus, int *cpu_ids) {
  if (lwps == NULL || count == 0) {
    errno = EINVAL;
    return -1;
  }

#if defined(MEMDBG_PAL_DEBUG_FREEBSD) || defined(MEMDBG_PAL_DEBUG_CONSOLE)
  int proc_selector = KERN_PROC_PID;
#ifdef KERN_PROC_INC_THREAD
  proc_selector |= KERN_PROC_INC_THREAD;
#endif
  int mib[4] = {CTL_KERN, KERN_PROC, proc_selector, pid};
  size_t len = 0;
  if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) return -1;
  if (len == 0) return -1;

  unsigned char *buf = (unsigned char *)malloc(len);
  if (buf == NULL) return -1;
  if (sysctl(mib, 4, buf, &len, NULL, 0) != 0) { free(buf); return -1; }

  for (size_t off = 0; off + sizeof(int) <= len;) {
    struct kinfo_proc *proc = (struct kinfo_proc *)(void *)(buf + off);
    size_t rs = proc->ki_structsize > 0 ? (size_t)proc->ki_structsize
                                        : sizeof(*proc);
    if (rs < sizeof(int) || off + rs > len) break;

    int32_t tid = (int32_t)proc->ki_tid;
    for (uint32_t i = 0; i < count; ++i) {
      if (lwps[i] != tid) continue;
      if (priorities != NULL)
        priorities[i] = (int)proc->ki_pri.pri_level;
      if (runtimes_us != NULL)
        runtimes_us[i] = (uint64_t)proc->ki_runtime;
      if (pctcpus != NULL)
        pctcpus[i] = (int)(((uint64_t)proc->ki_pctcpu * 100U) / 65536U);
      if (cpu_ids != NULL) {
#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
        const int cpu = proc->ki_oncpu >= 0 ? proc->ki_oncpu
                                            : proc->ki_lastcpu;
#else
        const int cpu = proc->ki_oncpu != 255U ? (int)proc->ki_oncpu
                                               : (int)proc->ki_lastcpu;
#endif
        cpu_ids[i] = cpu >= 0 ? cpu : -1;
      }
      break;
    }
    off += rs;
  }
  free(buf);
  return 0;
#else
  (void)pid; (void)priorities; (void)runtimes_us; (void)pctcpus; (void)cpu_ids;
  return -1;
#endif
}

#elif defined(MEMDBG_PAL_DEBUG_MACOS)

/*
 * macOS implementation.
 * Uses ptrace(PT_ATTACHEXC, ...) for attach / crash notification and
 * Mach task_for_pid + thread_get_state for register access.
 * PT_SYSCALL is not available on macOS, so syscall tracing is not supported.
 */

#include <sys/ptrace.h>
#include <mach/mach.h>
#include <mach/thread_status.h>
#include <mach/mach_init.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <dlfcn.h>
#include <unistd.h>

#ifndef PT_ATTACHEXC
#define PT_ATTACHEXC 14
#endif

bool pal_debug_supported(void) { return true; }
bool pal_debug_fpregs_supported(void) { return false; }
bool pal_debug_fsgsbase_supported(void) { return false; }

long pal_debug_ptrace(int op, int pid, void *addr, long data) {
  return ptrace(op, pid, (caddr_t)addr, (int)data);
}

static void pal_debug_sleep_ms(uint32_t ms) {
  struct timespec ts;
  ts.tv_sec = (time_t)(ms / 1000U);
  ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
  }
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
  /* On macOS, PT_ATTACHEXC attaches and routes exceptions through Mach
   * exception ports. The target receives SIGSTOP. */
  if (ptrace(PT_ATTACHEXC, pid, 0, 0) == -1) return -1;

  for (int i = 0; i < 500; ++i) {
    int status = 0;
    int r = pal_debug_wait(pid, &status, true);
    if (r == 1 && WIFSTOPPED(status)) return 0;
    if (r == -1 && errno != EINTR) break;
    pal_debug_sleep_ms(10U);
  }

  (void)pal_debug_detach(pid);
  errno = ETIMEDOUT;
  return -1;
}

int pal_debug_detach(int pid) {
  return (ptrace(PT_DETACH, pid, 0, 0) == -1) ? -1 : 0;
}

int pal_debug_continue(int pid) {
  return (ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) == -1) ? -1 : 0;
}

int pal_debug_syscall(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_stop(int pid) {
  return (kill((pid_t)pid, SIGSTOP) == 0) ? 0 : -1;
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

/* Helper: convert thread state (macOS) to memdbg_debug_regs_t. */
#if defined(__x86_64__)
static void pal_debug_regs_from_native(const x86_thread_state64_t *src,
                                      memdbg_debug_regs_t *dst) {
  memset(dst, 0, sizeof(*dst));
  dst->r_rax  = (int64_t)src->__rax;
  dst->r_rbx  = (int64_t)src->__rbx;
  dst->r_rcx  = (int64_t)src->__rcx;
  dst->r_rdx  = (int64_t)src->__rdx;
  dst->r_rdi  = (int64_t)src->__rdi;
  dst->r_rsi  = (int64_t)src->__rsi;
  dst->r_rbp  = (int64_t)src->__rbp;
  dst->r_rsp  = (int64_t)src->__rsp;
  dst->r_r8   = (int64_t)src->__r8;
  dst->r_r9   = (int64_t)src->__r9;
  dst->r_r10  = (int64_t)src->__r10;
  dst->r_r11  = (int64_t)src->__r11;
  dst->r_r12  = (int64_t)src->__r12;
  dst->r_r13  = (int64_t)src->__r13;
  dst->r_r14  = (int64_t)src->__r14;
  dst->r_r15  = (int64_t)src->__r15;
  dst->r_rip  = (int64_t)src->__rip;
  dst->r_rflags = (int64_t)src->__rflags;
  dst->r_cs   = (int64_t)src->__cs;
  dst->r_fs   = (uint16_t)src->__fs;
  dst->r_gs   = (uint16_t)src->__gs;
}
#elif defined(__arm64__) || defined(__aarch64__)
static void pal_debug_regs_from_native(const arm_thread_state64_t *src,
                                      memdbg_debug_regs_t *dst) {
  memset(dst, 0, sizeof(*dst));
  /* Map ARM64 x0-x13 to x86-style slots for crash dump utility.
   * The struct __x[] array is accessible even in the opaque layout. */
  dst->r_rax  = (int64_t)src->__x[0];
  dst->r_rbx  = (int64_t)src->__x[1];
  dst->r_rcx  = (int64_t)src->__x[2];
  dst->r_rdx  = (int64_t)src->__x[3];
  dst->r_rdi  = (int64_t)src->__x[4];
  dst->r_rsi  = (int64_t)src->__x[5];
  dst->r_r8   = (int64_t)src->__x[6];
  dst->r_r9   = (int64_t)src->__x[7];
  dst->r_r10  = (int64_t)src->__x[8];
  dst->r_r11  = (int64_t)src->__x[9];
  dst->r_r12  = (int64_t)src->__x[10];
  dst->r_r13  = (int64_t)src->__x[11];
  dst->r_r14  = (int64_t)src->__x[12];
  dst->r_r15  = (int64_t)src->__x[13];
  dst->r_rbp  = (int64_t)__darwin_arm_thread_state64_get_fp(*src);
  dst->r_rsp  = (int64_t)__darwin_arm_thread_state64_get_sp(*src);
  dst->r_rip  = (int64_t)__darwin_arm_thread_state64_get_pc(*src);
  dst->r_rflags = (int64_t)src->__cpsr & 0xffffffff;
  dst->r_cs   = 0;  /* not available on ARM64 */
  dst->r_fs   = 0;
  dst->r_gs   = 0;
}
#endif

int pal_debug_get_regs(int pid, int32_t lwp, memdbg_debug_regs_t *regs) {
  (void)lwp;
  task_t task = MACH_PORT_NULL;
  kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
  if (kr != KERN_SUCCESS) {
    return -1;
  }

  /* Get thread list from the task. */
  thread_act_array_t threads;
  mach_msg_type_number_t thread_count;
  kr = task_threads(task, &threads, &thread_count);
  if (kr != KERN_SUCCESS) {
    mach_port_deallocate(mach_task_self(), task);
    return -1;
  }

  if (thread_count == 0) {
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                       thread_count * sizeof(thread_t));
    mach_port_deallocate(mach_task_self(), task);
    return -1;
  }

  /* Read registers from the first thread (crash thread is typically first). */
#if defined(__x86_64__)
  x86_thread_state64_t state;
  mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
  kr = thread_get_state(threads[0], x86_THREAD_STATE64,
                        (thread_state_t)&state, &state_count);
#elif defined(__arm64__) || defined(__aarch64__)
  arm_thread_state64_t state;
  mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
  kr = thread_get_state(threads[0], ARM_THREAD_STATE64,
                        (thread_state_t)&state, &state_count);
#endif
  if (kr != KERN_SUCCESS) {
    for (mach_msg_type_number_t i = 0; i < thread_count; i++)
      mach_port_deallocate(mach_task_self(), threads[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                       thread_count * sizeof(thread_t));
    mach_port_deallocate(mach_task_self(), task);
    return -1;
  }

  pal_debug_regs_from_native(&state, regs);

  for (mach_msg_type_number_t i = 0; i < thread_count; i++)
    mach_port_deallocate(mach_task_self(), threads[i]);
  vm_deallocate(mach_task_self(), (vm_address_t)threads,
                     thread_count * sizeof(thread_t));
  mach_port_deallocate(mach_task_self(), task);
  return 0;
}

int pal_debug_set_regs(int pid, int32_t lwp, const memdbg_debug_regs_t *regs) {
  (void)pid;
  (void)lwp;
  (void)regs;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_fpregs(int pid, int32_t lwp,
                         memdbg_debug_fpregs_t *fpregs) {
  (void)pid;
  (void)lwp;
  if (fpregs != NULL) memset(fpregs, 0, sizeof(*fpregs));
  errno = ENOTSUP;
  return -1;
}

int pal_debug_set_fpregs(int pid, int32_t lwp,
                         const memdbg_debug_fpregs_t *fpregs) {
  (void)pid;
  (void)lwp;
  (void)fpregs;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_fsgsbase(int pid, int32_t lwp,
                           memdbg_debug_fsgsbase_t *base) {
  (void)pid;
  (void)lwp;
  if (base != NULL) memset(base, 0, sizeof(*base));
  errno = ENOTSUP;
  return -1;
}

int pal_debug_set_fsgsbase(int pid, int32_t lwp,
                           const memdbg_debug_fsgsbase_t *base) {
  (void)pid;
  (void)lwp;
  (void)base;
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

int pal_debug_get_thread_state(int pid, int32_t lwp, int *state_out) {
  (void)pid;
  (void)lwp;
  if (state_out != NULL) *state_out = (int)MEMDBG_THREAD_UNKNOWN;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_stop_info(int pid, int32_t lwp,
                                   int *pl_event, int *stop_signal,
                                   int *pl_flags,
                                   uint64_t *pl_sigmask_lo,
                                   uint64_t *pl_sigmask_hi,
                                   uint64_t *pl_siglist_lo,
                                   uint64_t *pl_siglist_hi) {
  (void)pid; (void)lwp; (void)pl_event; (void)stop_signal; (void)pl_flags;
  (void)pl_sigmask_lo; (void)pl_sigmask_hi;
  (void)pl_siglist_lo; (void)pl_siglist_hi;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_extra_info(int pid, const int32_t *lwps, uint32_t count,
                                    int *priorities, uint64_t *runtimes_us,
                                    int *pctcpus, int *cpu_ids) {
  (void)pid; (void)lwps; (void)count;
  (void)priorities; (void)runtimes_us; (void)pctcpus; (void)cpu_ids;
  errno = ENOTSUP;
  return -1;
}

#else /* Unsupported platform */

bool pal_debug_supported(void) { return false; }
bool pal_debug_fpregs_supported(void) { return false; }
bool pal_debug_fsgsbase_supported(void) { return false; }

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

int pal_debug_syscall(int pid) {
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

int pal_debug_get_fpregs(int pid, int32_t lwp,
                         memdbg_debug_fpregs_t *fpregs) {
  (void)pid;
  (void)lwp;
  if (fpregs != NULL) memset(fpregs, 0, sizeof(*fpregs));
  errno = ENOTSUP;
  return -1;
}

int pal_debug_set_fpregs(int pid, int32_t lwp,
                         const memdbg_debug_fpregs_t *fpregs) {
  (void)pid;
  (void)lwp;
  (void)fpregs;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_fsgsbase(int pid, int32_t lwp,
                           memdbg_debug_fsgsbase_t *base) {
  (void)pid;
  (void)lwp;
  if (base != NULL) memset(base, 0, sizeof(*base));
  errno = ENOTSUP;
  return -1;
}

int pal_debug_set_fsgsbase(int pid, int32_t lwp,
                           const memdbg_debug_fsgsbase_t *base) {
  (void)pid;
  (void)lwp;
  (void)base;
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

int pal_debug_get_thread_state(int pid, int32_t lwp, int *state_out) {
  (void)pid;
  (void)lwp;
  if (state_out != NULL) *state_out = (int)MEMDBG_THREAD_UNKNOWN;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_stop_info(int pid, int32_t lwp,
                                   int *pl_event, int *stop_signal,
                                   int *pl_flags,
                                   uint64_t *pl_sigmask_lo,
                                   uint64_t *pl_sigmask_hi,
                                   uint64_t *pl_siglist_lo,
                                   uint64_t *pl_siglist_hi) {
  (void)pid; (void)lwp; (void)pl_event; (void)stop_signal; (void)pl_flags;
  (void)pl_sigmask_lo; (void)pl_sigmask_hi;
  (void)pl_siglist_lo; (void)pl_siglist_hi;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_extra_info(int pid, const int32_t *lwps, uint32_t count,
                                    int *priorities, uint64_t *runtimes_us,
                                    int *pctcpus, int *cpu_ids) {
  (void)pid; (void)lwps; (void)count;
  (void)priorities; (void)runtimes_us; (void)pctcpus; (void)cpu_ids;
  errno = ENOTSUP;
  return -1;
}

#endif
