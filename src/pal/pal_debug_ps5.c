/*
 * memDBG - PAL: PS5 kernel-direct debug register helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Reads/writes registers, dbregs, fpregs, and fsgsbase directly from kernel
 * PCB and trapframe via kernel_copyout/kernel_copyin, bypassing ptrace which is
 * unreliable on some PS5 firmware versions.
 */

#include "memdbg/pal/pal_debug_ps5.h"
#include "memdbg/pal/pal_kernel_fast.h"

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)

#include <ps5/kernel.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int debug_kernel_copyout(intptr_t source, void *destination,
                                size_t length) {
  return memdbg_kernel_fast_available()
             ? memdbg_kernel_copyout_fast(source, destination, length)
             : kernel_copyout(source, destination, length);
}

static int debug_kernel_copyin(const void *source, intptr_t destination,
                               size_t length) {
  return memdbg_kernel_fast_available()
             ? memdbg_kernel_copyin_fast(source, destination, length)
             : kernel_copyin(source, destination, length);
}

static intptr_t debug_kernel_get_proc(pid_t pid) {
  return memdbg_kernel_fast_available()
             ? memdbg_kernel_get_proc_fast(pid)
             : kernel_get_proc(pid);
}

#define kernel_copyout debug_kernel_copyout
#define kernel_copyin debug_kernel_copyin
#define kernel_get_proc debug_kernel_get_proc

/* ---- Kernel thread address resolution (with cache) ---- */

#define KR_THR_CACHE_N 8
static struct { int32_t pid; int32_t lwpid; uint64_t kthread; } kr_thr_cache[KR_THR_CACHE_N];
static int kr_thr_cache_next = 0;
static pthread_mutex_t kr_thr_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

void kern_thread_cache_flush(void) {
  (void)pthread_mutex_lock(&kr_thr_cache_mutex);
  for (int i = 0; i < KR_THR_CACHE_N; i++) {
    kr_thr_cache[i].pid = 0; kr_thr_cache[i].lwpid = 0; kr_thr_cache[i].kthread = 0;
  }
  kr_thr_cache_next = 0;
  (void)pthread_mutex_unlock(&kr_thr_cache_mutex);
}

intptr_t kern_thread_addr(int pid, int lwpid) {
  uint64_t cached = 0U;
  (void)pthread_mutex_lock(&kr_thr_cache_mutex);
  for (int i = 0; i < KR_THR_CACHE_N; i++) {
    if (kr_thr_cache[i].pid == (int32_t)pid &&
        kr_thr_cache[i].lwpid == (int32_t)lwpid &&
        kr_thr_cache[i].kthread != 0) {
      cached = kr_thr_cache[i].kthread;
      break;
    }
  }
  (void)pthread_mutex_unlock(&kr_thr_cache_mutex);
  if (cached != 0U) {
    uint32_t v = 0;
    if (kernel_copyout((intptr_t)(cached + 0x9c), &v, 4) == 0 &&
        (int32_t)v == (int32_t)lwpid)
      return (intptr_t)cached;
    (void)pthread_mutex_lock(&kr_thr_cache_mutex);
    for (int i = 0; i < KR_THR_CACHE_N; ++i) {
      if (kr_thr_cache[i].kthread == cached) {
        kr_thr_cache[i].pid = 0;
        kr_thr_cache[i].lwpid = 0;
        kr_thr_cache[i].kthread = 0;
      }
    }
    (void)pthread_mutex_unlock(&kr_thr_cache_mutex);
  }

  intptr_t kproc = kernel_get_proc((pid_t)pid);
  if (!kproc) return 0;

  uint8_t chain_hdr[0x30];
  if (kernel_copyout(kproc + 0x10, chain_hdr, 0x30) != 0) return 0;
  intptr_t kthread = *(intptr_t *)chain_hdr;

  uint8_t tbuf[0x680];
  while (kthread) {
    if (kernel_copyout((intptr_t)kthread, tbuf, 0x680) != 0) return 0;
    if (*(uint32_t *)(tbuf + 0x9c) == (uint32_t)lwpid) {
      (void)pthread_mutex_lock(&kr_thr_cache_mutex);
      kr_thr_cache[kr_thr_cache_next].pid     = (int32_t)pid;
      kr_thr_cache[kr_thr_cache_next].lwpid   = (int32_t)lwpid;
      kr_thr_cache[kr_thr_cache_next].kthread = (uint64_t)kthread;
      kr_thr_cache_next = (kr_thr_cache_next + 1) % KR_THR_CACHE_N;
      (void)pthread_mutex_unlock(&kr_thr_cache_mutex);
      return kthread;
    }
    kthread = *(intptr_t *)(tbuf + 0x10);
  }
  return 0;
}

/* ---- Debug registers (PCB direct access) ---- */

int kern_get_dbregs(int pid, int lwpid, memdbg_debug_dbregs_t *dbregs_out) {
  if (pid == 0 || !dbregs_out) return 1;

  intptr_t kthread = kern_thread_addr(pid, lwpid);
  if (!kthread) return 6;

  intptr_t pcb_addr;
  if (kernel_copyout((intptr_t)(kthread + 0x3f8), &pcb_addr, 8) != 0) return 1;

  uint8_t pcb_buf[0x178];
  if (kernel_copyout((intptr_t)pcb_addr, pcb_buf, 0x178) != 0) return 1;

  memset(dbregs_out, 0, sizeof(*dbregs_out));
  dbregs_out->dr[0]  = *(uint64_t *)(pcb_buf + 0x78);
  dbregs_out->dr[1]  = *(uint64_t *)(pcb_buf + 0x80);
  dbregs_out->dr[2]  = *(uint64_t *)(pcb_buf + 0x88);
  dbregs_out->dr[3]  = *(uint64_t *)(pcb_buf + 0x90);
  dbregs_out->dr[6]  = *(uint64_t *)(pcb_buf + 0x98);
  dbregs_out->dr[7]  = *(uint64_t *)(pcb_buf + 0xa0);
  return 0;
}

int kern_set_dbregs(int pid, int lwpid, const memdbg_debug_dbregs_t *dbregs) {
  if (pid == 0 || !dbregs) return 1;

  intptr_t kthread = kern_thread_addr(pid, lwpid);
  if (!kthread) return 6;

  intptr_t pcb_addr;
  if (kernel_copyout((intptr_t)(kthread + 0x3f8), &pcb_addr, 8) != 0) return 1;

  uint8_t pcb_buf[0x178];
  if (kernel_copyout((intptr_t)pcb_addr, pcb_buf, 0x178) != 0) return 1;

  *(uint64_t *)(pcb_buf + 0x78) = dbregs->dr[0];
  *(uint64_t *)(pcb_buf + 0x80) = dbregs->dr[1];
  *(uint64_t *)(pcb_buf + 0x88) = dbregs->dr[2];
  *(uint64_t *)(pcb_buf + 0x90) = dbregs->dr[3];
  *(uint64_t *)(pcb_buf + 0x98) = dbregs->dr[6];
  *(uint64_t *)(pcb_buf + 0xa0) = dbregs->dr[7];

  return (kernel_copyin(pcb_buf, (intptr_t)pcb_addr, 0x178) != 0) ? 1 : 0;
}

/* ---- GP registers via kernel trapframe ---- */

int kern_get_regs(int pid, int lwpid, memdbg_debug_regs_t *regs_out) {
  if (pid == 0 || !regs_out) return 1;

  intptr_t kthread = kern_thread_addr(pid, lwpid);
  if (!kthread) return 1;

  intptr_t frame_addr;
  if (kernel_copyout((intptr_t)(kthread + 0x460), &frame_addr, 8) != 0) return 1;

  uint8_t fbuf[0x110];
  memset(fbuf, 0, 0x110);
  if (kernel_copyout((intptr_t)frame_addr, fbuf, 0x110) != 0) return 1;

  memset(regs_out, 0, sizeof(*regs_out));
  regs_out->r_r15     = *(int64_t *)(fbuf + 0x70);
  regs_out->r_r14     = *(int64_t *)(fbuf + 0x68);
  regs_out->r_r13     = *(int64_t *)(fbuf + 0x60);
  regs_out->r_r12     = *(int64_t *)(fbuf + 0x58);
  regs_out->r_r11     = *(int64_t *)(fbuf + 0x50);
  regs_out->r_r10     = *(int64_t *)(fbuf + 0x48);
  regs_out->r_r9      = *(int64_t *)(fbuf + 0x28);
  regs_out->r_r8      = *(int64_t *)(fbuf + 0x20);
  regs_out->r_rdi     = *(int64_t *)(fbuf + 0x00);
  regs_out->r_rsi     = *(int64_t *)(fbuf + 0x08);
  regs_out->r_rbp     = *(int64_t *)(fbuf + 0x40);
  regs_out->r_rbx     = *(int64_t *)(fbuf + 0x38);
  regs_out->r_rdx     = *(int64_t *)(fbuf + 0x10);
  regs_out->r_rcx     = *(int64_t *)(fbuf + 0x18);
  regs_out->r_rax     = *(int64_t *)(fbuf + 0x30);
  regs_out->r_trapno  = *(uint32_t *)(fbuf + 0x78);
  regs_out->r_fs      = *(uint16_t *)(fbuf + 0x7c);
  regs_out->r_gs      = *(uint16_t *)(fbuf + 0x7e);
  regs_out->r_err     = *(uint32_t *)(fbuf + 0xa0);
  regs_out->r_es      = *(uint16_t *)(fbuf + 0x8c);
  regs_out->r_ds      = *(uint16_t *)(fbuf + 0x8e);
  regs_out->r_rip     = *(int64_t *)(fbuf + 0xe8);
  regs_out->r_cs      = *(int64_t *)(fbuf + 0x100);
  regs_out->r_rflags  = (int64_t)*(uint32_t *)(fbuf + 0xe0);
  regs_out->r_rsp     = *(int64_t *)(fbuf + 0xf0);
  regs_out->r_ss      = *(int64_t *)(fbuf + 0xf8);
  return 0;
}

int kern_set_regs(int pid, int lwpid, const memdbg_debug_regs_t *regs) {
  if (pid == 0 || !regs) return 1;

  intptr_t kthread = kern_thread_addr(pid, lwpid);
  if (!kthread) return 1;

  intptr_t frame_addr;
  if (kernel_copyout((intptr_t)(kthread + 0x460), &frame_addr, 8) != 0) return 1;

  uint8_t fbuf[0x110];
  memset(fbuf, 0, 0x110);
  if (kernel_copyout((intptr_t)frame_addr, fbuf, 0x110) != 0) return 1;

  *(int64_t *)(fbuf + 0x70) = regs->r_r15;
  *(int64_t *)(fbuf + 0x68) = regs->r_r14;
  *(int64_t *)(fbuf + 0x60) = regs->r_r13;
  *(int64_t *)(fbuf + 0x58) = regs->r_r12;
  *(int64_t *)(fbuf + 0x50) = regs->r_r11;
  *(int64_t *)(fbuf + 0x48) = regs->r_r10;
  *(int64_t *)(fbuf + 0x28) = regs->r_r9;
  *(int64_t *)(fbuf + 0x20) = regs->r_r8;
  *(int64_t *)(fbuf + 0x00) = regs->r_rdi;
  *(int64_t *)(fbuf + 0x08) = regs->r_rsi;
  *(int64_t *)(fbuf + 0x40) = regs->r_rbp;
  *(int64_t *)(fbuf + 0x38) = regs->r_rbx;
  *(int64_t *)(fbuf + 0x10) = regs->r_rdx;
  *(int64_t *)(fbuf + 0x18) = regs->r_rcx;
  *(int64_t *)(fbuf + 0x30) = regs->r_rax;
  *(uint32_t *)(fbuf + 0x78) = regs->r_trapno;
  *(uint16_t *)(fbuf + 0x7c) = regs->r_fs;
  *(uint16_t *)(fbuf + 0x7e) = regs->r_gs;
  *(uint32_t *)(fbuf + 0xa0) = regs->r_err;
  *(uint16_t *)(fbuf + 0x8c) = regs->r_es;
  *(uint16_t *)(fbuf + 0x8e) = regs->r_ds;
  *(int64_t *)(fbuf + 0xe8) = regs->r_rip;
  *(int64_t *)(fbuf + 0x100) = regs->r_cs;
  *(uint32_t *)(fbuf + 0xe0) = (uint32_t)regs->r_rflags;
  *(int64_t *)(fbuf + 0xf0) = regs->r_rsp;
  *(int64_t *)(fbuf + 0xf8) = regs->r_ss;

  return (kernel_copyin(fbuf, (intptr_t)frame_addr, 0x110) != 0) ? 1 : 0;
}

/* ---- FPU registers via PCB -> kfpu ---- */

int kern_get_fpregs(int pid, int lwpid, memdbg_debug_fpregs_t *fpregs_out) {
  if (pid == 0 || !fpregs_out) return 1;

  intptr_t kthread = kern_thread_addr(pid, lwpid);
  if (!kthread) return 6;

  intptr_t pcb_addr;
  if (kernel_copyout((intptr_t)(kthread + 0x3f8), &pcb_addr, 8) != 0) return 1;

  intptr_t kfpu_addr;
  if (kernel_copyout((intptr_t)(pcb_addr + 0x148), &kfpu_addr, 8) != 0) return 1;
  if (!kfpu_addr) return 1;

  memset(fpregs_out, 0, sizeof(*fpregs_out));
  if (kernel_copyout((intptr_t)kfpu_addr, fpregs_out->data, 0x340) != 0) return 1;
  fpregs_out->length = 0x340;
  fpregs_out->flags  = 0;
  return 0;
}

int kern_set_fpregs(int pid, int lwpid, const memdbg_debug_fpregs_t *fpregs) {
  if (pid == 0 || !fpregs || fpregs->length == 0 || fpregs->length > MEMDBG_DEBUG_FPREGS_MAX) return 1;

  intptr_t kthread = kern_thread_addr(pid, lwpid);
  if (!kthread) return 6;

  intptr_t pcb_addr;
  if (kernel_copyout((intptr_t)(kthread + 0x3f8), &pcb_addr, 8) != 0) return 1;

  intptr_t kfpu_addr;
  if (kernel_copyout((intptr_t)(pcb_addr + 0x148), &kfpu_addr, 8) != 0) return 1;
  if (!kfpu_addr) return 1;

  return (kernel_copyin(fpregs->data, (intptr_t)kfpu_addr, 0x340) != 0) ? 1 : 0;
}

/* ---- FS/GS base via PCB ---- */

int kern_get_fsgsbase(int pid, int lwpid, memdbg_debug_fsgsbase_t *base_out) {
  if (pid == 0 || !base_out) return 1;

  intptr_t kthread = kern_thread_addr(pid, lwpid);
  if (!kthread) return 6;

  intptr_t pcb_addr;
  if (kernel_copyout((intptr_t)(kthread + 0x3f8), &pcb_addr, 8) != 0) return 1;

  memset(base_out, 0, sizeof(*base_out));
  if (kernel_copyout((intptr_t)(pcb_addr + 0x40), base_out, 16) != 0) return 1;
  return 0;
}

int kern_set_fsgsbase(int pid, int lwpid, const memdbg_debug_fsgsbase_t *base) {
  if (pid == 0 || !base) return 1;

  intptr_t kthread = kern_thread_addr(pid, lwpid);
  if (!kthread) return 6;

  intptr_t pcb_addr;
  if (kernel_copyout((intptr_t)(kthread + 0x3f8), &pcb_addr, 8) != 0) return 1;

  return (kernel_copyin(base, (intptr_t)(pcb_addr + 0x40), 16) != 0) ? 1 : 0;
}

/* ---- Thread list via kproc thread chain ---- */

int kern_get_thread_list(int pid, int32_t *lwps, int max_count) {
  if (pid == 0 || !lwps || max_count <= 0) return -1;

  intptr_t kproc = kernel_get_proc((pid_t)pid);
  if (!kproc) return -1;

  uint8_t chain_hdr[0x30];
  if (kernel_copyout(kproc + 0x10, chain_hdr, 0x30) != 0) return -1;
  intptr_t kthread = *(intptr_t *)chain_hdr;

  int count = 0;
  uint8_t tbuf[0x680];
  while (kthread && count < max_count) {
    if (count >= 16384) break;
    if (kernel_copyout((intptr_t)kthread, tbuf, 0x680) != 0) break;
    lwps[count++] = (int32_t)*(uint32_t *)(tbuf + 0x9c);
    kthread = *(intptr_t *)(tbuf + 0x10);
  }
  return count;
}

#else /* !PS5 — stubs */

void kern_thread_cache_flush(void) {}
intptr_t kern_thread_addr(int pid, int lwpid) { (void)pid; (void)lwpid; return 0; }
int kern_get_dbregs(int pid, int lwpid, memdbg_debug_dbregs_t *dbregs_out) { (void)pid; (void)lwpid; (void)dbregs_out; return -1; }
int kern_set_dbregs(int pid, int lwpid, const memdbg_debug_dbregs_t *dbregs) { (void)pid; (void)lwpid; (void)dbregs; return -1; }
int kern_get_regs(int pid, int lwpid, memdbg_debug_regs_t *regs_out) { (void)pid; (void)lwpid; (void)regs_out; return -1; }
int kern_set_regs(int pid, int lwpid, const memdbg_debug_regs_t *regs) { (void)pid; (void)lwpid; (void)regs; return -1; }
int kern_get_fpregs(int pid, int lwpid, memdbg_debug_fpregs_t *fpregs_out) { (void)pid; (void)lwpid; (void)fpregs_out; return -1; }
int kern_set_fpregs(int pid, int lwpid, const memdbg_debug_fpregs_t *fpregs) { (void)pid; (void)lwpid; (void)fpregs; return -1; }
int kern_get_fsgsbase(int pid, int lwpid, memdbg_debug_fsgsbase_t *base_out) { (void)pid; (void)lwpid; (void)base_out; return -1; }
int kern_set_fsgsbase(int pid, int lwpid, const memdbg_debug_fsgsbase_t *base) { (void)pid; (void)lwpid; (void)base; return -1; }
int kern_get_thread_list(int pid, int32_t *lwps, int max_count) { (void)pid; (void)lwps; (void)max_count; return -1; }

#endif /* PS5 */
