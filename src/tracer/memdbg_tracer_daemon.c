/*
 * memDBG - Tracer daemon module implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/tracer/memdbg_tracer_daemon.h"
#include "memdbg/tracer/memdbg_tracer.h"
#include "memdbg/pal/pal_debug.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Ring buffer for events (power-of-2 size). */
#define TRACER_DAEMON_RING_SIZE 8192U
#define TRACER_DAEMON_RING_MASK (TRACER_DAEMON_RING_SIZE - 1U)

/* ------------------------------------------------------------------ */
/*  State                                                             */
/* ------------------------------------------------------------------ */

static pthread_mutex_t  g_mtx       = PTHREAD_MUTEX_INITIALIZER;
static pthread_t        g_thread;
static atomic_bool     g_running       = false;
static atomic_bool     g_starting      = false;
static atomic_bool     g_stop_req      = false;
static bool            g_thread_created = false;

/* Ring buffer — single producer (tracer thread), single consumer (poll).
 * head/tail use C11 atomic with release/acquire ordering so that the
 * pattern is correct even on weakly-ordered CPUs (ARM in PS4/PS5). */
static memdbg_tracer_event_t g_ring[TRACER_DAEMON_RING_SIZE];
static atomic_uint          g_head = 0;  /* producer index */
static atomic_uint          g_tail = 0;  /* consumer index */
static atomic_uint          g_total_events = 0;

/* Status fields.  Most are also covered by g_mtx; atomics provide an
 * additional safety net for lock-free reads (e.g. g_stop_req in the
 * tracer thread hot loop). */
static atomic_int  g_state        = MEMDBG_TRACER_STATE_IDLE;
static atomic_int  g_crash_signal = 0;
static char        g_dump_path[256] = "";
static uint64_t    g_start_time_ns  = 0;
static int32_t     g_target_pid     = 0;

/* ------------------------------------------------------------------ */
/*  Timestamp                                                         */
/* ------------------------------------------------------------------ */

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/*  Ring buffer helpers (lock-free only when g_mtx is held for state) */
/* ------------------------------------------------------------------ */

static void ring_push(const memdbg_tracer_event_t *ev) {
  uint32_t h = atomic_load_explicit(&g_head, memory_order_relaxed);
  g_ring[h & TRACER_DAEMON_RING_MASK] = *ev;
  atomic_store_explicit(&g_head, h + 1, memory_order_release);
  atomic_fetch_add_explicit(&g_total_events, 1U, memory_order_relaxed);
  /* Advance tail if we wrapped (consumer index read with acquire). */
  uint32_t t = atomic_load_explicit(&g_tail, memory_order_acquire);
  uint32_t new_head = atomic_load_explicit(&g_head, memory_order_relaxed);
  if (new_head - t > TRACER_DAEMON_RING_SIZE) {
    atomic_store_explicit(&g_tail, new_head - TRACER_DAEMON_RING_SIZE,
                          memory_order_release);
  }
}

static uint32_t ring_pop(memdbg_tracer_event_t *out, uint32_t max_count) {
  uint32_t t = atomic_load_explicit(&g_tail, memory_order_relaxed);
  uint32_t h = atomic_load_explicit(&g_head, memory_order_acquire);
  uint32_t avail = h - t;
  if (avail == 0 || max_count == 0) return 0;
  uint32_t n = avail < max_count ? avail : max_count;
  for (uint32_t i = 0; i < n; i++)
    out[i] = g_ring[(t + i) & TRACER_DAEMON_RING_MASK];
  atomic_store_explicit(&g_tail, t + n, memory_order_release);
  return n;
}

/* ------------------------------------------------------------------ */
/*  Tracer thread                                                      */
/* ------------------------------------------------------------------ */

static void write_crash_dump(int pid, int signal);

static void *tracer_thread_fn(void *arg) {
  (void)arg;

  int32_t pid = g_target_pid;
  bool attached = false;

  /* 1. Attach using pal_debug */
  if (pal_debug_attach((int)pid) != 0) {
    pthread_mutex_lock(&g_mtx);
    atomic_store(&g_state, MEMDBG_TRACER_STATE_STOPPED);
    atomic_store(&g_running, false);
    atomic_store(&g_starting, false);
    pthread_mutex_unlock(&g_mtx);
    return NULL;
  }
  attached = true;

  /* A detach can arrive while the attach request is still completing. */
  if (atomic_load(&g_stop_req)) goto done;

  /* Try full syscall tracing if supported. */
  bool has_syscall = false;
#if defined(PT_SYSCALL)
  if (pal_debug_syscall((int)pid) == 0)
    has_syscall = true;
#endif

  /* PT_ATTACH stops the target.  If syscall tracing is unavailable, resume
   * it explicitly before entering the crash-only wait loop. */
  if (!has_syscall && pal_debug_continue((int)pid) != 0) {
    goto done;
  }
  if (g_stop_req) goto done;

  pthread_mutex_lock(&g_mtx);
  g_state = MEMDBG_TRACER_STATE_RUNNING;
  g_running = true;
  g_starting = false;
  g_start_time_ns = now_ns();
  pthread_mutex_unlock(&g_mtx);

  while (!g_stop_req) {
    int status = 0;
    int r = pal_debug_wait((int)pid, &status, false);
    if (r == -1) {
      if (errno == EINTR) continue;
      break;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      int sig = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
      memdbg_tracer_event_t ev;
      memset(&ev, 0, sizeof(ev));
      ev.event_type = MEMDBG_TRACER_EVENT_CRASH;
      ev.signal = sig;
      ev.timestamp_ns = now_ns();
      ring_push(&ev);

      /* Generate crash dump */
      write_crash_dump((int)pid, sig);

      pthread_mutex_lock(&g_mtx);
      if (WIFSIGNALED(status)) {
        g_state = MEMDBG_TRACER_STATE_CRASHED;
        g_crash_signal = sig;
      } else {
        g_state = MEMDBG_TRACER_STATE_EXITED;
      }
      g_running = false;
      pthread_mutex_unlock(&g_mtx);
      goto done;
    }

    if (!WIFSTOPPED(status)) continue;

    int sig = WSTOPSIG(status);

    if (has_syscall) {
      /* Check for syscall entry/exit via PT_LWPINFO. */
#if defined(PT_LWPINFO)
      {
        int32_t lwps[256];
        int nlwps = pal_debug_get_thread_list((int)pid, lwps, 256);
        struct ptrace_lwpinfo lwpinfo;
        memset(&lwpinfo, 0, sizeof(lwpinfo));
        if (nlwps > 0 &&
            pal_debug_ptrace(PT_LWPINFO, (int)lwps[0],
                            (void *)&lwpinfo,
                            (long)sizeof(lwpinfo)) == 0) {
          if (lwpinfo.pl_flags & PL_FLAG_SCE) {
            memdbg_debug_regs_t regs;
            if (pal_debug_get_regs((int)pid, lwps[0], &regs) == 0) {
              memdbg_tracer_event_t ev;
              memset(&ev, 0, sizeof(ev));
              ev.event_type = MEMDBG_TRACER_EVENT_SYSCALL_ENTRY;
              ev.lwp = (uint32_t)lwps[0];
              ev.syscall_no = (uint32_t)regs.r_rax;
              ev.args[0] = (uint64_t)regs.r_rdi;
              ev.args[1] = (uint64_t)regs.r_rsi;
              ev.args[2] = (uint64_t)regs.r_rdx;
              ev.args[3] = (uint64_t)regs.r_r10;
              ev.args[4] = (uint64_t)regs.r_r8;
              ev.args[5] = (uint64_t)regs.r_r9;
              ev.timestamp_ns = now_ns();
              ring_push(&ev);
            }
            pal_debug_syscall((int)pid);
            continue;
          }
          if (lwpinfo.pl_flags & PL_FLAG_SCX) {
            memdbg_debug_regs_t regs;
            if (pal_debug_get_regs((int)pid, lwps[0], &regs) == 0) {
              memdbg_tracer_event_t ev;
              memset(&ev, 0, sizeof(ev));
              ev.event_type = MEMDBG_TRACER_EVENT_SYSCALL_EXIT;
              ev.lwp = (uint32_t)lwps[0];
              ev.syscall_ret = regs.r_rax;
              ev.timestamp_ns = now_ns();
              ring_push(&ev);
            }
            pal_debug_syscall((int)pid);
            continue;
          }
          if (lwpinfo.pl_event == PL_EVENT_SIGNAL)
            sig = (int)lwpinfo.pl_siginfo.si_signo;
        }
      }
#endif
    }

    /* Check for crash signals. */
    {
      int crash_sigs[] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGSYS, 0};
      bool is_crash = false;
      for (int *sp = crash_sigs; *sp; sp++) {
        if (sig == *sp) { is_crash = true; break; }
      }

      if (is_crash) {
        memdbg_tracer_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.event_type = MEMDBG_TRACER_EVENT_CRASH;
        ev.signal = sig;
        ev.timestamp_ns = now_ns();
        ring_push(&ev);

        write_crash_dump((int)pid, sig);

        pthread_mutex_lock(&g_mtx);
        g_state = MEMDBG_TRACER_STATE_CRASHED;
        g_crash_signal = sig;
        g_running = false;
        pthread_mutex_unlock(&g_mtx);
        goto done;
      }

      /* Non-crash signal — record and continue. */
      {
        memdbg_tracer_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.event_type = MEMDBG_TRACER_EVENT_SIGNAL;
        ev.signal = sig;
        ev.timestamp_ns = now_ns();
        ring_push(&ev);
      }

      if (has_syscall)
        pal_debug_syscall((int)pid);
      else
        pal_debug_continue((int)pid);
    }
  }

done:
  if (attached) (void)pal_debug_detach((int)pid);
  pthread_mutex_lock(&g_mtx);
  if (g_state != MEMDBG_TRACER_STATE_CRASHED &&
      g_state != MEMDBG_TRACER_STATE_EXITED) {
    g_state = MEMDBG_TRACER_STATE_STOPPED;
  }
  g_running = false;
  g_starting = false;
  pthread_mutex_unlock(&g_mtx);
  return NULL;
}

/* Helper: write a simple crash dump file. */
static void write_crash_dump(int pid, int signal) {
  char path[256];
  if (g_dump_path[0]) {
    snprintf(path, sizeof(path), "%s", g_dump_path);
  } else {
    snprintf(path, sizeof(path), "crash_%d.json", pid);
  }

  /* Push the dump path into g_dump_path so the status response is useful. */
  pthread_mutex_lock(&g_mtx);
  snprintf(g_dump_path, sizeof(g_dump_path), "%s", path);
  pthread_mutex_unlock(&g_mtx);

  FILE *fp = fopen(path, "w");
  if (!fp) return;

  fprintf(fp, "{\n");
  fprintf(fp, "  \"version\": 1,\n");
  fprintf(fp, "  \"timestamp_ns\": %llu,\n", (unsigned long long)now_ns());
  fprintf(fp, "  \"process\": { \"pid\": %d },\n", pid);
  fprintf(fp, "  \"crash\": { \"signal\": %d },\n", signal);
  fprintf(fp, "  \"events_total\": %u\n", (unsigned)g_total_events);
  fprintf(fp, "}\n");
  fclose(fp);
}

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

bool memdbg_tracer_daemon_available(void) {
  return pal_debug_supported();
}

memdbg_status_t memdbg_tracer_daemon_start(int32_t pid, const char *dump_path) {
  if (pid <= 0) return MEMDBG_ERR_PARAM;
  if (!pal_debug_supported()) return MEMDBG_ERR_UNSUPPORTED;

  pthread_mutex_lock(&g_mtx);
  if (g_running || g_starting) {
    pthread_mutex_unlock(&g_mtx);
    return MEMDBG_ERR_STATE;
  }
  const bool reap_previous = g_thread_created;
  pthread_mutex_unlock(&g_mtx);

  /* Reap a completed tracer before reusing the static pthread handle. */
  if (reap_previous) {
    (void)pthread_join(g_thread, NULL);
    pthread_mutex_lock(&g_mtx);
    g_thread_created = false;
    pthread_mutex_unlock(&g_mtx);
  }

  pthread_mutex_lock(&g_mtx);
  /* Reset state. */
  g_head = 0;
  g_tail = 0;
  g_total_events = 0;
  g_stop_req = false;
  g_state = MEMDBG_TRACER_STATE_STARTING;
  g_crash_signal = 0;
  if (dump_path && dump_path[0])
    snprintf(g_dump_path, sizeof(g_dump_path), "%s", dump_path);
  else
    g_dump_path[0] = '\0';
  g_target_pid = pid;
  g_starting = true;
  pthread_mutex_unlock(&g_mtx);

  /* Spawn the tracer thread. */
  if (pthread_create(&g_thread, NULL, tracer_thread_fn, NULL) != 0) {
    pthread_mutex_lock(&g_mtx);
    g_running = false;
    g_starting = false;
    g_state = MEMDBG_TRACER_STATE_STOPPED;
    pthread_mutex_unlock(&g_mtx);
    return MEMDBG_ERR_NOMEM;
  }

  pthread_mutex_lock(&g_mtx);
  g_thread_created = true;
  pthread_mutex_unlock(&g_mtx);

  return MEMDBG_OK;
}

void memdbg_tracer_daemon_stop(void) {
  pthread_mutex_lock(&g_mtx);
  const bool wake_target = g_running;
  const bool join_thread = g_thread_created;
  const int32_t target_pid = g_target_pid;
  g_stop_req = true;
  pthread_mutex_unlock(&g_mtx);

  if (wake_target) {
    /* Signal the target process to wake up the tracer thread. */
    if (target_pid > 0) {
      (void)kill((pid_t)target_pid, SIGSTOP);
    }
  }
  if (join_thread) {
    pthread_join(g_thread, NULL);
  }

  pthread_mutex_lock(&g_mtx);
  g_thread_created = false;
  g_starting = false;
  g_running = false;
  g_state = MEMDBG_TRACER_STATE_STOPPED;
  g_target_pid = 0;
  pthread_mutex_unlock(&g_mtx);
}

bool memdbg_tracer_daemon_is_running(void) {
  pthread_mutex_lock(&g_mtx);
  bool r = g_running;
  pthread_mutex_unlock(&g_mtx);
  return r;
}

uint32_t memdbg_tracer_daemon_poll_events(memdbg_tracer_event_t *out,
                                          uint32_t max_count) {
  return ring_pop(out, max_count);
}

void memdbg_tracer_daemon_status(memdbg_tracer_status_response_t *out) {
  memset(out, 0, sizeof(*out));
  pthread_mutex_lock(&g_mtx);
  out->state = g_state;
  out->events_total = g_total_events;
  out->crash_signal = g_crash_signal;
  out->start_time_ns = g_start_time_ns;
  out->elapsed_ns = g_start_time_ns ? (now_ns() - g_start_time_ns) : 0;
  snprintf(out->dump_path, sizeof(out->dump_path), "%s",
           g_dump_path[0] ? g_dump_path : "");
  pthread_mutex_unlock(&g_mtx);
}
