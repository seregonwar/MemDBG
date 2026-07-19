/*
 * memDBG - Syscall tracer & crash dump implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/tracer/memdbg_tracer.h"

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/pal/pal_debug.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

/* ------------------------------------------------------------------ */
/*  Ring buffer (lock-free, single producer, single consumer)         */
/* ------------------------------------------------------------------ */

struct ring {
  memdbg_tracer_event_t *slots;
  uint32_t               mask;     /* capacity - 1 (must be power of 2) */
  uint32_t               head;     /* producer writes here              */
  volatile uint32_t      tail;     /* consumer reads up to here         */
};

static bool ring_init(struct ring *r, uint32_t capacity) {
  /* capacity must be a power of two */
  if (capacity < 2 || (capacity & (capacity - 1)) != 0) return false;
  r->slots = (memdbg_tracer_event_t *)calloc(capacity, sizeof(memdbg_tracer_event_t));
  if (!r->slots) return false;
  r->mask = capacity - 1;
  r->head = 0;
  r->tail = 0;
  return true;
}

static void ring_destroy(struct ring *r) {
  free(r->slots);
  r->slots = NULL;
}

static bool ring_push(struct ring *r, const memdbg_tracer_event_t *ev) {
  uint32_t h = r->head;
  /* If the ring is full ((head - tail) == capacity), overwrite the oldest. */
  r->slots[h & r->mask] = *ev;
  /* Ensure the write is visible before advancing head. */
  __sync_synchronize();
  r->head = h + 1;
  /* Advance tail if we wrapped — keep at most capacity entries. */
  if (r->head - r->tail > r->mask + 1) {
    r->tail = r->head - (r->mask + 1);
  }
  return true;
}

static uint32_t ring_pop(struct ring *r, memdbg_tracer_event_t *out,
                         uint32_t max_count) {
  uint32_t h = r->head;
  uint32_t avail = h - r->tail;
  if (avail == 0 || max_count == 0) return 0;
  uint32_t to_copy = avail < max_count ? avail : max_count;
  for (uint32_t i = 0; i < to_copy; i++) {
    out[i] = r->slots[(r->tail + i) & r->mask];
  }
  r->tail = r->tail + to_copy;
  return to_copy;
}

/* ------------------------------------------------------------------ */
/*  Timestamp helper — monotonic clock in nanoseconds                 */
/* ------------------------------------------------------------------ */

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/*  Signal name lookup                                                */
/* ------------------------------------------------------------------ */

static const char *signal_name(int sig) {
  switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS:  return "SIGBUS";
    case SIGABRT: return "SIGABRT";
    case SIGILL:  return "SIGILL";
    case SIGFPE:  return "SIGFPE";
    case SIGSYS:  return "SIGSYS";
    case SIGTRAP: return "SIGTRAP";
    case SIGSTOP: return "SIGSTOP";
    case SIGTERM: return "SIGTERM";
    case SIGKILL: return "SIGKILL";
    case SIGINT:  return "SIGINT";
    case SIGPIPE: return "SIGPIPE";
    case SIGALRM: return "SIGALRM";
    case SIGHUP:  return "SIGHUP";
    case SIGCHLD: return "SIGCHLD";
    case SIGCONT: return "SIGCONT";
    case SIGTSTP: return "SIGTSTP";
    case SIGTTIN: return "SIGTTIN";
    case SIGTTOU: return "SIGTTOU";
    case SIGPROF: return "SIGPROF";
    case SIGQUIT: return "SIGQUIT";
    case SIGUSR1: return "SIGUSR1";
    case SIGUSR2: return "SIGUSR2";
    default:      return "?";
  }
}

/* ------------------------------------------------------------------ */
/*  Tracer state                                                      */
/* ------------------------------------------------------------------ */

struct memdbg_tracer {
  memdbg_tracer_config_t  config;
  volatile bool           stop_requested;

  /* Ring buffer */
  struct ring             ring;

  /* Crash info */
  int                     crash_signal;
  uint64_t                crash_fault_addr;
  memdbg_debug_regs_t     crash_regs;
  bool                    crash_regs_valid;
  int32_t                 crash_lwp;
  char                    dump_path[512];

  /* Syscall stats (dynamic array) */
  memdbg_tracer_syscall_stat_t *stats;
  uint32_t                stats_count;
  uint32_t                stats_capacity;

  /* Internal tracing state (syscall entry pending) */
  bool                    pending_exit;
  uint32_t                pending_lwp;
  uint32_t                pending_sc_no;
  uint64_t                pending_sc_args[MEMDBG_TRACER_MAX_ARGS];
  uint64_t                pending_entry_ns;

  /* Thread list cache */
  int32_t                *lwps;
  uint32_t                lwp_count;
  uint32_t                lwp_capacity;
};

/* ------------------------------------------------------------------ */
/*  Syscall stats helpers — only used in full syscall trace mode      */
/* ------------------------------------------------------------------ */

#if defined(__FreeBSD__) || defined(PLATFORM_PS4) || defined(PLATFORM_PS5) || \
    defined(PS4) || defined(PS5) || defined(__ORBIS__) || defined(__PROSPERO__)

static void stats_record(struct memdbg_tracer *t, uint32_t sc_no,
                         uint64_t duration_ns) {
  for (uint32_t i = 0; i < t->stats_count; i++) {
    if (t->stats[i].syscall_no == sc_no) {
      t->stats[i].call_count++;
      t->stats[i].total_duration_ns += duration_ns;
      return;
    }
  }
  /* Not found — add new entry. */
  if (t->stats_count >= t->stats_capacity) {
    uint32_t new_cap = t->stats_capacity ? t->stats_capacity * 2 : 128;
    memdbg_tracer_syscall_stat_t *new_stats =
        (memdbg_tracer_syscall_stat_t *)realloc(
            t->stats, new_cap * sizeof(memdbg_tracer_syscall_stat_t));
    if (!new_stats) return;
    t->stats = new_stats;
    t->stats_capacity = new_cap;
  }
  uint32_t idx = t->stats_count++;
  t->stats[idx].syscall_no = sc_no;
  t->stats[idx].call_count = 1;
  t->stats[idx].total_duration_ns = duration_ns;
}

#endif /* FreeBSD/console — stats_record */

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

bool memdbg_tracer_supported(void) {
  return pal_debug_supported();
}

bool memdbg_tracer_syscall_supported(void) {
#if defined(__FreeBSD__) || defined(PLATFORM_PS4) || defined(PLATFORM_PS5) || \
    defined(PS4) || defined(PS5) || defined(__ORBIS__) || defined(__PROSPERO__)
  return true;
#else
  return false;
#endif
}

memdbg_tracer_t *memdbg_tracer_create(const memdbg_tracer_config_t *cfg) {
  if (!cfg || cfg->pid <= 0) {
    errno = EINVAL;
    return NULL;
  }

  memdbg_tracer_t *t = (memdbg_tracer_t *)calloc(1, sizeof(*t));
  if (!t) return NULL;

  t->config = *cfg;
  if (cfg->ring_size == 0) t->config.ring_size = MEMDBG_TRACER_DEFAULT_RING_SIZE;

  /* Initialise ring buffer */
  /* Round up to next power of two */
  uint32_t cap = t->config.ring_size;
  if (cap & (cap - 1)) {
    cap--;
    cap |= cap >> 1; cap |= cap >> 2; cap |= cap >> 4;
    cap |= cap >> 8; cap |= cap >> 16; cap++;
  }
  if (!ring_init(&t->ring, cap)) {
    free(t);
    return NULL;
  }

  /* Copy dump path */
  if (cfg->dump_path[0]) {
    size_t n = strlen(cfg->dump_path);
    if (n >= sizeof(t->dump_path)) n = sizeof(t->dump_path) - 1;
    memcpy(t->dump_path, cfg->dump_path, n);
    t->dump_path[n] = '\0';
  }

  /* Initialise thread list */
  t->lwp_capacity = 64;
  t->lwps = (int32_t *)calloc(t->lwp_capacity, sizeof(int32_t));
  if (!t->lwps) {
    ring_destroy(&t->ring);
    free(t);
    return NULL;
  }

  return t;
}

void memdbg_tracer_destroy(memdbg_tracer_t *t) {
  if (!t) return;
  ring_destroy(&t->ring);
  free(t->stats);
  free(t->lwps);
  free(t);
}

void memdbg_tracer_request_stop(memdbg_tracer_t *t) {
  if (t) t->stop_requested = true;
}

const char *memdbg_tracer_dump_path(const memdbg_tracer_t *t) {
  return t ? t->dump_path : "";
}

uint32_t memdbg_tracer_events(memdbg_tracer_t *t,
                              memdbg_tracer_event_t *out,
                              uint32_t max_count) {
  if (!t || !out) return 0;
  return ring_pop(&t->ring, out, max_count);
}

uint32_t memdbg_tracer_syscall_stats(memdbg_tracer_t *t,
                                     memdbg_tracer_syscall_stat_t *out,
                                     uint32_t max_count) {
  if (!t || !out || max_count == 0) return 0;
  uint32_t n = t->stats_count < max_count ? t->stats_count : max_count;
  /* Simple insertion sort by count descending */
  uint32_t *order = (uint32_t *)malloc(t->stats_count * sizeof(uint32_t));
  if (!order) return 0;
  for (uint32_t i = 0; i < t->stats_count; i++) order[i] = i;
  for (uint32_t i = 1; i < t->stats_count; i++) {
    uint32_t key = order[i];
    uint32_t j = i;
    while (j > 0 && t->stats[order[j - 1]].call_count < t->stats[key].call_count) {
      order[j] = order[j - 1];
      j--;
    }
    order[j] = key;
  }
  for (uint32_t i = 0; i < n; i++) out[i] = t->stats[order[i]];
  free(order);
  return n;
}

/* ------------------------------------------------------------------ */
/*  Crash dump writer                                                 */
/* ------------------------------------------------------------------ */

/* Forward declaration */
static int write_crash_dump(memdbg_tracer_t *t, const char *proc_name);

/* Capture process name from /proc/pid/name or /proc/pid/cmdline
 * (macOS: proc_name via sysctl) */
static int get_process_name(int pid, char *name, size_t name_len) {
  char buf[256];
  /* Try /proc/pid/name (Linux) */
  snprintf(buf, sizeof(buf), "/proc/%d/comm", pid);
  FILE *fp = fopen(buf, "r");
  if (fp) {
    if (fgets(name, (int)name_len, fp)) {
      size_t n = strlen(name);
      if (n > 0 && name[n - 1] == '\n') name[n - 1] = '\0';
    }
    fclose(fp);
    return 0;
  }
  /* Try macOS proc_name via sysctl */
#if defined(__APPLE__)
  int mib[3] = { CTL_KERN, KERN_PROC, pid };
  struct kinfo_proc kp;
  size_t len = sizeof(kp);
  if (sysctl(mib, 3, &kp, &len, NULL, 0) == 0) {
    snprintf(name, name_len, "%s", kp.kp_proc.p_comm);
    return 0;
  }
#endif
  snprintf(name, name_len, "pid-%d", pid);
  return -1;
}

/* Write a JSON crash dump */
static int write_crash_dump(memdbg_tracer_t *t, const char *proc_name) {
  char path[512];
  if (t->dump_path[0]) {
    snprintf(path, sizeof(path), "%s", t->dump_path);
  } else {
    /* Auto-generate a filename */
    snprintf(path, sizeof(path), "crash_%s_%d.json",
             proc_name, t->config.pid);
  }

  FILE *fp = fopen(path, "w");
  if (!fp) return -1;

  fprintf(fp, "{\n");
  fprintf(fp, "  \"version\": 1,\n");
  fprintf(fp, "  \"tracer\": \"memDBG Tracer\",\n");
  fprintf(fp, "  \"timestamp_ns\": %llu,\n", (unsigned long long)now_ns());

  /* Process info */
  fprintf(fp, "  \"process\": {\n");
  fprintf(fp, "    \"pid\": %d,\n", t->config.pid);
  fprintf(fp, "    \"name\": \"%s\"\n", proc_name ? proc_name : "?");
  fprintf(fp, "  },\n");

  /* Crash info */
  fprintf(fp, "  \"crash\": {\n");
  fprintf(fp, "    \"signal\": %d,\n", t->crash_signal);
  fprintf(fp, "    \"signal_name\": \"%s\",\n", signal_name(t->crash_signal));
  fprintf(fp, "    \"fault_address\": \"0x%llx\",\n",
          (unsigned long long)t->crash_fault_addr);
  fprintf(fp, "    \"lwp\": %d\n", t->crash_lwp);
  fprintf(fp, "  },\n");

  /* Crash registers */
  if (t->crash_regs_valid) {
    fprintf(fp, "  \"registers\": {\n");
    fprintf(fp, "    \"rax\": \"0x%llx\",\n", (unsigned long long)t->crash_regs.r_rax);
    fprintf(fp, "    \"rbx\": \"0x%llx\",\n", (unsigned long long)t->crash_regs.r_rbx);
    fprintf(fp, "    \"rcx\": \"0x%llx\",\n", (unsigned long long)t->crash_regs.r_rcx);
    fprintf(fp, "    \"rdx\": \"0x%llx\",\n", (unsigned long long)t->crash_regs.r_rdx);
    fprintf(fp, "    \"rdi\": \"0x%llx\",\n", (unsigned long long)t->crash_regs.r_rdi);
    fprintf(fp, "    \"rsi\": \"0x%llx\",\n", (unsigned long long)t->crash_regs.r_rsi);
    fprintf(fp, "    \"rbp\": \"0x%llx\",\n", (unsigned long long)t->crash_regs.r_rbp);
    fprintf(fp, "    \"rsp\": \"0x%llx\",\n", (unsigned long long)t->crash_regs.r_rsp);
    fprintf(fp, "    \"rip\": \"0x%llx\",\n", (unsigned long long)t->crash_regs.r_rip);
    fprintf(fp, "    \"rflags\": \"0x%llx\"\n", (unsigned long long)t->crash_regs.r_rflags);
    fprintf(fp, "  },\n");
  }

  /* Ring buffer events (last N recorded) */
  fprintf(fp, "  \"events\": [\n");
  uint32_t event_count = t->ring.head - t->ring.tail;
  uint32_t count = event_count < 100 ? event_count : 100;
  memdbg_tracer_event_t *events =
      (memdbg_tracer_event_t *)calloc(count, sizeof(memdbg_tracer_event_t));
  if (events) {
    uint32_t n = ring_pop(&t->ring, events, count);
    for (uint32_t i = 0; i < n; i++) {
      const memdbg_tracer_event_t *e = &events[i];
      fprintf(fp, "    {\n");
      fprintf(fp, "      \"type\": %u,\n", e->event_type);
      fprintf(fp, "      \"lwp\": %u,\n", e->lwp);
      fprintf(fp, "      \"syscall\": %u,\n", e->syscall_no);
      fprintf(fp, "      \"syscall_name\": \"%s\",\n",
              memdbg_tracer_syscall_name((int)e->syscall_no));
      if (e->event_type == MEMDBG_TRACER_EVENT_SYSCALL_ENTRY) {
        fprintf(fp, "      \"args\": [%llu,%llu,%llu,%llu,%llu,%llu],\n",
                (unsigned long long)e->args[0],
                (unsigned long long)e->args[1],
                (unsigned long long)e->args[2],
                (unsigned long long)e->args[3],
                (unsigned long long)e->args[4],
                (unsigned long long)e->args[5]);
      } else if (e->event_type == MEMDBG_TRACER_EVENT_SYSCALL_EXIT) {
        fprintf(fp, "      \"retval\": %lld,\n", (long long)e->syscall_ret);
      } else {
        fprintf(fp, "      \"signal\": %d,\n", e->signal);
      }
      fprintf(fp, "      \"timestamp_ns\": %llu\n",
              (unsigned long long)e->timestamp_ns);
      fprintf(fp, "    }%s\n", (i + 1 < n) ? "," : "");
    }
    free(events);
  }
  fprintf(fp, "  ],\n");

  /* Syscall frequency summary */
  fprintf(fp, "  \"syscall_frequency\": [\n");
  uint32_t nstats = t->stats_count;
  if (nstats > 50) nstats = 50; /* limit output */
  memdbg_tracer_syscall_stat_t *sout =
      (memdbg_tracer_syscall_stat_t *)calloc(nstats, sizeof(*sout));
  if (sout) {
    uint32_t ns = memdbg_tracer_syscall_stats(t, sout, nstats);
    for (uint32_t i = 0; i < ns; i++) {
      fprintf(fp, "    {\n");
      fprintf(fp, "      \"syscall\": %u,\n", sout[i].syscall_no);
      fprintf(fp, "      \"name\": \"%s\",\n",
              memdbg_tracer_syscall_name((int)sout[i].syscall_no));
      fprintf(fp, "      \"count\": %llu,\n",
              (unsigned long long)sout[i].call_count);
      fprintf(fp, "      \"total_time_ns\": %llu\n",
              (unsigned long long)sout[i].total_duration_ns);
      fprintf(fp, "    }%s\n", (i + 1 < ns) ? "," : "");
    }
    free(sout);
  }
  fprintf(fp, "  ]\n");

  fprintf(fp, "}\n");
  fclose(fp);

  /* Store the path used */
  if (!t->dump_path[0]) {
    size_t n = strlen(path);
    if (n >= sizeof(t->dump_path)) n = sizeof(t->dump_path) - 1;
    memcpy(t->dump_path, path, n);
    t->dump_path[n] = '\0';
  }

  return 0;
}

/* ------------------------------------------------------------------ */
/*  Crash signal check                                                */
/* ------------------------------------------------------------------ */

static bool is_crash_signal(int sig) {
  switch (sig) {
    case SIGSEGV:
    case SIGBUS:
    case SIGABRT:
    case SIGILL:
    case SIGFPE:
    case SIGSYS:
      return true;
    default:
      return false;
  }
}

/* ------------------------------------------------------------------ */
/*  Tracer loop — macOS crash-only path                               */
/* ------------------------------------------------------------------ */

static memdbg_status_t tracer_run_crash_only(memdbg_tracer_t *t) {
  int pid = t->config.pid;

  /* Attach */
  if (pal_debug_attach(pid) != 0) {
    return MEMDBG_ERR_PERMISSION;
  }

  /* Read initial registers from the crash thread */
  memdbg_debug_regs_t regs;
  if (pal_debug_get_regs(pid, 0, &regs) == 0) {
    t->crash_regs = regs;
    t->crash_regs_valid = true;
  }

  /* Let the process run */
  if (pal_debug_continue(pid) != 0) {
    pal_debug_detach(pid);
    return MEMDBG_ERR_STATE;
  }

  /* Wait loop */
  while (!t->stop_requested) {
    int status = 0;
    int r = pal_debug_wait(pid, &status, false);
    if (r == -1) {
      if (errno == EINTR && t->stop_requested) break;
      pal_debug_detach(pid);
      return MEMDBG_ERR_STATE;
    }

    if (WIFEXITED(status)) {
      /* Normal exit */
      pal_debug_detach(pid);
      return MEMDBG_ERR_NOT_FOUND;
    }

    if (WIFSIGNALED(status)) {
      /* Process was killed by a signal (not caught) */
      int sig = WTERMSIG(status);
      t->crash_signal = sig;

      /* Read registers one more time if possible (process may still be
       * waitable enough). */
      if (!t->crash_regs_valid) {
        if (pal_debug_get_regs(pid, 0, &regs) == 0) {
          t->crash_regs = regs;
          t->crash_regs_valid = true;
        }
      }

      char proc_name[256] = "";
      get_process_name(pid, proc_name, sizeof(proc_name));

      memdbg_tracer_event_t ev;
      memset(&ev, 0, sizeof(ev));
      ev.event_type = MEMDBG_TRACER_EVENT_CRASH;
      ev.signal = sig;
      ev.timestamp_ns = now_ns();
      ring_push(&t->ring, &ev);

      write_crash_dump(t, proc_name);
      return MEMDBG_OK;
    }

    if (WIFSTOPPED(status)) {
      int sig = WSTOPSIG(status);

      /* Record the signal event */
      memdbg_tracer_event_t ev;
      memset(&ev, 0, sizeof(ev));
      ev.event_type = MEMDBG_TRACER_EVENT_SIGNAL;
      ev.signal = sig;
      ev.timestamp_ns = now_ns();
      ring_push(&t->ring, &ev);

      if (is_crash_signal(sig)) {
        /* Crash detected */
        t->crash_signal = sig;

        /* Try to read registers */
        if (pal_debug_get_regs(pid, 0, &regs) == 0) {
          t->crash_regs = regs;
          t->crash_regs_valid = true;
        }

        char proc_name[256] = "";
        get_process_name(pid, proc_name, sizeof(proc_name));

        ev.event_type = MEMDBG_TRACER_EVENT_CRASH;
        ev.signal = sig;
        ev.timestamp_ns = now_ns();
        ring_push(&t->ring, &ev);

        /* Detach first (before the crash signal kills the process) */
        pal_debug_detach(pid);

        write_crash_dump(t, proc_name);
        return MEMDBG_OK;
      }

      /* Non-crash signal — deliver it and continue */
      pal_debug_continue(pid);
    }
  }

  /* Stopped by user request */
  pal_debug_detach(pid);
  return MEMDBG_ERR_STATE;
}

/* ------------------------------------------------------------------ */
/*  Tracer loop — FreeBSD/console full syscall trace path             */
/* ------------------------------------------------------------------ */

#if defined(__FreeBSD__) || defined(PLATFORM_PS4) || defined(PLATFORM_PS5) || \
    defined(PS4) || defined(PS5) || defined(__ORBIS__) || defined(__PROSPERO__)

static memdbg_status_t tracer_run_full(memdbg_tracer_t *t) {
  int pid = t->config.pid;

  /* Attach */
  if (pal_debug_attach(pid) != 0) {
    return MEMDBG_ERR_PERMISSION;
  }

  /* Ensure we're using syscall-stops (PL_FLAG_SCE / PL_FLAG_SCX). */
  if (pal_debug_syscall(pid) != 0) {
    pal_debug_detach(pid);
    return MEMDBG_ERR_STATE;
  }

  while (!t->stop_requested) {
    int status = 0;
    int r = pal_debug_wait(pid, &status, false);
    if (r == -1) {
      if (errno == EINTR && t->stop_requested) break;
      pal_debug_detach(pid);
      return MEMDBG_ERR_STATE;
    }

    if (WIFEXITED(status)) {
      pal_debug_detach(pid);
      return MEMDBG_ERR_NOT_FOUND;
    }

    if (WIFSIGNALED(status)) {
      int sig = WTERMSIG(status);
      t->crash_signal = sig;
      char proc_name[256] = "";
      get_process_name(pid, proc_name, sizeof(proc_name));

      memdbg_tracer_event_t ev;
      memset(&ev, 0, sizeof(ev));
      ev.event_type = MEMDBG_TRACER_EVENT_CRASH;
      ev.signal = sig;
      ev.timestamp_ns = now_ns();
      ring_push(&t->ring, &ev);

      write_crash_dump(t, proc_name);
      return MEMDBG_OK;
    }

    if (!WIFSTOPPED(status)) continue;

    int sig = WSTOPSIG(status);
    bool is_syscall_entry = false;
    bool is_syscall_exit = false;
    (void)is_syscall_exit;

    /* Attempt to get PT_LWPINFO for syscall entry/exit detection. */
#if defined(PT_LWPINFO)
    {
      struct ptrace_lwpinfo lwpinfo;
      memset(&lwpinfo, 0, sizeof(lwpinfo));
      /* We need to get the first LWP to read LWP info. Use the cached LWP list
       * or query it now. */
      int32_t lwp_buf[256];
      int nlwps = pal_debug_get_thread_list(pid, lwp_buf, 256);
      if (nlwps > 0) {
        long ri = pal_debug_ptrace(PT_LWPINFO, (int)lwp_buf[0],
                                   (void *)&lwpinfo, (long)sizeof(lwpinfo));
        if (ri == 0) {
          unsigned int flags = (unsigned int)lwpinfo.pl_flags;
          if (flags & PL_FLAG_SCE) is_syscall_entry = true;
          if (flags & PL_FLAG_SCX) is_syscall_exit = true;
          if (lwpinfo.pl_event == PL_EVENT_SIGNAL) {
            sig = (int)lwpinfo.pl_siginfo.si_signo;
          }
        }
      }
    }
#endif

    if (is_syscall_entry) {
      /* Read registers to get syscall number and arguments */
      memdbg_debug_regs_t regs;
      int32_t lwp_buf[256];
      int nlwps = pal_debug_get_thread_list(pid, lwp_buf, 256);
      int32_t crash_lwp = (nlwps > 0) ? lwp_buf[0] : 0;

      if (pal_debug_get_regs(pid, crash_lwp, &regs) == 0) {
        /* FreeBSD x86-64: syscall number in rax, args in rdi, rsi, rdx, r10, r8, r9 */
        int no = (int)regs.r_rax;
        t->pending_sc_no = (uint32_t)no;
        t->pending_sc_args[0] = (uint64_t)regs.r_rdi;
        t->pending_sc_args[1] = (uint64_t)regs.r_rsi;
        t->pending_sc_args[2] = (uint64_t)regs.r_rdx;
        t->pending_sc_args[3] = (uint64_t)regs.r_r10;
        t->pending_sc_args[4] = (uint64_t)regs.r_r8;
        t->pending_sc_args[5] = (uint64_t)regs.r_r9;
        t->pending_lwp = (uint32_t)crash_lwp;
        t->pending_entry_ns = now_ns();
        t->pending_exit = true;

        /* Push entry event */
        memdbg_tracer_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.event_type = MEMDBG_TRACER_EVENT_SYSCALL_ENTRY;
        ev.lwp = (uint32_t)crash_lwp;
        ev.syscall_no = (uint32_t)no;
        memcpy(ev.args, t->pending_sc_args, sizeof(ev.args));
        ev.timestamp_ns = t->pending_entry_ns;
        ring_push(&t->ring, &ev);
      }

      pal_debug_syscall(pid);
      continue;
    }

    if (is_syscall_exit && t->pending_exit) {
      /* Read return value */
      memdbg_debug_regs_t regs;
      int32_t lwp_buf[256];
      int nlwps = pal_debug_get_thread_list(pid, lwp_buf, 256);
      int32_t crash_lwp = (nlwps > 0) ? lwp_buf[0] : 0;

      uint64_t exit_ns = now_ns();
      uint64_t duration = exit_ns - t->pending_entry_ns;

      if (pal_debug_get_regs(pid, crash_lwp, &regs) == 0) {
        memdbg_tracer_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.event_type = MEMDBG_TRACER_EVENT_SYSCALL_EXIT;
        ev.lwp = t->pending_lwp;
        ev.syscall_no = t->pending_sc_no;
        ev.syscall_ret = (int32_t)regs.r_rax;
        ev.timestamp_ns = exit_ns;
        ring_push(&t->ring, &ev);

        /* Update statistics */
        stats_record(t, t->pending_sc_no, duration);
      }

      t->pending_exit = false;
      pal_debug_syscall(pid);
      continue;
    }

    /* Signal delivery or other stop */
    {
      memdbg_tracer_event_t ev;
      memset(&ev, 0, sizeof(ev));

      if (is_crash_signal(sig)) {
        ev.event_type = MEMDBG_TRACER_EVENT_CRASH;
        t->crash_signal = sig;

        /* Read registers */
        memdbg_debug_regs_t regs;
        int32_t lwp_buf[256];
        int nlwps = pal_debug_get_thread_list(pid, lwp_buf, 256);
        int32_t crash_lwp = (nlwps > 0) ? lwp_buf[0] : 0;
        if (pal_debug_get_regs(pid, crash_lwp, &regs) == 0) {
          t->crash_regs = regs;
          t->crash_regs_valid = true;
          t->crash_lwp = crash_lwp;
        }

        char proc_name[256] = "";
        get_process_name(pid, proc_name, sizeof(proc_name));
        write_crash_dump(t, proc_name);
        pal_debug_detach(pid);
        return MEMDBG_OK;
      }

      ev.event_type = MEMDBG_TRACER_EVENT_SIGNAL;
      ev.signal = sig;
      ev.timestamp_ns = now_ns();
      ring_push(&t->ring, &ev);

      /* Resume with the signal */
      pal_debug_syscall(pid);
    }
  }

  pal_debug_detach(pid);
  return MEMDBG_ERR_STATE;
}

#else /* not FreeBSD/console — fallback to crash-only */

static memdbg_status_t tracer_run_full(memdbg_tracer_t *t) {
  (void)t;
  return MEMDBG_ERR_UNSUPPORTED;
}

#endif /* FreeBSD/console */

/* ------------------------------------------------------------------ */
/*  memdbg_tracer_run — platform dispatch                             */
/* ------------------------------------------------------------------ */

memdbg_status_t memdbg_tracer_run(memdbg_tracer_t *t) {
  if (!t) return MEMDBG_ERR_PARAM;

  /* Try full syscall tracing if available and requested */
  if (t->config.trace_syscalls) {
    memdbg_status_t st = tracer_run_full(t);
    if (st != MEMDBG_ERR_UNSUPPORTED) return st;
    /* Fall through to crash-only */
  }

  return tracer_run_crash_only(t);
}
