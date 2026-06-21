/*
 * memDBG - Tracer daemon lifecycle test.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/tracer/memdbg_tracer_daemon.h"
#include "memdbg/pal/pal_debug.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

static volatile int g_attach_calls = 0;
static volatile int g_detach_calls = 0;
static volatile int g_continue_calls = 0;

static void sleep_ms(long milliseconds) {
  struct timespec ts;
  ts.tv_sec = milliseconds / 1000L;
  ts.tv_nsec = (milliseconds % 1000L) * 1000000L;
  (void)nanosleep(&ts, NULL);
}

static bool wait_for_state(int32_t expected) {
  for (int i = 0; i < 200; ++i) {
    memdbg_tracer_status_response_t status;
    memdbg_tracer_daemon_status(&status);
    if (status.state == expected) return true;
    sleep_ms(2);
  }
  return false;
}

#define TEST(label, condition) \
  do { \
    if (!(condition)) { \
      fprintf(stderr, "FAIL %s\n", label); \
      return 1; \
    } \
    printf("PASS %s\n", label); \
  } while (0)

/* PAL stubs: PT_SYSCALL is unavailable, so the daemon must explicitly
 * continue the target after attach and always detach it during shutdown. */
bool pal_debug_supported(void) { return true; }

int pal_debug_attach(int pid) {
  (void)pid;
  ++g_attach_calls;
  return 0;
}

int pal_debug_detach(int pid) {
  (void)pid;
  ++g_detach_calls;
  return 0;
}

int pal_debug_syscall(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_continue(int pid) {
  (void)pid;
  ++g_continue_calls;
  return 0;
}

int pal_debug_wait(int pid, int *status, bool nohang) {
  (void)pid;
  (void)nohang;
  sleep_ms(1);
  if (status != NULL) *status = 0x7f; /* WIFSTOPPED */
  return 1;
}

int pal_debug_get_thread_list(int pid, int32_t *lwps, int max_count) {
  (void)pid;
  (void)lwps;
  (void)max_count;
  errno = ENOTSUP;
  return -1;
}

long pal_debug_ptrace(int op, int pid, void *addr, long data) {
  (void)op;
  (void)pid;
  (void)addr;
  (void)data;
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

int main(void) {
  printf("=== Tracer daemon lifecycle test ===\n");

  TEST("initial stop is harmless", (memdbg_tracer_daemon_stop(), true));
  TEST("start accepts PID", memdbg_tracer_daemon_start(4242, NULL) == MEMDBG_OK);
  TEST("tracer reaches running", wait_for_state(MEMDBG_TRACER_STATE_RUNNING));
  TEST("fallback path continues target", g_continue_calls > 0);

  memdbg_tracer_daemon_stop();
  TEST("stop reaches stopped", wait_for_state(MEMDBG_TRACER_STATE_STOPPED));
  TEST("stop detaches target", g_detach_calls == 1);

  TEST("restart accepts PID", memdbg_tracer_daemon_start(4242, NULL) == MEMDBG_OK);
  TEST("restart reaches running", wait_for_state(MEMDBG_TRACER_STATE_RUNNING));
  memdbg_tracer_daemon_stop();
  TEST("restart detaches target", g_detach_calls == 2);

  printf("All tracer daemon lifecycle tests passed.\n");
  return 0;
}
