/*
 * memDBG - Debugger subsystem end-to-end test.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Verifies the high-level debugger API (memdbg_debugger.h) against mocked
 * PAL primitives.  Covers:
 *   - attach / detach state transitions
 *   - stop / continue / step
 *   - thread enumeration and naming
 *   - general-purpose register get / set
 *   - debug register get / set
 *   - software breakpoint install / uninstall (INT3)
 *   - hardware breakpoint install / uninstall (dbregs)
 *   - hardware watchpoint install / uninstall
 *   - thread suspend / resume
 *   - poll events and stop-LWP detection
 *   - error-path behaviour (double-attach, invalid params, etc.)
 */

#include "memdbg/debug/memdbg_debugger.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* ======================================================================
 * Mock target state — a simulated process with threads, registers, and
 * a 4 KiB memory page that the PAL stubs operate on.
 * ====================================================================== */

#define MOCK_PID         100
#define MOCK_LWP_MAIN    1001
#define MOCK_LWP_WORKER  1002
#define MOCK_MEM_SIZE    65536           /* 64 KiB — enough for test addresses up to 0xFFFF */

/* WIFSTOPPED macro encoding: status = (signal) | 0x7F means "stopped by signal".
 * Using SIGTRAP (5) yields 0x85, not 0x7F.  The actual test for WIFSTOPPED is
 * ((status & 0xFF) == 0x7F), so we need exactly 0x7F to trigger it.
 * 0x7F is the raw POSIX encoding for a stop event (signal 0, but WIFSTOPPED checks
 * the low byte against 0x7F). */
#define MOCK_WAIT_STOPPED  0x7F

static struct {
  bool     supported;
  int      pid;
  bool     attached;
  bool     stopped;
  int32_t  stop_lwp;

  /* Thread list */
  int32_t  lwps[8];
  char     lwp_names[8][24];
  int      lwp_count;

  /* Per-thread registers */
  memdbg_debug_regs_t   regs[8];
  int                   regs_lwp_idx[8]; /* which LWP each slot maps to */

  /* Debug registers (shared across threads in this mock) */
  memdbg_debug_dbregs_t dbregs;

  /* 4 KiB simulated process memory */
  uint8_t  memory[MOCK_MEM_SIZE];

  /* wait() simulation */
  int      wait_status;
  int      wait_call_count;
  bool     wait_nohang_empty;   /* when true, next nohang wait returns 0 */

  /* step expected flag */
  bool     step_called;
  bool     suspend_called[8];
  bool     resume_called[8];
  int      attach_errno;
} mock = {0};

/* ---- Mock helpers ---- */

static void mock_reset(void) {
  memset(&mock, 0, sizeof(mock));
  mock.supported = true;
  mock.pid       = MOCK_PID;
  mock.lwp_count = 2;
  mock.lwps[0]   = MOCK_LWP_MAIN;
  mock.lwps[1]   = MOCK_LWP_WORKER;
  (void)snprintf(mock.lwp_names[0], sizeof(mock.lwp_names[0]), "main");
  (void)snprintf(mock.lwp_names[1], sizeof(mock.lwp_names[1]), "worker");
  mock.regs_lwp_idx[0] = MOCK_LWP_MAIN;
  mock.regs_lwp_idx[1] = MOCK_LWP_WORKER;

  /* Initialise registers for the main LWP with plausible x86-64 values. */
  mock.regs[0].r_rip    = 0x7FFF12340000LL;
  mock.regs[0].r_rsp    = 0x7FFEE0001000LL;
  mock.regs[0].r_rbp    = 0x7FFEE0001080LL;
  mock.regs[0].r_rax    = 0x42LL;
  mock.regs[0].r_rbx    = 0x100LL;
  mock.regs[0].r_rcx    = 0x200LL;
  mock.regs[0].r_rdx    = 0x300LL;
  mock.regs[0].r_rflags = 0x202LL; /* IF set */

  mock.regs[1].r_rip    = 0x7FFF56780000LL;
  mock.regs[1].r_rsp    = 0x7FFEE0002000LL;
}

static int mock_find_regs_idx(int32_t lwp) {
  for (int i = 0; i < 8; ++i) {
    if (mock.regs_lwp_idx[i] == lwp) return i;
  }
  return -1;
}

/* ======================================================================
 * PAL stubs — these override the real pal_debug / pal_memory / privilege
 * functions so the test can run without ptrace entitlements.
 * ====================================================================== */

bool pal_debug_supported(void) { return mock.supported; }

int pal_debug_attach(int pid) {
  (void)pid;
  if (mock.attach_errno != 0) { errno = mock.attach_errno; return -1; }
  if (mock.attached) { errno = EINVAL; return -1; }
  mock.attached = true;
  mock.stopped  = true;
  return 0;
}

int pal_debug_detach(int pid) {
  (void)pid;
  if (!mock.attached) { errno = ESRCH; return -1; }
  mock.attached = false;
  mock.stopped  = false;
  return 0;
}

int pal_debug_wait(int pid, int *status, bool nohang) {
  (void)pid;
  if (nohang) {
    if (mock.wait_nohang_empty) {
      if (status != NULL) *status = 0;
      return 0;
    }
    if (mock.wait_call_count == 0 && mock.attached) {
      /* First nohang wait after attach: return stop event. */
      if (status != NULL) *status = MOCK_WAIT_STOPPED;
      mock.wait_call_count++;
      return 1;
    }
    /* Subsequent calls: check if process is stopped */
    if (mock.stopped) {
      if (status != NULL) *status = MOCK_WAIT_STOPPED;
      mock.wait_call_count++;
      return 1;
    }
    if (status != NULL) *status = 0;
    mock.wait_call_count++;
    return 0;
  }
  /* Blocking wait: just return stopped for the first call */
  if (mock.wait_call_count == 0) {
    if (status != NULL) *status = MOCK_WAIT_STOPPED;
    mock.wait_call_count++;
    return 1;
  }
  errno = ECHILD;
  return -1;
}

int pal_debug_continue(int pid) {
  (void)pid;
  if (!mock.attached) { errno = ESRCH; return -1; }
  mock.stopped = false;
  mock.stop_lwp = 0;
  return 0;
}

int pal_debug_stop(int pid) {
  (void)pid;
  if (!mock.attached) { errno = ESRCH; return -1; }
  mock.stopped = true;
  return 0;
}

int pal_debug_single_step(int pid, int32_t lwp) {
  (void)pid;
  (void)lwp;
  if (!mock.attached) { errno = ESRCH; return -1; }
  mock.step_called = true;
  mock.stopped = true;
  return 0;
}

int pal_debug_suspend_thread(int pid, int32_t lwp) {
  (void)pid;
  for (int i = 0; i < mock.lwp_count; ++i) {
    if (mock.lwps[i] == lwp) { mock.suspend_called[i] = true; return 0; }
  }
  errno = ESRCH;
  return -1;
}

int pal_debug_resume_thread(int pid, int32_t lwp) {
  (void)pid;
  for (int i = 0; i < mock.lwp_count; ++i) {
    if (mock.lwps[i] == lwp) { mock.resume_called[i] = true; return 0; }
  }
  errno = ESRCH;
  return -1;
}

int pal_debug_get_thread_list(int pid, int32_t *lwps, int max_count) {
  (void)pid;
  if (lwps == NULL || max_count <= 0) { errno = EINVAL; return -1; }
  int n = mock.lwp_count < max_count ? mock.lwp_count : max_count;
  for (int i = 0; i < n; ++i) lwps[i] = mock.lwps[i];
  return n;
}

int pal_debug_get_thread_name(int pid, int32_t lwp, char *name, size_t name_len) {
  (void)pid;
  if (name == NULL || name_len == 0) { errno = EINVAL; return -1; }
  for (int i = 0; i < mock.lwp_count; ++i) {
    if (mock.lwps[i] == lwp) {
      (void)snprintf(name, name_len, "%s", mock.lwp_names[i]);
      return 0;
    }
  }
  name[0] = '\0';
  return -1;
}

int pal_debug_get_thread_state(int pid, int32_t lwp, int *state_out) {
  (void)pid; (void)lwp;
  if (state_out != NULL) *state_out = (int)MEMDBG_THREAD_RUNNING;
  return 0;
}

int pal_debug_get_regs(int pid, int32_t lwp, memdbg_debug_regs_t *regs) {
  (void)pid;
  if (regs == NULL) { errno = EINVAL; return -1; }
  int idx = mock_find_regs_idx(lwp);
  if (idx < 0) { errno = ESRCH; return -1; }
  memcpy(regs, &mock.regs[idx], sizeof(*regs));
  return 0;
}

int pal_debug_set_regs(int pid, int32_t lwp, const memdbg_debug_regs_t *regs) {
  (void)pid;
  if (regs == NULL) { errno = EINVAL; return -1; }
  int idx = mock_find_regs_idx(lwp);
  if (idx < 0) { errno = ESRCH; return -1; }
  memcpy(&mock.regs[idx], regs, sizeof(*regs));
  return 0;
}

int pal_debug_get_dbregs(int pid, int32_t lwp, memdbg_debug_dbregs_t *dbregs) {
  (void)pid;
  (void)lwp;
  if (dbregs == NULL) { errno = EINVAL; return -1; }
  memcpy(dbregs, &mock.dbregs, sizeof(*dbregs));
  return 0;
}

int pal_debug_set_dbregs(int pid, int32_t lwp, const memdbg_debug_dbregs_t *dbregs) {
  (void)pid;
  (void)lwp;
  if (dbregs == NULL) { errno = EINVAL; return -1; }
  memcpy(&mock.dbregs, dbregs, sizeof(*dbregs));
  return 0;
}

/* ---- PAL memory stubs (needed for software breakpoint install) ---- */

#include "memdbg/pal/pal_memory.h"

memdbg_status_t pal_memory_read(int pid, uint64_t address, void *buffer,
                                size_t length, size_t *read_out) {
  (void)pid;
  if (buffer == NULL) return MEMDBG_ERR_PARAM;
  if (address + (uint64_t)length > MOCK_MEM_SIZE) {
    if (read_out != NULL) *read_out = 0;
    return MEMDBG_ERR_IO;
  }
  memcpy(buffer, mock.memory + (size_t)address, length);
  if (read_out != NULL) *read_out = length;
  return MEMDBG_OK;
}

memdbg_status_t pal_memory_write(int pid, uint64_t address, const void *buffer,
                                 size_t length, size_t *written_out) {
  (void)pid;
  if (buffer == NULL) return MEMDBG_ERR_PARAM;
  if (address + (uint64_t)length > MOCK_MEM_SIZE) {
    if (written_out != NULL) *written_out = 0;
    return MEMDBG_ERR_IO;
  }
  memcpy(mock.memory + (size_t)address, buffer, length);
  if (written_out != NULL) *written_out = length;
  return MEMDBG_OK;
}

/* ---- Privilege stub (no elevation on host) ---- */

#include "memdbg/privilege/privilege.h"

bool memdbg_privilege_supported(void) { return false; }

int memdbg_privilege_elevate_target(pid_t pid, memdbg_ucred_backup_t *backup) {
  (void)pid; (void)backup;
  errno = ENOTSUP;
  return -1;
}

void memdbg_privilege_restore_target(pid_t pid, const memdbg_ucred_backup_t *backup) {
  (void)pid; (void)backup;
}

/* ---- Log stub ---- */

#include "memdbg/core/memdbg_log.h"

void memdbg_log_write(memdbg_log_level_t level, const char *fmt, ...) {
  (void)level; (void)fmt;
}

/* ======================================================================
 * Test harness
 * ====================================================================== */

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s\n", name);                                            \
    }                                                                          \
  } while (0)

#define TEST_EQ_I(name, actual, expected)                                      \
  do {                                                                         \
    int _a = (int)(actual);                                                    \
    int _e = (int)(expected);                                                  \
    if (_a == _e) {                                                            \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s  (got %d, expected %d)\n", name, _a, _e);             \
    }                                                                          \
  } while (0)

#define TEST_EQ_U(name, actual, expected)                                      \
  do {                                                                         \
    unsigned _a = (unsigned)(actual);                                          \
    unsigned _e = (unsigned)(expected);                                       \
    if (_a == _e) {                                                            \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s  (got %u, expected %u)\n", name, _a, _e);             \
    }                                                                          \
  } while (0)

#define TEST_EQ_LL(name, actual, expected)                                     \
  do {                                                                         \
    long long _a = (long long)(actual);                                        \
    long long _e = (long long)(expected);                                      \
    if (_a == _e) {                                                            \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s  (got %lld, expected %lld)\n", name, _a, _e);         \
    }                                                                          \
  } while (0)

#define TEST_OK(name, status)                                                  \
  do {                                                                         \
    int _s = (int)(status);                                                    \
    if (_s == (int)MEMDBG_OK) {                                                \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s  (status %d)\n", name, _s);                          \
    }                                                                          \
  } while (0)

#define TEST_ERR(name, status, expected_err)                                   \
  do {                                                                         \
    int _s = (int)(status);                                                    \
    int _e = (int)(expected_err);                                              \
    if (_s == _e) {                                                            \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s  (got %d, expected %d)\n", name, _s, _e);             \
    }                                                                          \
  } while (0)

/* ======================================================================
 * Test cases
 * ====================================================================== */

/* ---- 1. Attach / Detach state transitions ---- */

static void test_attach_detach(void) {
  printf("\n--- Attach / Detach ---\n");

  mock_reset();

  /* Pre-condition: not attached */
  TEST("not attached initially", !memdbg_debugger_is_attached());
  TEST("not stopped initially", !memdbg_debugger_is_stopped());
  TEST("is_elevated false", !memdbg_debugger_is_elevated(MOCK_PID));

  /* Attach */
  memdbg_status_t st = memdbg_debugger_attach(MOCK_PID);
  TEST_OK("attach succeeds", st);
  TEST("attached after attach", memdbg_debugger_is_attached());
  TEST("stopped after attach", memdbg_debugger_is_stopped());
  TEST_EQ_I("attached pid", memdbg_debugger_attached_pid(), MOCK_PID);

  /* Re-attaching the same PID is idempotent, a different PID is not. */
  st = memdbg_debugger_attach(MOCK_PID);
  TEST_OK("same PID attach is idempotent", st);
  st = memdbg_debugger_attach(MOCK_PID + 1);
  TEST_ERR("different PID double attach fails", st, MEMDBG_ERR_STATE);

  /* Detach */
  st = memdbg_debugger_detach();
  TEST_OK("detach succeeds", st);
  TEST("not attached after detach", !memdbg_debugger_is_attached());
  TEST("not stopped after detach", !memdbg_debugger_is_stopped());

  /* Double-detach should fail */
  st = memdbg_debugger_detach();
  TEST_ERR("double detach fails", st, MEMDBG_ERR_STATE);
}

/* ---- 2. Stop / Continue / Step ---- */

static void test_stop_continue_step(void) {
  printf("\n--- Stop / Continue / Step ---\n");

  mock_reset();
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));
  TEST("stopped after attach", memdbg_debugger_is_stopped());

  /* Continue */
  memdbg_status_t st = memdbg_debugger_continue();
  TEST_OK("continue succeeds", st);
  TEST("not stopped after continue", !memdbg_debugger_is_stopped());

  /* Stop */
  st = memdbg_debugger_stop();
  TEST_OK("stop succeeds", st);
  TEST("stopped after stop", memdbg_debugger_is_stopped());

  /* Step */
  mock.step_called = false;
  st = memdbg_debugger_step(MOCK_LWP_MAIN);
  TEST_OK("step succeeds", st);
  TEST("step called PAL single_step", mock.step_called);

  TEST_OK("detach", memdbg_debugger_detach());
}

/* ---- 3. Thread enumeration ---- */

static void test_thread_enumeration(void) {
  printf("\n--- Thread Enumeration ---\n");

  mock_reset();
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  int32_t lwps[MEMDBG_DEBUGGER_MAX_THREADS];
  char    names[MEMDBG_DEBUGGER_MAX_THREADS][24];
  uint32_t count = 0;

  memdbg_status_t st = memdbg_debugger_get_threads(lwps, names, NULL, &count,
                                                    MEMDBG_DEBUGGER_MAX_THREADS);
  TEST_OK("get_threads succeeds", st);
  TEST_EQ_U("thread count", count, 2U);
  TEST_EQ_I("lwp[0] matches main", lwps[0], MOCK_LWP_MAIN);
  TEST_EQ_I("lwp[1] matches worker", lwps[1], MOCK_LWP_WORKER);
  TEST("name[0] is 'main'", strcmp(names[0], "main") == 0);
  TEST("name[1] is 'worker'", strcmp(names[1], "worker") == 0);

  /* Also test without names (names == NULL) */
  count = 0;
  st = memdbg_debugger_get_threads(lwps, NULL, NULL, &count,
                                   MEMDBG_DEBUGGER_MAX_THREADS);
  TEST_OK("get_threads without names succeeds", st);
  TEST_EQ_U("count still 2", count, 2U);

  TEST_OK("detach", memdbg_debugger_detach());
}

/* ---- 4. Register access ---- */

static void test_register_access(void) {
  printf("\n--- Register Access ---\n");

  mock_reset();
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  memdbg_debug_regs_t regs;
  memset(&regs, 0, sizeof(regs));

  /* Get registers for main LWP */
  memdbg_status_t st = memdbg_debugger_get_regs(MOCK_LWP_MAIN, &regs);
  TEST_OK("get_regs succeeds", st);
  TEST_EQ_LL("RIP matches mock", regs.r_rip, 0x7FFF12340000LL);
  TEST_EQ_LL("RSP matches mock", regs.r_rsp, 0x7FFEE0001000LL);
  TEST_EQ_LL("RAX matches mock", regs.r_rax, 0x42LL);

  /* Set registers */
  regs.r_rip = 0xDEADBEEFLL;
  st = memdbg_debugger_set_regs(MOCK_LWP_MAIN, &regs);
  TEST_OK("set_regs succeeds", st);

  /* Verify change persisted */
  memset(&regs, 0, sizeof(regs));
  st = memdbg_debugger_get_regs(MOCK_LWP_MAIN, &regs);
  TEST_OK("get_regs after set succeeds", st);
  TEST_EQ_LL("RIP updated to DEADBEEF", regs.r_rip, 0xDEADBEEFLL);

  /* Get registers for worker LWP */
  memset(&regs, 0, sizeof(regs));
  st = memdbg_debugger_get_regs(MOCK_LWP_WORKER, &regs);
  TEST_OK("get_regs for worker succeeds", st);
  TEST_EQ_LL("worker RIP", regs.r_rip, 0x7FFF56780000LL);

  /* Invalid LWP */
  st = memdbg_debugger_get_regs(9999, &regs);
  TEST("invalid LWP fails", st != MEMDBG_OK);

  TEST_OK("detach", memdbg_debugger_detach());
}

/* ---- 5. Debug register access ---- */

static void test_debug_registers(void) {
  printf("\n--- Debug Register Access ---\n");

  mock_reset();
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  memdbg_debug_dbregs_t dbregs;
  memset(&dbregs, 0, sizeof(dbregs));

  memdbg_status_t st = memdbg_debugger_get_dbregs(MOCK_LWP_MAIN, &dbregs);
  TEST_OK("get_dbregs succeeds", st);

  /* Set some debug registers */
  dbregs.dr[0] = 0x1000ULL;
  dbregs.dr[7] = 0x155ULL; /* enable dr0 as local+global */
  st = memdbg_debugger_set_dbregs(MOCK_LWP_MAIN, &dbregs);
  TEST_OK("set_dbregs succeeds", st);

  /* Verify change persisted */
  memset(&dbregs, 0, sizeof(dbregs));
  st = memdbg_debugger_get_dbregs(MOCK_LWP_MAIN, &dbregs);
  TEST_OK("get_dbregs after set succeeds", st);
  TEST_EQ_LL("dr0 persisted", dbregs.dr[0], 0x1000ULL);
  TEST_EQ_LL("dr7 persisted", dbregs.dr[7], 0x155ULL);

  TEST_OK("detach", memdbg_debugger_detach());
}

/* ---- 6. Software breakpoint ---- */

static void test_software_breakpoint(void) {
  printf("\n--- Software Breakpoint ---\n");

  mock_reset();

  /* Write a known byte at the breakpoint address */
  mock.memory[0x1000] = 0x90; /* NOP */

  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  /* Set software breakpoint at 0x1000 */
  memdbg_status_t st = memdbg_debugger_set_breakpoint(0x1000ULL,
                                                       MEMDBG_BP_SOFTWARE);
  TEST_OK("set SW breakpoint succeeds", st);

  /* Verify INT3 was written */
  TEST("INT3 written to 0x1000", mock.memory[0x1000] == 0xCCU);

  /* Verify breakpoint list */
  uint32_t bp_count = 0;
  memdbg_breakpoint_t bps[MEMDBG_DEBUGGER_MAX_BREAKPOINTS];
  TEST_OK("breakpoint snapshot",
          memdbg_debugger_breakpoints_snapshot(
              bps, MEMDBG_DEBUGGER_MAX_BREAKPOINTS, &bp_count));
  TEST_EQ_U("breakpoint slots total", bp_count, MEMDBG_DEBUGGER_MAX_BREAKPOINTS);

  int found = 0;
  uint8_t orig = 0;
  for (uint32_t i = 0; i < bp_count; ++i) {
    if (bps[i].active && bps[i].address == 0x1000ULL) {
      found = 1;
      TEST_EQ_U("BP kind is SW", bps[i].kind, MEMDBG_BP_SOFTWARE);
      TEST("BP installed", bps[i].installed);
      TEST("BP active", bps[i].active);
      orig = bps[i].original_byte;
      break;
    }
  }
  TEST("SW BP in list", found);
  TEST("original byte saved = 0x90", orig == 0x90U);

  /* Clear breakpoint */
  st = memdbg_debugger_clear_breakpoint(0x1000ULL);
  TEST_OK("clear breakpoint succeeds", st);

  /* Verify original byte restored */
  TEST("original byte restored to 0x90", mock.memory[0x1000] == 0x90U);

  /* Verify breakpoint list empty */
  TEST_OK("breakpoint snapshot after clear",
          memdbg_debugger_breakpoints_snapshot(
              bps, MEMDBG_DEBUGGER_MAX_BREAKPOINTS, &bp_count));
  int still_active = 0;
  for (uint32_t i = 0; i < bp_count; ++i) {
    if (bps[i].active) still_active++;
  }
  TEST_EQ_I("no active breakpoints after clear", still_active, 0);

  /* Duplicate breakpoint */
  st = memdbg_debugger_set_breakpoint(0x1000ULL, MEMDBG_BP_SOFTWARE);
  TEST_OK("first BP at 0x1000", st);
  st = memdbg_debugger_set_breakpoint(0x1000ULL, MEMDBG_BP_SOFTWARE);
  TEST_ERR("duplicate BP rejected", st, MEMDBG_ERR_PARAM);

  /* Clear non-existent */
  st = memdbg_debugger_clear_breakpoint(0xFFFFULL);
  TEST_ERR("clear non-existent BP", st, MEMDBG_ERR_NOT_FOUND);

  TEST_OK("detach", memdbg_debugger_detach());
}

/* ---- 7. Hardware breakpoint ---- */

static void test_hardware_breakpoint(void) {
  printf("\n--- Hardware Breakpoint ---\n");

  mock_reset();
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  memdbg_status_t st = memdbg_debugger_set_breakpoint(0x2000ULL,
                                                       MEMDBG_BP_HARDWARE);
  TEST_OK("set HW breakpoint succeeds", st);

  /* Verify it appears in breakpoint list */
  uint32_t bp_count = 0;
  memdbg_breakpoint_t bps[MEMDBG_DEBUGGER_MAX_BREAKPOINTS];
  TEST_OK("breakpoint snapshot",
          memdbg_debugger_breakpoints_snapshot(
              bps, MEMDBG_DEBUGGER_MAX_BREAKPOINTS, &bp_count));
  int found = 0;
  for (uint32_t i = 0; i < bp_count; ++i) {
    if (bps[i].active && bps[i].address == 0x2000ULL &&
        bps[i].kind == MEMDBG_BP_HARDWARE) {
      found = 1;
      break;
    }
  }
  TEST("HW BP in breakpoint list", found);

  /* Verify it also appears as a watchpoint (HW BPs consume watchpoint slots) */
  uint32_t wp_count = 0;
  memdbg_watchpoint_t wps[MEMDBG_DEBUGGER_MAX_WATCHPOINTS];
  TEST_OK("watchpoint snapshot",
          memdbg_debugger_watchpoints_snapshot(
              wps, MEMDBG_DEBUGGER_MAX_WATCHPOINTS, &wp_count));
  int wp_found = 0;
  for (uint32_t i = 0; i < wp_count; ++i) {
    if (wps[i].installed && wps[i].address == 0x2000ULL &&
        wps[i].type == 0U /* exec */) {
      wp_found = 1;
      break;
    }
  }
  TEST("HW BP consumes watchpoint slot", wp_found);

  /* Verify dbregs reflect the hardware breakpoint (dr[slot] = address). */
  memdbg_debug_dbregs_t dbregs;
  memset(&dbregs, 0, sizeof(dbregs));
  st = memdbg_debugger_get_dbregs(MOCK_LWP_MAIN, &dbregs);
  TEST_OK("get_dbregs for HW BP check", st);
  int hw_slot_found = 0;
  for (uint32_t s = 0; s < MEMDBG_DEBUGGER_MAX_WATCHPOINTS; ++s) {
    if (dbregs.dr[s] == 0x2000ULL) { hw_slot_found = 1; break; }
  }
  TEST("dbregs have HW BP address", hw_slot_found);

  /* Clear */
  st = memdbg_debugger_clear_breakpoint(0x2000ULL);
  TEST_OK("clear HW breakpoint succeeds", st);

  TEST_OK("detach", memdbg_debugger_detach());
}

/* ---- 8. Watchpoint ---- */

static void test_watchpoint(void) {
  printf("\n--- Watchpoint ---\n");

  mock_reset();
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  /* Set a write watchpoint at 0x3000, length 4 */
  memdbg_status_t st = memdbg_debugger_set_watchpoint(0x3000ULL, 4U, 1U);
  TEST_OK("set watchpoint succeeds", st);

  /* Verify in list */
  uint32_t count = 0;
  memdbg_watchpoint_t wps[MEMDBG_DEBUGGER_MAX_WATCHPOINTS];
  TEST_OK("watchpoint snapshot",
          memdbg_debugger_watchpoints_snapshot(
              wps, MEMDBG_DEBUGGER_MAX_WATCHPOINTS, &count));
  TEST_EQ_U("watchpoint slots total", count, MEMDBG_DEBUGGER_MAX_WATCHPOINTS);

  int found = 0;
  uint32_t found_slot = 0;
  for (uint32_t i = 0; i < count; ++i) {
    if (wps[i].installed && wps[i].address == 0x3000ULL) {
      found = 1;
      found_slot = wps[i].slot;
      TEST_EQ_U("WP length = 4", wps[i].length, 4U);
      TEST_EQ_U("WP type = write", wps[i].type, 1U);
      break;
    }
  }
  TEST("watchpoint in list", found);

  /* Verify dbregs were updated */
  memdbg_debug_dbregs_t dbregs;
  memset(&dbregs, 0, sizeof(dbregs));
  TEST_OK("get_dbregs", memdbg_debugger_get_dbregs(MOCK_LWP_MAIN, &dbregs));
  TEST_EQ_LL("dr[slot] has address", dbregs.dr[found_slot], 0x3000ULL);
  TEST("dr7 has enable bits", (dbregs.dr[7] & (1ULL << (found_slot * 2))) != 0);

  /* Invalid length */
  st = memdbg_debugger_set_watchpoint(0x4000ULL, 3U, 1U);
  TEST_ERR("watchpoint length 3 rejected", st, MEMDBG_ERR_PARAM);

  /* Invalid type */
  st = memdbg_debugger_set_watchpoint(0x4000ULL, 4U, 99U);
  TEST_ERR("watchpoint type 99 rejected", st, MEMDBG_ERR_PARAM);

  /* Duplicate */
  st = memdbg_debugger_set_watchpoint(0x3000ULL, 4U, 1U);
  TEST_ERR("duplicate watchpoint rejected", st, MEMDBG_ERR_PARAM);

  /* Clear */
  st = memdbg_debugger_clear_watchpoint(0x3000ULL);
  TEST_OK("clear watchpoint succeeds", st);

  /* Verify removed from list */
  TEST_OK("watchpoint snapshot after clear",
          memdbg_debugger_watchpoints_snapshot(
              wps, MEMDBG_DEBUGGER_MAX_WATCHPOINTS, &count));
  int still_installed = 0;
  for (uint32_t i = 0; i < count; ++i) {
    if (wps[i].installed) still_installed++;
  }
  TEST_EQ_I("no installed watchpoints after clear", still_installed, 0);

  /* Clear non-existent */
  st = memdbg_debugger_clear_watchpoint(0xFFFFULL);
  TEST_ERR("clear non-existent WP", st, MEMDBG_ERR_NOT_FOUND);

  TEST_OK("detach", memdbg_debugger_detach());
}

/* ---- 9. Thread suspend / resume ---- */

static void test_thread_suspend_resume(void) {
  printf("\n--- Thread Suspend / Resume ---\n");

  mock_reset();
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  memdbg_status_t st = memdbg_debugger_suspend_thread(MOCK_LWP_WORKER);
  TEST_OK("suspend worker thread", st);
  TEST("suspend called on worker", mock.suspend_called[1]);

  st = memdbg_debugger_resume_thread(MOCK_LWP_WORKER);
  TEST_OK("resume worker thread", st);
  TEST("resume called on worker", mock.resume_called[1]);

  TEST_OK("detach", memdbg_debugger_detach());
}

/* ---- 10. Poll events ---- */

static void test_poll_events(void) {
  printf("\n--- Poll Events ---\n");

  mock_reset();

  /* Simulate: attach → wait returns SIGTRAP → stopped */
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));
  TEST("stopped after attach", memdbg_debugger_is_stopped());

  /* Continue, then poll with a stop event */
  TEST_OK("continue", memdbg_debugger_continue());
  TEST("not stopped after continue", !memdbg_debugger_is_stopped());

  /* Simulate a stop event on next wait */
  mock.stopped = true;  /* PAL stop called externally (e.g. by signal) */

  memdbg_status_t st = memdbg_debugger_poll_events();
  TEST_OK("poll_events succeeds", st);
  TEST("stopped after poll", memdbg_debugger_is_stopped());

  /* Verify stop_lwp: set worker RIP to a mock-range address (0x6001),
   * set a SW BP at 0x6000 so RIP-1 matches, call stop() which sends
   * SIGSTOP and polls.  We use stop() instead of continue+external-stop
   * because continue() would step over the SW breakpoint and modify RIP. */
  {
    memdbg_debug_regs_t regs;
    memset(&regs, 0, sizeof(regs));
    memdbg_status_t st = memdbg_debugger_get_regs(MOCK_LWP_WORKER, &regs);
    TEST_OK("get worker regs", st);

    int64_t saved_rip = regs.r_rip;
    regs.r_rip = 0x6001LL;
    st = memdbg_debugger_set_regs(MOCK_LWP_WORKER, &regs);
    TEST_OK("set worker RIP to 0x6001", st);

    mock.memory[0x6000] = 0x90;
    st = memdbg_debugger_set_breakpoint(0x6000ULL, MEMDBG_BP_SOFTWARE);
    TEST_OK("set BP at 0x6000", st);

    /* Call stop() — sends SIGSTOP and polls internally. */
    st = memdbg_debugger_stop();
    TEST_OK("stop succeeds", st);
    TEST("stopped after stop", memdbg_debugger_is_stopped());
    TEST_EQ_I("stop_lwp matches worker", memdbg_debugger_get_stop_lwp(),
              MOCK_LWP_WORKER);

    /* Restore worker RIP. */
    regs.r_rip = saved_rip;
    (void)memdbg_debugger_set_regs(MOCK_LWP_WORKER, &regs);
  }

  TEST_OK("detach", memdbg_debugger_detach());
}

/* ---- 11. Max breakpoints / watchpoints ---- */

static void test_max_breakpoints_watchpoints(void) {
  printf("\n--- Max Breakpoints / Watchpoints ---\n");

  mock_reset();
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  /* Fill all breakpoint slots */
  memdbg_status_t st;
  int i;
  for (i = 0; i < (int)MEMDBG_DEBUGGER_MAX_BREAKPOINTS; ++i) {
    st = memdbg_debugger_set_breakpoint((uint64_t)(0x1000 + i),
                                         MEMDBG_BP_SOFTWARE);
    if (st != MEMDBG_OK) break;
  }
  TEST_EQ_I("installed max BPs", i, (int)MEMDBG_DEBUGGER_MAX_BREAKPOINTS);

  /* Next should fail */
  st = memdbg_debugger_set_breakpoint(0xFFFFULL, MEMDBG_BP_SOFTWARE);
  TEST_ERR("BP overflow rejected", st, MEMDBG_ERR_NOMEM);

  /* Clear one and add again */
  st = memdbg_debugger_clear_breakpoint(0x1000ULL);
  TEST_OK("clear BP to free slot", st);
  st = memdbg_debugger_set_breakpoint(0xFFFFULL, MEMDBG_BP_SOFTWARE);
  TEST_OK("BP after freeing slot", st);

  /* Clear all remaining */
  uint32_t count = 0;
  memdbg_breakpoint_t bps[MEMDBG_DEBUGGER_MAX_BREAKPOINTS];
  TEST_OK("breakpoint snapshot before clear remaining",
          memdbg_debugger_breakpoints_snapshot(
              bps, MEMDBG_DEBUGGER_MAX_BREAKPOINTS, &count));
  for (uint32_t j = 0; j < count; ++j) {
    if (bps[j].active) memdbg_debugger_clear_breakpoint(bps[j].address);
  }

  /* Fill all watchpoint slots */
  uint64_t wp_addrs[] = {0x3000, 0x3010, 0x3020, 0x3030};
  int wp_count = (int)MEMDBG_DEBUGGER_MAX_WATCHPOINTS;
  for (i = 0; i < wp_count; ++i) {
    st = memdbg_debugger_set_watchpoint(wp_addrs[i], 4U, 1U);
    if (st != MEMDBG_OK) break;
  }
  TEST_EQ_I("installed max WPs", i, wp_count);

  /* Next should fail */
  st = memdbg_debugger_set_watchpoint(0x4000ULL, 4U, 1U);
  TEST_ERR("WP overflow rejected", st, MEMDBG_ERR_NOMEM);

  TEST_OK("detach", memdbg_debugger_detach());
}

/* ---- 11b. Detach with active software breakpoints ---- */

static void test_detach_with_active_bp(void) {
  printf("\n--- Detach with active SW breakpoint ---\n");

  mock_reset();
  mock.memory[0x5000] = 0x90; /* NOP */

  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  /* Set a software breakpoint but do NOT clear it. */
  memdbg_status_t st = memdbg_debugger_set_breakpoint(0x5000ULL,
                                                       MEMDBG_BP_SOFTWARE);
  TEST_OK("set SW BP at 0x5000", st);
  TEST("INT3 written", mock.memory[0x5000] == 0xCCU);

  /* Detach — should automatically uninstall the breakpoint. */
  st = memdbg_debugger_detach();
  TEST_OK("detach succeeds", st);

  /* Verify original byte (0x90) was restored. */
  TEST("original byte restored after detach", mock.memory[0x5000] == 0x90U);

  TEST("not attached after detach", !memdbg_debugger_is_attached());
}

/* ---- 12. Operations while detached should fail ---- */

static void test_error_when_detached(void) {
  printf("\n--- Error: operations while detached ---\n");

  mock_reset();

  memdbg_status_t st;

  st = memdbg_debugger_stop();
  TEST_ERR("stop while detached", st, MEMDBG_ERR_STATE);

  st = memdbg_debugger_continue();
  TEST_ERR("continue while detached", st, MEMDBG_ERR_STATE);

  st = memdbg_debugger_step(MOCK_LWP_MAIN);
  TEST_ERR("step while detached", st, MEMDBG_ERR_STATE);

  st = memdbg_debugger_set_breakpoint(0x1000ULL, MEMDBG_BP_SOFTWARE);
  TEST_ERR("set BP while detached", st, MEMDBG_ERR_STATE);

  st = memdbg_debugger_set_watchpoint(0x3000ULL, 4U, 1U);
  TEST_ERR("set WP while detached", st, MEMDBG_ERR_STATE);

  st = memdbg_debugger_suspend_thread(MOCK_LWP_MAIN);
  TEST_ERR("suspend while detached", st, MEMDBG_ERR_STATE);

  st = memdbg_debugger_resume_thread(MOCK_LWP_MAIN);
  TEST_ERR("resume while detached", st, MEMDBG_ERR_STATE);

  int32_t lwps[8];
  uint32_t count = 0;
  st = memdbg_debugger_get_threads(lwps, NULL, NULL, &count, 8);
  TEST_ERR("get_threads while detached", st, MEMDBG_ERR_STATE);

  memdbg_debug_regs_t regs;
  st = memdbg_debugger_get_regs(MOCK_LWP_MAIN, &regs);
  TEST_ERR("get_regs while detached", st, MEMDBG_ERR_STATE);

  st = memdbg_debugger_poll_events();
  TEST_ERR("poll_events while detached", st, MEMDBG_ERR_STATE);
}

/* ---- 13. Attach with invalid PID ---- */

static void test_attach_invalid_pid(void) {
  printf("\n--- Error: attach invalid PID ---\n");

  mock_reset();

  memdbg_status_t st = memdbg_debugger_attach(0);
  TEST("attach PID 0 fails", st != MEMDBG_OK);

  st = memdbg_debugger_attach(1);
  TEST("attach PID 1 fails", st != MEMDBG_OK);
}

/* ---- 14. Attach errno mapping ---- */

static void test_attach_errno_mapping(void) {
  printf("\n--- Error: attach errno mapping ---\n");

  mock_reset();
  mock.attach_errno = EPERM;
  TEST_ERR("attach EPERM maps to permission",
           memdbg_debugger_attach(MOCK_PID), MEMDBG_ERR_PERMISSION);
  TEST("not attached after EPERM", !memdbg_debugger_is_attached());

  mock_reset();
  mock.attach_errno = ESRCH;
  TEST_ERR("attach ESRCH maps to not found",
           memdbg_debugger_attach(MOCK_PID), MEMDBG_ERR_NOT_FOUND);
  TEST("not attached after ESRCH", !memdbg_debugger_is_attached());

#ifdef ETIMEDOUT
  mock_reset();
  mock.attach_errno = ETIMEDOUT;
  TEST_ERR("attach ETIMEDOUT maps to state",
           memdbg_debugger_attach(MOCK_PID), MEMDBG_ERR_STATE);
  TEST("not attached after ETIMEDOUT", !memdbg_debugger_is_attached());
#endif
}

/* ---- 15. Batch clear-all breakpoints / watchpoints ---- */

static void test_batch_clear(void) {
  printf("\n--- Batch Clear-All ---\n");

  /* ---- Clear-all breakpoints ---- */
  mock_reset();
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  /* Set 3 software breakpoints */
  mock.memory[0x1000] = 0x90;
  mock.memory[0x2000] = 0x90;
  mock.memory[0x3000] = 0x90;
  TEST_OK("BP at 0x1000",
          memdbg_debugger_set_breakpoint(0x1000ULL, MEMDBG_BP_SOFTWARE));
  TEST_OK("BP at 0x2000",
          memdbg_debugger_set_breakpoint(0x2000ULL, MEMDBG_BP_SOFTWARE));
  TEST_OK("BP at 0x3000",
          memdbg_debugger_set_breakpoint(0x3000ULL, MEMDBG_BP_SOFTWARE));

  uint32_t cleared = 0;
  memdbg_status_t st = memdbg_debugger_clear_all_breakpoints(&cleared);
  TEST_OK("clear-all BPs succeeds", st);
  TEST_EQ_U("cleared 3 BPs", cleared, 3U);

  /* Verify all restored */
  TEST("0x1000 restored", mock.memory[0x1000] == 0x90U);
  TEST("0x2000 restored", mock.memory[0x2000] == 0x90U);
  TEST("0x3000 restored", mock.memory[0x3000] == 0x90U);

  /* Verify list is empty */
  uint32_t bp_count = 0;
  memdbg_breakpoint_t bps[MEMDBG_DEBUGGER_MAX_BREAKPOINTS];
  TEST_OK("breakpoint snapshot after clear-all",
          memdbg_debugger_breakpoints_snapshot(
              bps, MEMDBG_DEBUGGER_MAX_BREAKPOINTS, &bp_count));
  int active = 0;
  for (uint32_t i = 0; i < bp_count; ++i) { if (bps[i].active) ++active; }
  TEST_EQ_I("no active BPs after clear-all", active, 0);

  /* Clear-all when already empty */
  st = memdbg_debugger_clear_all_breakpoints(&cleared);
  TEST_OK("clear-all BPs on empty succeeds", st);
  TEST_EQ_U("cleared 0 BPs", cleared, 0U);

  TEST_OK("detach", memdbg_debugger_detach());

  /* Clear-all while detached */
  st = memdbg_debugger_clear_all_breakpoints(&cleared);
  TEST_ERR("clear-all BPs while detached", st, MEMDBG_ERR_STATE);

  /* ---- Clear-all watchpoints ---- */
  mock_reset();
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  /* Set 2 watchpoints */
  TEST_OK("WP at 0x4000",
          memdbg_debugger_set_watchpoint(0x4000ULL, 4U, 1U));
  TEST_OK("WP at 0x4010",
          memdbg_debugger_set_watchpoint(0x4010ULL, 8U, 2U));

  st = memdbg_debugger_clear_all_watchpoints(&cleared);
  TEST_OK("clear-all WPs succeeds", st);
  TEST_EQ_U("cleared 2 WPs", cleared, 2U);

  /* Verify list is empty */
  uint32_t wp_count = 0;
  memdbg_watchpoint_t wps[MEMDBG_DEBUGGER_MAX_WATCHPOINTS];
  TEST_OK("watchpoint snapshot after clear-all",
          memdbg_debugger_watchpoints_snapshot(
              wps, MEMDBG_DEBUGGER_MAX_WATCHPOINTS, &wp_count));
  int installed = 0;
  for (uint32_t i = 0; i < wp_count; ++i) { if (wps[i].installed) ++installed; }
  TEST_EQ_I("no installed WPs after clear-all", installed, 0);

  /* Verify dbregs cleared */
  memdbg_debug_dbregs_t dbregs;
  memset(&dbregs, 0, sizeof(dbregs));
  st = memdbg_debugger_get_dbregs(MOCK_LWP_MAIN, &dbregs);
  TEST_OK("get_dbregs after WP clear-all", st);
  TEST("dr7 is 0 after clear-all", dbregs.dr[7] == 0ULL);

  /* Clear-all when already empty */
  st = memdbg_debugger_clear_all_watchpoints(&cleared);
  TEST_OK("clear-all WPs on empty succeeds", st);
  TEST_EQ_U("cleared 0 WPs", cleared, 0U);

  TEST_OK("detach", memdbg_debugger_detach());

  /* Clear-all while detached */
  st = memdbg_debugger_clear_all_watchpoints(&cleared);
  TEST_ERR("clear-all WPs while detached", st, MEMDBG_ERR_STATE);

  /* ---- Mixed SW/HW breakpoints clear-all ---- */
  mock_reset();
  TEST_OK("attach", memdbg_debugger_attach(MOCK_PID));

  mock.memory[0x5000] = 0x90;
  TEST_OK("SW BP at 0x5000",
          memdbg_debugger_set_breakpoint(0x5000ULL, MEMDBG_BP_SOFTWARE));
  TEST_OK("HW BP at 0x6000",
          memdbg_debugger_set_breakpoint(0x6000ULL, MEMDBG_BP_HARDWARE));

  st = memdbg_debugger_clear_all_breakpoints(&cleared);
  TEST_OK("clear-all mixed BPs succeeds", st);
  TEST_EQ_U("cleared 2 mixed BPs", cleared, 2U);
  TEST("SW BP INT3 restored", mock.memory[0x5000] == 0x90U);

  TEST_OK("breakpoint snapshot after mixed clear-all",
          memdbg_debugger_breakpoints_snapshot(
              bps, MEMDBG_DEBUGGER_MAX_BREAKPOINTS, &bp_count));
  active = 0;
  for (uint32_t i = 0; i < bp_count; ++i) { if (bps[i].active) ++active; }
  TEST_EQ_I("no active BPs after mixed clear-all", active, 0);

  /* Verify HW BP watchpoint slot also freed */
  TEST_OK("watchpoint snapshot after mixed clear-all",
          memdbg_debugger_watchpoints_snapshot(
              wps, MEMDBG_DEBUGGER_MAX_WATCHPOINTS, &wp_count));
  installed = 0;
  for (uint32_t i = 0; i < wp_count; ++i) { if (wps[i].installed) ++installed; }
  TEST_EQ_I("no installed WPs after mixed clear-all", installed, 0);

  TEST_OK("detach", memdbg_debugger_detach());
}

/* ======================================================================
 * Main
 * ====================================================================== */

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("=== Debugger Subsystem Tests ===\n");
  printf("Testing: attach/detach, stop/continue/step, threads, registers,\n");
  printf("         breakpoints (SW+HW), watchpoints, poll events, error paths\n\n");

  test_attach_detach();
  test_stop_continue_step();
  test_thread_enumeration();
  test_register_access();
  test_debug_registers();
  test_software_breakpoint();
  test_hardware_breakpoint();
  test_watchpoint();
  test_thread_suspend_resume();
  test_poll_events();
  test_detach_with_active_bp();
  test_max_breakpoints_watchpoints();
  test_error_when_detached();
  test_attach_invalid_pid();
  test_attach_errno_mapping();
  test_batch_clear();

  printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  printf("Total:  %d\n", total);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}
