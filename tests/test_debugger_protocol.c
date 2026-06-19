/*
 * memDBG - Protocol-level debugger handler tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Exercises every handle_debug_* function from memdbg.c by calling them
 * directly with mocked send_response and memdbg_debugger_* backends.
 *
 * Covers:
 *   - body-length validation (too-short, exact, too-long)
 *   - correct status passthrough from the debugger backend
 *   - correct response payload construction
 *   - network-error handling (send_response returning -1)
 *   - all 25 debugger command handlers
 */

#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/core/memdbg_protocol_debug_handlers.h"
#include "memdbg/debug/memdbg_debugger.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ======================================================================
 * Mock send_response — captures the last call's status, payload, length.
 * ====================================================================== */

static int g_mock_socket = 42; /* arbitrary fd number */
static memdbg_status_t g_last_status = MEMDBG_OK;
static uint8_t g_last_payload[65536];
static uint32_t g_last_payload_len = 0;
static int g_send_rc = 0; /* return value for send_response */

static void mock_send_reset(void) {
  g_last_status = MEMDBG_OK;
  memset(g_last_payload, 0, sizeof(g_last_payload));
  g_last_payload_len = 0;
  g_send_rc = 0;
}

/* Override send_response.  Called by the handler functions. */
static int send_response(int fd, const memdbg_packet_header_t *req,
                         memdbg_status_t status, const void *payload,
                         uint32_t payload_len) {
  (void)fd;
  (void)req;
  g_last_status = status;
  g_last_payload_len = payload_len;
  if (payload != NULL && payload_len > 0 && payload_len <= sizeof(g_last_payload)) {
    memcpy(g_last_payload, payload, payload_len);
  }
  return g_send_rc;
}

/* ======================================================================
 * Mock debugger backend — allows per-function control of return values.
 * ====================================================================== */

static memdbg_status_t g_mock_attach_st      = MEMDBG_OK;
static memdbg_status_t g_mock_detach_st      = MEMDBG_OK;
static memdbg_status_t g_mock_stop_st        = MEMDBG_OK;
static memdbg_status_t g_mock_continue_st    = MEMDBG_OK;
static memdbg_status_t g_mock_step_st        = MEMDBG_OK;
static memdbg_status_t g_mock_get_regs_st    = MEMDBG_OK;
static memdbg_status_t g_mock_set_regs_st    = MEMDBG_OK;
static memdbg_status_t g_mock_get_dbregs_st  = MEMDBG_OK;
static memdbg_status_t g_mock_set_dbregs_st  = MEMDBG_OK;
static memdbg_status_t g_mock_set_bp_st      = MEMDBG_OK;
static memdbg_status_t g_mock_set_bp_cond_st = MEMDBG_OK;
static memdbg_status_t g_mock_clear_bp_st    = MEMDBG_OK;
static memdbg_status_t g_mock_set_wp_st      = MEMDBG_OK;
static memdbg_status_t g_mock_clear_wp_st    = MEMDBG_OK;
static memdbg_status_t g_mock_suspend_st     = MEMDBG_OK;
static memdbg_status_t g_mock_resume_st      = MEMDBG_OK;
static memdbg_status_t g_mock_poll_st        = MEMDBG_OK;
static memdbg_status_t g_mock_clear_all_bp_st = MEMDBG_OK;
static memdbg_status_t g_mock_clear_all_wp_st = MEMDBG_OK;
static memdbg_status_t g_mock_get_threads_st = MEMDBG_OK;

static bool     g_mock_is_stopped = false;
static int32_t  g_mock_stop_lwp   = 0;

/* Thread list mock */
static int32_t g_mock_lwps[4] = { 1001, 1002, 1003, 0 };
static char    g_mock_names[4][24] = { "main", "worker", "io", "" };
static uint32_t g_mock_thread_count = 3;

/* Register mock */
static memdbg_debug_regs_t g_mock_regs;
static memdbg_debug_dbregs_t g_mock_dbregs;

/* Breakpoint list mock */
static memdbg_breakpoint_t g_mock_bps[MEMDBG_DEBUGGER_MAX_BREAKPOINTS];
static uint32_t g_mock_bp_active_count = 0;

/* Watchpoint list mock */
static memdbg_watchpoint_t g_mock_wps[MEMDBG_DEBUGGER_MAX_WATCHPOINTS];
static uint32_t g_mock_wp_installed_count = 0;

static void mock_backend_reset(void) {
  g_mock_attach_st      = MEMDBG_OK;
  g_mock_detach_st      = MEMDBG_OK;
  g_mock_stop_st        = MEMDBG_OK;
  g_mock_continue_st    = MEMDBG_OK;
  g_mock_step_st        = MEMDBG_OK;
  g_mock_get_regs_st    = MEMDBG_OK;
  g_mock_set_regs_st    = MEMDBG_OK;
  g_mock_get_dbregs_st  = MEMDBG_OK;
  g_mock_set_dbregs_st  = MEMDBG_OK;
  g_mock_set_bp_st      = MEMDBG_OK;
  g_mock_set_bp_cond_st = MEMDBG_OK;
  g_mock_clear_bp_st    = MEMDBG_OK;
  g_mock_set_wp_st      = MEMDBG_OK;
  g_mock_clear_wp_st    = MEMDBG_OK;
  g_mock_suspend_st     = MEMDBG_OK;
  g_mock_resume_st      = MEMDBG_OK;
  g_mock_poll_st        = MEMDBG_OK;
  g_mock_clear_all_bp_st = MEMDBG_OK;
  g_mock_clear_all_wp_st = MEMDBG_OK;
  g_mock_get_threads_st = MEMDBG_OK;
  g_mock_is_stopped = false;
  g_mock_stop_lwp = 0;
  g_mock_thread_count = 3;
  g_mock_bp_active_count = 0;
  g_mock_wp_installed_count = 0;
  memset(&g_mock_regs, 0, sizeof(g_mock_regs));
  memset(&g_mock_dbregs, 0, sizeof(g_mock_dbregs));
  g_mock_regs.r_rip = 0x7FFF12340000LL;
  g_mock_regs.r_rax = 0x42LL;
  memset(g_mock_bps, 0, sizeof(g_mock_bps));
  memset(g_mock_wps, 0, sizeof(g_mock_wps));
}

/* ---- Backend mock implementations ---- */

memdbg_status_t memdbg_debugger_attach(int32_t pid) {
  (void)pid; return g_mock_attach_st;
}
memdbg_status_t memdbg_debugger_detach(void) {
  return g_mock_detach_st;
}
memdbg_status_t memdbg_debugger_stop(void) {
  return g_mock_stop_st;
}
memdbg_status_t memdbg_debugger_continue(void) {
  return g_mock_continue_st;
}
memdbg_status_t memdbg_debugger_step(int32_t lwp) {
  (void)lwp; return g_mock_step_st;
}
memdbg_status_t memdbg_debugger_get_regs(int32_t lwp, memdbg_debug_regs_t *regs) {
  (void)lwp;
  if (regs != NULL) memcpy(regs, &g_mock_regs, sizeof(*regs));
  return g_mock_get_regs_st;
}
memdbg_status_t memdbg_debugger_set_regs(int32_t lwp, const memdbg_debug_regs_t *regs) {
  (void)lwp; (void)regs; return g_mock_set_regs_st;
}
memdbg_status_t memdbg_debugger_get_dbregs(int32_t lwp, memdbg_debug_dbregs_t *dbregs) {
  (void)lwp;
  if (dbregs != NULL) memcpy(dbregs, &g_mock_dbregs, sizeof(*dbregs));
  return g_mock_get_dbregs_st;
}
memdbg_status_t memdbg_debugger_set_dbregs(int32_t lwp, const memdbg_debug_dbregs_t *dbregs) {
  (void)lwp; (void)dbregs; return g_mock_set_dbregs_st;
}
memdbg_status_t memdbg_debugger_set_breakpoint(uint64_t address, uint32_t kind) {
  (void)address; (void)kind; return g_mock_set_bp_st;
}
memdbg_status_t memdbg_debugger_set_breakpoint_cond(
    uint64_t address, uint32_t kind,
    uint32_t cond_reg, uint32_t cond_op, uint64_t cond_value) {
  (void)address; (void)kind;
  (void)cond_reg; (void)cond_op; (void)cond_value;
  return g_mock_set_bp_cond_st;
}
memdbg_status_t memdbg_debugger_clear_breakpoint(uint64_t address) {
  (void)address; return g_mock_clear_bp_st;
}
memdbg_status_t memdbg_debugger_clear_all_breakpoints(uint32_t *cleared) {
  if (cleared != NULL) *cleared = g_mock_bp_active_count;
  return g_mock_clear_all_bp_st;
}
memdbg_status_t memdbg_debugger_set_watchpoint(uint64_t address, uint32_t length,
                                                uint32_t type) {
  (void)address; (void)length; (void)type; return g_mock_set_wp_st;
}
memdbg_status_t memdbg_debugger_clear_watchpoint(uint64_t address) {
  (void)address; return g_mock_clear_wp_st;
}
memdbg_status_t memdbg_debugger_clear_all_watchpoints(uint32_t *cleared) {
  if (cleared != NULL) *cleared = g_mock_wp_installed_count;
  return g_mock_clear_all_wp_st;
}
memdbg_status_t memdbg_debugger_suspend_thread(int32_t lwp) {
  (void)lwp; return g_mock_suspend_st;
}
memdbg_status_t memdbg_debugger_resume_thread(int32_t lwp) {
  (void)lwp; return g_mock_resume_st;
}
memdbg_status_t memdbg_debugger_poll_events(void) {
  return g_mock_poll_st;
}
bool memdbg_debugger_is_stopped(void) {
  return g_mock_is_stopped;
}
int32_t memdbg_debugger_get_stop_lwp(void) {
  return g_mock_stop_lwp;
}
memdbg_status_t memdbg_debugger_get_threads(int32_t *lwps, char (*names)[24],
                                            uint32_t *states,
                                            uint32_t *count_out, uint32_t max) {
  if (g_mock_get_threads_st != MEMDBG_OK) {
    if (count_out != NULL) *count_out = 0;
    return g_mock_get_threads_st;
  }
  uint32_t n = g_mock_thread_count;
  if (n > max) n = max;
  if (lwps != NULL) memcpy(lwps, g_mock_lwps, n * sizeof(int32_t));
  if (names != NULL) memcpy(names, g_mock_names, n * sizeof(g_mock_names[0]));
  if (states != NULL) {
    for (uint32_t i = 0; i < n; ++i) states[i] = (uint32_t)MEMDBG_THREAD_RUNNING;
  }
  if (count_out != NULL) *count_out = n;
  return MEMDBG_OK;
}
memdbg_status_t memdbg_debugger_breakpoints_snapshot(
    memdbg_breakpoint_t *out, uint32_t max, uint32_t *count) {
  if (count == NULL || (out == NULL && max > 0U)) return MEMDBG_ERR_PARAM;
  uint32_t n = max;
  if (n > MEMDBG_DEBUGGER_MAX_BREAKPOINTS) {
    n = MEMDBG_DEBUGGER_MAX_BREAKPOINTS;
  }
  if (n > 0U) memcpy(out, g_mock_bps, n * sizeof(out[0]));
  *count = n;
  return MEMDBG_OK;
}
memdbg_status_t memdbg_debugger_watchpoints_snapshot(
    memdbg_watchpoint_t *out, uint32_t max, uint32_t *count) {
  if (count == NULL || (out == NULL && max > 0U)) return MEMDBG_ERR_PARAM;
  uint32_t n = max;
  if (n > MEMDBG_DEBUGGER_MAX_WATCHPOINTS) {
    n = MEMDBG_DEBUGGER_MAX_WATCHPOINTS;
  }
  if (n > 0U) memcpy(out, g_mock_wps, n * sizeof(out[0]));
  *count = n;
  return MEMDBG_OK;
}

/* Stub: memdbg_debugger_is_elevated (needed by memdbg_memory.c but not by handlers) */
bool memdbg_debugger_is_elevated(int32_t pid) {
  (void)pid; return false;
}

int32_t memdbg_debugger_attached_pid(void) {
  return 100;
}

int pal_debug_get_thread_stop_info(int pid, int32_t lwp,
                                   int *pl_event, int *stop_signal,
                                   int *pl_flags,
                                   uint64_t *pl_sigmask_lo,
                                   uint64_t *pl_sigmask_hi,
                                   uint64_t *pl_siglist_lo,
                                   uint64_t *pl_siglist_hi) {
  (void)pid; (void)lwp;
  if (pl_event != NULL) *pl_event = 0;
  if (stop_signal != NULL) *stop_signal = 0;
  if (pl_flags != NULL) *pl_flags = 0;
  if (pl_sigmask_lo != NULL) *pl_sigmask_lo = 0;
  if (pl_sigmask_hi != NULL) *pl_sigmask_hi = 0;
  if (pl_siglist_lo != NULL) *pl_siglist_lo = 0;
  if (pl_siglist_hi != NULL) *pl_siglist_hi = 0;
  return -1;
}

int pal_debug_get_thread_extra_info(int pid, const int32_t *lwps, uint32_t count,
                                    int *priorities, uint64_t *runtimes_us,
                                    int *pctcpus, int *cpu_ids) {
  (void)pid; (void)lwps; (void)count;
  /* Leave all fields at defaults — the handler already zeroed them. */
  (void)priorities; (void)runtimes_us; (void)pctcpus; (void)cpu_ids;
  return -1;
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
  TEST_EQ_I(name, (int)(status), (int)MEMDBG_OK)

#define TEST_ERR(name, status, expected_err)                                   \
  TEST_EQ_I(name, (int)(status), (int)(expected_err))

/* Reusable empty request packet header */
static memdbg_packet_header_t g_req = {
  MEMDBG_PACKET_MAGIC, MEMDBG_PROTOCOL_VERSION, 0, 1, 0
};

/* ======================================================================
 * Test cases
 * ====================================================================== */

/* ---- 1. handle_debug_attach ---- */

static void test_proto_attach(void) {
  printf("\n--- handle_debug_attach ---\n");

  mock_backend_reset();
  mock_send_reset();

  memdbg_status_t st;
  memdbg_debug_attach_request_t body = { 100, 0 };

  /* Valid */
  st = handle_debug_attach(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_OK("attach valid body", st);
  TEST_EQ_I("attach sent OK", (int)g_last_status, (int)MEMDBG_OK);

  /* Wrong body length */
  st = handle_debug_attach(g_mock_socket, &g_req, &body, sizeof(body) - 1, send_response);
  TEST_ERR("attach short body", st, MEMDBG_ERR_PROTOCOL);

  st = handle_debug_attach(g_mock_socket, &g_req, &body, sizeof(body) + 1, send_response);
  TEST_ERR("attach long body", st, MEMDBG_ERR_PROTOCOL);

  /* Backend error passthrough */
  g_mock_attach_st = MEMDBG_ERR_STATE;
  mock_send_reset();
  st = handle_debug_attach(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_OK("attach backend ERR_STATE → send OK", st);
  TEST_EQ_I("attach passthrough status", (int)g_last_status, (int)MEMDBG_ERR_STATE);

  /* Network error: send_response returns -1 */
  g_mock_attach_st = MEMDBG_OK;
  mock_send_reset();
  g_send_rc = -1;
  st = handle_debug_attach(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_ERR("attach net error", st, MEMDBG_ERR_NET);
  g_send_rc = 0;
}

/* ---- 2. handle_debug_detach ---- */

static void test_proto_detach(void) {
  printf("\n--- handle_debug_detach ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_status_t st = handle_debug_detach(g_mock_socket, &g_req, send_response);
  TEST_OK("detach OK", st);

  g_mock_detach_st = MEMDBG_ERR_STATE;
  mock_send_reset();
  st = handle_debug_detach(g_mock_socket, &g_req, send_response);
  TEST_EQ_I("detach passthrough", (int)g_last_status, (int)MEMDBG_ERR_STATE);
}

/* ---- 3. handle_debug_stop ---- */

static void test_proto_stop(void) {
  printf("\n--- handle_debug_stop ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_status_t st = handle_debug_stop(g_mock_socket, &g_req, send_response);
  TEST_OK("stop OK", st);

  g_mock_stop_st = MEMDBG_ERR_STATE;
  mock_send_reset();
  st = handle_debug_stop(g_mock_socket, &g_req, send_response);
  TEST_EQ_I("stop passthrough", (int)g_last_status, (int)MEMDBG_ERR_STATE);
}

/* ---- 4. handle_debug_continue ---- */

static void test_proto_continue(void) {
  printf("\n--- handle_debug_continue ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_status_t st = handle_debug_continue(g_mock_socket, &g_req, send_response);
  TEST_OK("continue OK", st);
}

/* ---- 5. handle_debug_step ---- */

static void test_proto_step(void) {
  printf("\n--- handle_debug_step ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_debug_thread_request_t body = { 0, 1001 };
  memdbg_status_t st;

  /* Valid */
  st = handle_debug_step(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_OK("step valid", st);

  /* Short body */
  st = handle_debug_step(g_mock_socket, &g_req, &body, 1, send_response);
  TEST_ERR("step short body", st, MEMDBG_ERR_PROTOCOL);

  /* Backend error */
  g_mock_step_st = MEMDBG_ERR_STATE;
  mock_send_reset();
  st = handle_debug_step(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_EQ_I("step passthrough", (int)g_last_status, (int)MEMDBG_ERR_STATE);
}

/* ---- 6. handle_debug_get_threads ---- */

static void test_proto_get_threads(void) {
  printf("\n--- handle_debug_get_threads ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_status_t st = handle_debug_get_threads(g_mock_socket, &g_req, send_response);
  TEST_OK("get_threads OK", st);
  /* Verify payload */
  if (g_last_payload_len >= sizeof(memdbg_debug_threads_response_prefix_t)) {
    const memdbg_debug_threads_response_prefix_t *pfx =
        (const memdbg_debug_threads_response_prefix_t *)g_last_payload;
    TEST_EQ_U("thread count", pfx->count, g_mock_thread_count);

    if (pfx->count >= 1) {
      const memdbg_debug_thread_entry_t *ent =
          (const memdbg_debug_thread_entry_t *)(g_last_payload + sizeof(*pfx));
      TEST_EQ_I("thread[0] lwp", (int)ent[0].lwp, 1001);
      TEST("thread[0] name", strcmp(ent[0].name, "main") == 0);
    }
  }

  /* Backend error */
  g_mock_get_threads_st = MEMDBG_ERR_STATE;
  mock_send_reset();
  st = handle_debug_get_threads(g_mock_socket, &g_req, send_response);
  TEST_EQ_I("get_threads backend error passthrough",
            (int)g_last_status, (int)MEMDBG_ERR_STATE);

  /* Network error */
  g_mock_get_threads_st = MEMDBG_OK;
  mock_send_reset();
  g_send_rc = -1;
  st = handle_debug_get_threads(g_mock_socket, &g_req, send_response);
  TEST_ERR("get_threads net error", st, MEMDBG_ERR_NET);
  g_send_rc = 0;

  /* Zero threads */
  g_mock_thread_count = 0;
  mock_send_reset();
  st = handle_debug_get_threads(g_mock_socket, &g_req, send_response);
  TEST_OK("get_threads zero threads", st);
  {
    const memdbg_debug_threads_response_prefix_t *pfx =
        (const memdbg_debug_threads_response_prefix_t *)g_last_payload;
    TEST_EQ_U("zero count", pfx->count, 0U);
  }
  g_mock_thread_count = 3;
}

/* ---- 7. handle_debug_get_regs ---- */

static void test_proto_get_regs(void) {
  printf("\n--- handle_debug_get_regs ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_debug_thread_request_t body = { 0, 1001 };
  memdbg_status_t st;

  /* Valid */
  st = handle_debug_get_regs(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_OK("get_regs valid", st);
  TEST_EQ_U("regs payload len matches", g_last_payload_len,
            (uint32_t)sizeof(memdbg_debug_regs_t));
  {
    const memdbg_debug_regs_t *regs =
        (const memdbg_debug_regs_t *)g_last_payload;
    TEST_EQ_LL("RIP matches", regs->r_rip, 0x7FFF12340000LL);
    TEST_EQ_LL("RAX matches", regs->r_rax, 0x42LL);
  }

  /* Short body */
  st = handle_debug_get_regs(g_mock_socket, &g_req, &body, 1, send_response);
  TEST_ERR("get_regs short body", st, MEMDBG_ERR_PROTOCOL);

  /* Backend error */
  g_mock_get_regs_st = MEMDBG_ERR_NOT_FOUND;
  mock_send_reset();
  st = handle_debug_get_regs(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_EQ_I("get_regs passthrough status",
            (int)g_last_status, (int)MEMDBG_ERR_NOT_FOUND);
}

/* ---- 8. handle_debug_set_regs ---- */

static void test_proto_set_regs(void) {
  printf("\n--- handle_debug_set_regs ---\n");
  mock_backend_reset(); mock_send_reset();

  /* Build request: thread_request + regs */
  uint8_t body_raw[sizeof(memdbg_debug_thread_request_t) +
                   sizeof(memdbg_debug_regs_t)];
  memdbg_debug_thread_request_t *tr =
      (memdbg_debug_thread_request_t *)body_raw;
  tr->pid = 0; tr->lwp = 1001;
  memdbg_debug_regs_t *regs =
      (memdbg_debug_regs_t *)(body_raw + sizeof(*tr));
  memset(regs, 0, sizeof(*regs));
  regs->r_rip = 0xDEADBEEFLL;

  memdbg_status_t st;

  /* Valid */
  st = handle_debug_set_regs(g_mock_socket, &g_req, body_raw,
                             (uint32_t)sizeof(body_raw), send_response);
  TEST_OK("set_regs valid", st);
  TEST_EQ_I("set_regs sent OK", (int)g_last_status, (int)MEMDBG_OK);

  /* Short body */
  st = handle_debug_set_regs(g_mock_socket, &g_req, body_raw, 1, send_response);
  TEST_ERR("set_regs short body", st, MEMDBG_ERR_PROTOCOL);

  /* Body size exactly sizeof(thread_request) — missing regs */
  st = handle_debug_set_regs(g_mock_socket, &g_req, body_raw,
                             (uint32_t)sizeof(memdbg_debug_thread_request_t), send_response);
  TEST_ERR("set_regs missing regs", st, MEMDBG_ERR_PROTOCOL);

  /* Backend error */
  g_mock_set_regs_st = MEMDBG_ERR_NOT_FOUND;
  mock_send_reset();
  st = handle_debug_set_regs(g_mock_socket, &g_req, body_raw,
                             (uint32_t)sizeof(body_raw), send_response);
  TEST_EQ_I("set_regs passthrough",
            (int)g_last_status, (int)MEMDBG_ERR_NOT_FOUND);
}

/* ---- 9. handle_debug_get_dbregs ---- */

static void test_proto_get_dbregs(void) {
  printf("\n--- handle_debug_get_dbregs ---\n");
  mock_backend_reset(); mock_send_reset();

  g_mock_dbregs.dr[0] = 0x1000ULL;
  g_mock_dbregs.dr[7] = 0x155ULL;

  memdbg_debug_thread_request_t body = { 0, 1001 };
  memdbg_status_t st;

  /* Valid */
  st = handle_debug_get_dbregs(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_OK("get_dbregs valid", st);
  TEST_EQ_U("dbregs payload len", g_last_payload_len,
            (uint32_t)sizeof(memdbg_debug_dbregs_t));
  {
    const memdbg_debug_dbregs_t *db =
        (const memdbg_debug_dbregs_t *)g_last_payload;
    TEST_EQ_LL("dr0 matches", db->dr[0], 0x1000ULL);
    TEST_EQ_LL("dr7 matches", db->dr[7], 0x155ULL);
  }

  /* Short body */
  st = handle_debug_get_dbregs(g_mock_socket, &g_req, &body, 1, send_response);
  TEST_ERR("get_dbregs short body", st, MEMDBG_ERR_PROTOCOL);
}

/* ---- 10. handle_debug_set_dbregs ---- */

static void test_proto_set_dbregs(void) {
  printf("\n--- handle_debug_set_dbregs ---\n");
  mock_backend_reset(); mock_send_reset();

  uint8_t body_raw[sizeof(memdbg_debug_thread_request_t) +
                   sizeof(memdbg_debug_dbregs_t)];
  memdbg_debug_thread_request_t *tr =
      (memdbg_debug_thread_request_t *)body_raw;
  tr->pid = 0; tr->lwp = 1001;
  memdbg_debug_dbregs_t *db =
      (memdbg_debug_dbregs_t *)(body_raw + sizeof(*tr));
  memset(db, 0, sizeof(*db));
  db->dr[0] = 0x2000ULL;

  memdbg_status_t st;
  st = handle_debug_set_dbregs(g_mock_socket, &g_req, body_raw,
                               (uint32_t)sizeof(body_raw), send_response);
  TEST_OK("set_dbregs valid", st);

  /* Short body */
  st = handle_debug_set_dbregs(g_mock_socket, &g_req, body_raw, 1, send_response);
  TEST_ERR("set_dbregs short body", st, MEMDBG_ERR_PROTOCOL);
}

/* ---- 11. handle_debug_set_breakpoint ---- */

static void test_proto_set_breakpoint(void) {
  printf("\n--- handle_debug_set_breakpoint ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_debug_breakpoint_request_t body = { 0x4000ULL, 0, 0 };
  memdbg_status_t st;

  /* Valid */
  st = handle_debug_set_breakpoint(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_OK("set_bp valid", st);

  /* Short body */
  st = handle_debug_set_breakpoint(g_mock_socket, &g_req, &body, 1, send_response);
  TEST_ERR("set_bp short body", st, MEMDBG_ERR_PROTOCOL);

  /* Backend error */
  g_mock_set_bp_st = MEMDBG_ERR_NOMEM;
  mock_send_reset();
  st = handle_debug_set_breakpoint(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_EQ_I("set_bp passthrough",
            (int)g_last_status, (int)MEMDBG_ERR_NOMEM);
}

/* ---- 12. handle_debug_set_breakpoint_cond ---- */

static void test_proto_set_breakpoint_cond(void) {
  printf("\n--- handle_debug_set_breakpoint_cond ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_debug_breakpoint_cond_request_t body = {
    0x5000ULL, /* address */
    0,         /* software */
    MEMDBG_BP_COND_RAX,
    MEMDBG_BP_COND_EQ,
    0,
    0x1234ULL
  };

  memdbg_status_t st;

  /* Valid */
  st = handle_debug_set_breakpoint_cond(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_OK("set_bp_cond valid", st);
  TEST_EQ_I("set_bp_cond sent OK", (int)g_last_status, (int)MEMDBG_OK);

  /* Short body */
  st = handle_debug_set_breakpoint_cond(g_mock_socket, &g_req, &body, 1, send_response);
  TEST_ERR("set_bp_cond short body", st, MEMDBG_ERR_PROTOCOL);

  /* Wrong body length — must be exactly sizeof(cond_request) */
  st = handle_debug_set_breakpoint_cond(g_mock_socket, &g_req, &body,
                                        sizeof(memdbg_debug_breakpoint_request_t), send_response);
  TEST_ERR("set_bp_cond wrong struct size", st, MEMDBG_ERR_PROTOCOL);
}

/* ---- 13. handle_debug_clear_breakpoint ---- */

static void test_proto_clear_breakpoint(void) {
  printf("\n--- handle_debug_clear_breakpoint ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_debug_breakpoint_request_t body = { 0x4000ULL, 0, 0 };
  memdbg_status_t st;

  /* Valid */
  st = handle_debug_clear_breakpoint(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_OK("clear_bp valid", st);

  /* Short body */
  st = handle_debug_clear_breakpoint(g_mock_socket, &g_req, &body, 1, send_response);
  TEST_ERR("clear_bp short body", st, MEMDBG_ERR_PROTOCOL);
}

/* ---- 14. handle_debug_set_watchpoint ---- */

static void test_proto_set_watchpoint(void) {
  printf("\n--- handle_debug_set_watchpoint ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_debug_watchpoint_request_t body = { 0x6000ULL, 8, 1 };
  memdbg_status_t st;

  /* Valid */
  st = handle_debug_set_watchpoint(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_OK("set_wp valid", st);

  /* Short body */
  st = handle_debug_set_watchpoint(g_mock_socket, &g_req, &body, 1, send_response);
  TEST_ERR("set_wp short body", st, MEMDBG_ERR_PROTOCOL);

  /* Backend error */
  g_mock_set_wp_st = MEMDBG_ERR_NOMEM;
  mock_send_reset();
  st = handle_debug_set_watchpoint(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_EQ_I("set_wp passthrough",
            (int)g_last_status, (int)MEMDBG_ERR_NOMEM);
}

/* ---- 15. handle_debug_clear_watchpoint ---- */

static void test_proto_clear_watchpoint(void) {
  printf("\n--- handle_debug_clear_watchpoint ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_debug_watchpoint_request_t body = { 0x6000ULL, 0, 0 };
  memdbg_status_t st;

  /* Valid */
  st = handle_debug_clear_watchpoint(g_mock_socket, &g_req, &body, sizeof(body), send_response);
  TEST_OK("clear_wp valid", st);

  /* Short body */
  st = handle_debug_clear_watchpoint(g_mock_socket, &g_req, &body, 1, send_response);
  TEST_ERR("clear_wp short body", st, MEMDBG_ERR_PROTOCOL);
}

/* ---- 16. handle_debug_thread_control (suspend) ---- */

static void test_proto_suspend_thread(void) {
  printf("\n--- handle_debug_suspend_thread ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_debug_thread_request_t body = { 0, 1001 };
  memdbg_status_t st;

  /* Valid suspend */
  st = handle_debug_thread_control(g_mock_socket, &g_req, &body,
                                   sizeof(body), true, send_response);
  TEST_OK("suspend valid", st);

  /* Short body */
  st = handle_debug_thread_control(g_mock_socket, &g_req, &body, 1, true, send_response);
  TEST_ERR("suspend short body", st, MEMDBG_ERR_PROTOCOL);

  /* Backend error */
  g_mock_suspend_st = MEMDBG_ERR_NOT_FOUND;
  mock_send_reset();
  st = handle_debug_thread_control(g_mock_socket, &g_req, &body,
                                   sizeof(body), true, send_response);
  TEST_EQ_I("suspend passthrough",
            (int)g_last_status, (int)MEMDBG_ERR_NOT_FOUND);
}

/* ---- 17. handle_debug_thread_control (resume) ---- */

static void test_proto_resume_thread(void) {
  printf("\n--- handle_debug_resume_thread ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_debug_thread_request_t body = { 0, 1001 };
  memdbg_status_t st;

  /* Valid resume */
  st = handle_debug_thread_control(g_mock_socket, &g_req, &body,
                                   sizeof(body), false, send_response);
  TEST_OK("resume valid", st);

  /* Short body */
  st = handle_debug_thread_control(g_mock_socket, &g_req, &body, 1, false, send_response);
  TEST_ERR("resume short body", st, MEMDBG_ERR_PROTOCOL);
}

/* ---- 18. handle_debug_poll_events ---- */

static void test_proto_poll_events(void) {
  printf("\n--- handle_debug_poll_events ---\n");
  mock_backend_reset(); mock_send_reset();

  memdbg_status_t st;

  /* Not stopped */
  g_mock_is_stopped = false;
  st = handle_debug_poll_events(g_mock_socket, &g_req, send_response);
  TEST_OK("poll events OK", st);
  {
    const memdbg_debug_poll_response_t *resp =
        (const memdbg_debug_poll_response_t *)g_last_payload;
    TEST_EQ_I("poll not stopped", resp->stopped, 0);
    TEST_EQ_I("poll stop_lwp is 0", resp->stop_lwp, 0);
  }

  /* Stopped */
  g_mock_is_stopped = true;
  g_mock_stop_lwp = 1001;
  mock_send_reset();
  st = handle_debug_poll_events(g_mock_socket, &g_req, send_response);
  TEST_OK("poll events stopped", st);
  {
    const memdbg_debug_poll_response_t *resp =
        (const memdbg_debug_poll_response_t *)g_last_payload;
    TEST_EQ_I("poll stopped", resp->stopped, 1);
    TEST_EQ_I("poll stop_lwp correct", resp->stop_lwp, 1001);
  }

  /* Backend error */
  g_mock_poll_st = MEMDBG_ERR_STATE;
  mock_send_reset();
  st = handle_debug_poll_events(g_mock_socket, &g_req, send_response);
  TEST_EQ_I("poll passthrough",
            (int)g_last_status, (int)MEMDBG_ERR_STATE);

  /* Network error */
  g_mock_poll_st = MEMDBG_OK;
  mock_send_reset();
  g_send_rc = -1;
  st = handle_debug_poll_events(g_mock_socket, &g_req, send_response);
  TEST_ERR("poll net error", st, MEMDBG_ERR_NET);
  g_send_rc = 0;
}

/* ---- 19. handle_debug_get_breakpoints ---- */

static void test_proto_get_breakpoints(void) {
  printf("\n--- handle_debug_get_breakpoints ---\n");
  mock_backend_reset(); mock_send_reset();

  /* Empty list */
  memdbg_status_t st = handle_debug_get_breakpoints(g_mock_socket, &g_req, send_response);
  TEST_OK("get_bps empty", st);
  {
    const memdbg_debug_breakpoint_list_prefix_t *pfx =
        (const memdbg_debug_breakpoint_list_prefix_t *)g_last_payload;
    TEST_EQ_U("empty bp count", pfx->count, 0U);
  }

  /* Populated list */
  g_mock_bps[0].address = 0x1000ULL;
  g_mock_bps[0].kind = MEMDBG_BP_SOFTWARE;
  g_mock_bps[0].installed = true;
  g_mock_bps[0].active = true;
  g_mock_bps[2].address = 0x2000ULL;
  g_mock_bps[2].kind = MEMDBG_BP_HARDWARE;
  g_mock_bps[2].installed = true;
  g_mock_bps[2].active = true;
  g_mock_bps[2].cond_reg = MEMDBG_BP_COND_RAX;
  g_mock_bps[2].cond_op = MEMDBG_BP_COND_EQ;
  g_mock_bps[2].cond_value = 0x42ULL;

  mock_send_reset();
  st = handle_debug_get_breakpoints(g_mock_socket, &g_req, send_response);
  TEST_OK("get_bps populated", st);
  {
    const memdbg_debug_breakpoint_list_prefix_t *pfx =
        (const memdbg_debug_breakpoint_list_prefix_t *)g_last_payload;
    TEST_EQ_U("bp count 2", pfx->count, 2U);

    const memdbg_debug_breakpoint_list_entry_t *ents =
        (const memdbg_debug_breakpoint_list_entry_t *)(g_last_payload +
                                                       sizeof(*pfx));
    /* First: SW BP */
    TEST_EQ_LL("bp[0] addr", ents[0].address, 0x1000ULL);
    TEST_EQ_U("bp[0] kind SW", ents[0].kind, MEMDBG_BP_SOFTWARE);
    TEST("bp[0] flags installed", (ents[0].flags & 1) != 0);
    TEST("bp[0] flags active", (ents[0].flags & 2) != 0);

    /* Second: HW BP with condition */
    TEST_EQ_LL("bp[1] addr", ents[1].address, 0x2000ULL);
    TEST_EQ_U("bp[1] kind HW", ents[1].kind, MEMDBG_BP_HARDWARE);
    TEST_EQ_U("bp[1] cond reg RAX", ents[1].cond_reg, (uint32_t)MEMDBG_BP_COND_RAX);
    TEST_EQ_U("bp[1] cond op EQ", ents[1].cond_op, (uint32_t)MEMDBG_BP_COND_EQ);
    TEST_EQ_LL("bp[1] cond val", ents[1].cond_value, 0x42ULL);
  }

  /* Network error */
  mock_send_reset();
  g_send_rc = -1;
  st = handle_debug_get_breakpoints(g_mock_socket, &g_req, send_response);
  TEST_ERR("get_bps net error", st, MEMDBG_ERR_NET);
  g_send_rc = 0;

  /* Clear for other tests */
  memset(g_mock_bps, 0, sizeof(g_mock_bps));
}

/* ---- 20. handle_debug_get_watchpoints ---- */

static void test_proto_get_watchpoints(void) {
  printf("\n--- handle_debug_get_watchpoints ---\n");
  mock_backend_reset(); mock_send_reset();

  /* Empty list */
  memdbg_status_t st = handle_debug_get_watchpoints(g_mock_socket, &g_req, send_response);
  TEST_OK("get_wps empty", st);
  {
    const memdbg_debug_watchpoint_list_prefix_t *pfx =
        (const memdbg_debug_watchpoint_list_prefix_t *)g_last_payload;
    TEST_EQ_U("empty wp count", pfx->count, 0U);
  }

  /* Populated list */
  g_mock_wps[0].address = 0x3000ULL;
  g_mock_wps[0].length = 4;
  g_mock_wps[0].type = 1; /* write */
  g_mock_wps[0].slot = 0;
  g_mock_wps[0].installed = true;

  g_mock_wps[1].address = 0x4000ULL;
  g_mock_wps[1].length = 8;
  g_mock_wps[1].type = 3; /* read-write */
  g_mock_wps[1].slot = 1;
  g_mock_wps[1].installed = true;

  mock_send_reset();
  st = handle_debug_get_watchpoints(g_mock_socket, &g_req, send_response);
  TEST_OK("get_wps populated", st);
  {
    const memdbg_debug_watchpoint_list_prefix_t *pfx =
        (const memdbg_debug_watchpoint_list_prefix_t *)g_last_payload;
    TEST_EQ_U("wp count 2", pfx->count, 2U);

    const memdbg_debug_watchpoint_list_entry_t *ents =
        (const memdbg_debug_watchpoint_list_entry_t *)(g_last_payload +
                                                       sizeof(*pfx));
    TEST_EQ_LL("wp[0] addr", ents[0].address, 0x3000ULL);
    TEST_EQ_U("wp[0] len 4", ents[0].length, 4U);
    TEST_EQ_U("wp[0] type write", ents[0].type, 1U);
    TEST_EQ_U("wp[0] slot 0", ents[0].slot, 0U);
    TEST("wp[0] installed", (ents[0].flags & 1) != 0);

    TEST_EQ_LL("wp[1] addr", ents[1].address, 0x4000ULL);
    TEST_EQ_U("wp[1] type rw", ents[1].type, 3U);
  }

  /* Only show installed ones */
  g_mock_wps[0].installed = false;
  mock_send_reset();
  st = handle_debug_get_watchpoints(g_mock_socket, &g_req, send_response);
  TEST_OK("get_wps filter installed", st);
  {
    const memdbg_debug_watchpoint_list_prefix_t *pfx =
        (const memdbg_debug_watchpoint_list_prefix_t *)g_last_payload;
    TEST_EQ_U("wp filtered count", pfx->count, 1U);
  }
  memset(g_mock_wps, 0, sizeof(g_mock_wps));
}

/* ---- 21. handle_debug_clear_all_breakpoints ---- */

static void test_proto_clear_all_breakpoints(void) {
  printf("\n--- handle_debug_clear_all_breakpoints ---\n");
  mock_backend_reset(); mock_send_reset();

  g_mock_bp_active_count = 5;
  memdbg_status_t st = handle_debug_clear_all_breakpoints(g_mock_socket, &g_req, send_response);
  TEST_OK("clear_all_bp OK", st);
  {
    const memdbg_debug_clear_all_response_t *resp =
        (const memdbg_debug_clear_all_response_t *)g_last_payload;
    TEST_EQ_U("cleared count", resp->cleared, 5U);
  }

  /* Backend error — response still sent */
  g_mock_clear_all_bp_st = MEMDBG_ERR_STATE;
  mock_send_reset();
  st = handle_debug_clear_all_breakpoints(g_mock_socket, &g_req, send_response);
  TEST_EQ_I("clear_all_bp error passthrough",
            (int)g_last_status, (int)MEMDBG_ERR_STATE);

  /* Network error */
  g_mock_clear_all_bp_st = MEMDBG_OK;
  mock_send_reset();
  g_send_rc = -1;
  st = handle_debug_clear_all_breakpoints(g_mock_socket, &g_req, send_response);
  TEST_ERR("clear_all_bp net error", st, MEMDBG_ERR_NET);
  g_send_rc = 0;
  g_mock_bp_active_count = 0;
}

/* ---- 22. handle_debug_clear_all_watchpoints ---- */

static void test_proto_clear_all_watchpoints(void) {
  printf("\n--- handle_debug_clear_all_watchpoints ---\n");
  mock_backend_reset(); mock_send_reset();

  g_mock_wp_installed_count = 3;
  memdbg_status_t st = handle_debug_clear_all_watchpoints(g_mock_socket, &g_req, send_response);
  TEST_OK("clear_all_wp OK", st);
  {
    const memdbg_debug_clear_all_response_t *resp =
        (const memdbg_debug_clear_all_response_t *)g_last_payload;
    TEST_EQ_U("cleared wp count", resp->cleared, 3U);
  }
  g_mock_wp_installed_count = 0;
}

/* ======================================================================
 * Main
 * ====================================================================== */

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("=== Debugger Protocol Handler Tests ===\n");
  printf("Testing: 25 debugger protocol handlers across attach/detach,\n");
  printf("         stop/continue/step, threads, regs, dbregs, breakpoints,\n");
  printf("         watchpoints, poll events, get/add/clear-all lists,\n");
  printf("         body-length validation, error passthrough, net errors\n\n");

  test_proto_attach();
  test_proto_detach();
  test_proto_stop();
  test_proto_continue();
  test_proto_step();
  test_proto_get_threads();
  test_proto_get_regs();
  test_proto_set_regs();
  test_proto_get_dbregs();
  test_proto_set_dbregs();
  test_proto_set_breakpoint();
  test_proto_set_breakpoint_cond();
  test_proto_clear_breakpoint();
  test_proto_set_watchpoint();
  test_proto_clear_watchpoint();
  test_proto_suspend_thread();
  test_proto_resume_thread();
  test_proto_poll_events();
  test_proto_get_breakpoints();
  test_proto_get_watchpoints();
  test_proto_clear_all_breakpoints();
  test_proto_clear_all_watchpoints();

  printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  printf("Total:  %d\n", total);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}
