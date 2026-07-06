/*
 * memDBG - E2E test: debugger subsystem against a live target.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Uses shared E2E helpers from e2e_utils.h.
 */

#include "memdbg/core/memdbg_protocol.h"
#include "e2e_utils.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void sleep_ms(unsigned int ms) {
  struct timespec ts;
  ts.tv_sec  = (time_t)(ms / 1000U);
  ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

/* ---- Main ---- */

int main(int argc, char **argv) {
  const char *host = "127.0.0.1";
  uint16_t port    = 19121;
  if (argc >= 2) host = argv[1];
  if (argc >= 3) port = (uint16_t)atoi(argv[2]);

  int failures = 0;

  printf("--- E2E Debugger test ---\n");

  /* 1. Connect */
  printf("Connecting to %s:%u...\n", host, port);
  e2e_test_socket = e2e_connect(host, port, 5);
  if (e2e_test_socket < 0) { printf("FAIL: connect\n"); return 1; }
  printf("  connected\n");

  /* 2. HELLO */
  uint8_t response[65536];
  uint32_t response_len = sizeof(response);

  if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_HELLO, NULL, 0,
                       response, &response_len) != 0) {
    printf("FAIL: hello\n"); close(e2e_test_socket); return 1;
  }
  memdbg_hello_response_t hello;
  memcpy(&hello, response, sizeof(hello));
  printf("  HELLO: protocol=%u platform=%u caps=0x%08x\n",
         hello.protocol_version, hello.platform_id, hello.capabilities);

  if (!(hello.capabilities & MEMDBG_CAP_DEBUGGER)) {
    printf("SKIP: payload does not advertise DEBUGGER capability\n");
    printf("  This is expected on platforms without ptrace (macOS, etc.)\n");
    close(e2e_test_socket);
    return 0;
  }

  printf("  DEBUGGER capability detected — proceeding with live test.\n");

  /* 3. Spawn a child process to debug */
  pid_t child_pid = fork();
  if (child_pid < 0) {
    perror("fork");
    printf("FAIL: fork child\n");
    close(e2e_test_socket); return 1;
  }

  if (child_pid == 0) {
    execlp("sleep", "sleep", "60", (char *)NULL);
    _exit(127);
  }

  printf("  Child PID: %d\n", (int)child_pid);
  sleep_ms(100U);

  /* 4. DEBUG_ATTACH */
  {
    memdbg_debug_attach_request_t ar = { (int32_t)child_pid, 0 };
    response_len = sizeof(response);
    e2e_quiet_errors = 1;
    int rc = e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_ATTACH,
                              &ar, sizeof(ar), response, &response_len);
    e2e_quiet_errors = 0;

    if (rc != 0) {
      printf("SKIP: DEBUG_ATTACH failed — likely ptrace permissions (yama, etc.)\n");
      printf("  Try: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n");
      kill(child_pid, SIGKILL);
      waitpid(child_pid, NULL, 0);
      close(e2e_test_socket);
      return 0;
    }
    printf("  DEBUG_ATTACH: OK\n");
  }

  /* 5. DEBUG_STOP */
  if (e2e_send_cmd(e2e_test_socket, MEMDBG_CMD_DEBUG_STOP) != 0)
    { printf("FAIL: DEBUG_STOP\n"); failures++; }
  else printf("  DEBUG_STOP: OK\n");

  /* 6. DEBUG_GET_THREADS */
  {
    response_len = sizeof(response);
    if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_GET_THREADS,
                         NULL, 0, response, &response_len) != 0) {
      printf("FAIL: DEBUG_GET_THREADS\n"); failures++;
    } else {
      if (response_len < sizeof(memdbg_debug_threads_response_prefix_t)) {
        printf("FAIL: short thread list response\n"); failures++;
      } else {
        const memdbg_debug_threads_response_prefix_t *prefix =
            (const memdbg_debug_threads_response_prefix_t *)response;
        printf("  DEBUG_GET_THREADS: count=%u\n", prefix->count);
        if (prefix->count == 0) {
          printf("FAIL: expected at least 1 thread\n"); failures++;
        } else {
          const memdbg_debug_thread_entry_t *entries =
              (const memdbg_debug_thread_entry_t *)(response + sizeof(*prefix));
          for (uint32_t i = 0; i < prefix->count && i < 4; ++i)
            printf("    LWP %d: \"%.24s\"\n", (int)entries[i].lwp, entries[i].name);
        }
      }
    }
  }

  /* 7. DEBUG_GET_REGS */
  {
    if (response_len < sizeof(memdbg_debug_threads_response_prefix_t)) {
      printf("FAIL: need thread list for regs\n"); failures++;
    } else {
      const memdbg_debug_threads_response_prefix_t *prefix =
          (const memdbg_debug_threads_response_prefix_t *)response;
      if (prefix->count > 0) {
        const memdbg_debug_thread_entry_t *entries =
            (const memdbg_debug_thread_entry_t *)(response + sizeof(*prefix));
        int32_t lwp = entries[0].lwp;
        memdbg_debug_thread_request_t tr = { 0, lwp };
        response_len = sizeof(response);
        if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_GET_REGS,
                             &tr, sizeof(tr), response, &response_len) != 0) {
          printf("FAIL: DEBUG_GET_REGS\n"); failures++;
        } else {
          if (response_len < sizeof(memdbg_debug_regs_t)) {
            printf("FAIL: short regs response\n"); failures++;
          } else {
            const memdbg_debug_regs_t *regs =
                (const memdbg_debug_regs_t *)response;
            printf("  DEBUG_GET_REGS: RIP=0x%016" PRIx64
                   " RSP=0x%016" PRIx64 " RAX=0x%016" PRIx64 "\n",
                   regs->r_rip, regs->r_rsp, regs->r_rax);
            if (regs->r_rip == 0)
              printf("WARN: RIP is zero (unusual for a live process)\n");
          }
        }
      }
    }
  }

  /* 8. DEBUG_GET_DBREGS */
  {
    uint8_t tl_resp[65536];
    uint32_t tl_len = sizeof(tl_resp);
    if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_GET_THREADS,
                         NULL, 0, tl_resp, &tl_len) == 0 &&
        tl_len >= sizeof(memdbg_debug_threads_response_prefix_t)) {
      const memdbg_debug_threads_response_prefix_t *tl_pfx =
          (const memdbg_debug_threads_response_prefix_t *)tl_resp;
      if (tl_pfx->count > 0) {
        const memdbg_debug_thread_entry_t *tl_entries =
            (const memdbg_debug_thread_entry_t *)(tl_resp + sizeof(*tl_pfx));
        int32_t lwp = tl_entries[0].lwp;
        memdbg_debug_thread_request_t tr = { 0, lwp };
        response_len = sizeof(response);
        if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_GET_DBREGS,
                             &tr, sizeof(tr), response, &response_len) != 0)
          printf("WARN: DEBUG_GET_DBREGS failed (may not be supported)\n");
        else {
          const memdbg_debug_dbregs_t *dbregs =
              (const memdbg_debug_dbregs_t *)response;
          printf("  DEBUG_GET_DBREGS: dr7=0x%016" PRIx64 "\n", dbregs->dr[7]);
        }
      }
    }
  }

  /* 9. DEBUG_CONTINUE → stop again */
  if (e2e_send_cmd(e2e_test_socket, MEMDBG_CMD_DEBUG_CONTINUE) != 0)
    { printf("FAIL: DEBUG_CONTINUE\n"); failures++; }
  else printf("  DEBUG_CONTINUE: OK\n");
  sleep_ms(50U);
  if (e2e_send_cmd(e2e_test_socket, MEMDBG_CMD_DEBUG_STOP) != 0)
    { printf("FAIL: DEBUG_STOP after continue\n"); failures++; }
  else printf("  DEBUG_STOP: OK\n");

  /* 10. DEBUG_SET_BREAKPOINT + CLEAR */
  {
    int32_t lwp = 0;
    response_len = sizeof(response);
    if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_GET_THREADS,
                         NULL, 0, response, &response_len) == 0 &&
        response_len >= sizeof(memdbg_debug_threads_response_prefix_t)) {
      const memdbg_debug_threads_response_prefix_t *pfx =
          (const memdbg_debug_threads_response_prefix_t *)response;
      if (pfx->count > 0) {
        lwp = ((const memdbg_debug_thread_entry_t *)(response + sizeof(*pfx)))->lwp;
        memdbg_debug_thread_request_t tr = { 0, lwp };
        uint8_t regs_resp[65536];
        uint32_t regs_len = sizeof(regs_resp);
        if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_GET_REGS,
                             &tr, sizeof(tr), regs_resp, &regs_len) == 0 &&
            regs_len >= sizeof(memdbg_debug_regs_t)) {
          const memdbg_debug_regs_t *regs = (const memdbg_debug_regs_t *)regs_resp;
          uint64_t bp_addr = (uint64_t)regs->r_rip;

          memdbg_debug_breakpoint_request_t bp_req = { bp_addr, 0, 0 };
          e2e_quiet_errors = 1;
          int rc = e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_SET_BREAKPOINT,
                                    &bp_req, sizeof(bp_req), response, &response_len);
          e2e_quiet_errors = 0;

          if (rc != 0) {
            printf("WARN: DEBUG_SET_BREAKPOINT at RIP=0x%" PRIx64
                   " failed (may be read-only map)\n", bp_addr);
          } else {
            printf("  DEBUG_SET_BREAKPOINT at RIP=0x%" PRIx64 ": OK\n", bp_addr);
            /* Verify in breakpoint list, then clear */
            uint8_t bp_list[65536];
            uint32_t bp_len = sizeof(bp_list);
            if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_GET_BREAKPOINTS,
                                 NULL, 0, bp_list, &bp_len) == 0 &&
                bp_len >= sizeof(memdbg_debug_breakpoint_list_prefix_t)) {
              const memdbg_debug_breakpoint_list_prefix_t *bp_pfx =
                  (const memdbg_debug_breakpoint_list_prefix_t *)bp_list;
              printf("  DEBUG_GET_BREAKPOINTS: count=%u\n", bp_pfx->count);
            }
            memdbg_debug_breakpoint_request_t clr_req = { bp_addr, 0, 0 };
            if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_CLEAR_BREAKPOINT,
                                 &clr_req, sizeof(clr_req), response, &response_len) != 0)
              { printf("FAIL: DEBUG_CLEAR_BREAKPOINT\n"); failures++; }
            else printf("  DEBUG_CLEAR_BREAKPOINT: OK\n");
          }
        }
      }
    }
  }

  /* 11. DEBUG_SET_WATCHPOINT + CLEAR */
  {
    uint8_t tl_resp[65536];
    uint32_t tl_len = sizeof(tl_resp);
    if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_GET_THREADS,
                         NULL, 0, tl_resp, &tl_len) == 0 &&
        tl_len >= sizeof(memdbg_debug_threads_response_prefix_t)) {
      const memdbg_debug_threads_response_prefix_t *tl_pfx =
          (const memdbg_debug_threads_response_prefix_t *)tl_resp;
      if (tl_pfx->count > 0) {
        int32_t lwp = ((const memdbg_debug_thread_entry_t *)(tl_resp + sizeof(*tl_pfx)))->lwp;
        memdbg_debug_thread_request_t tr = { 0, lwp };
        uint8_t regs_resp[65536];
        uint32_t regs_len = sizeof(regs_resp);
        if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_GET_REGS,
                             &tr, sizeof(tr), regs_resp, &regs_len) == 0 &&
            regs_len >= sizeof(memdbg_debug_regs_t)) {
          const memdbg_debug_regs_t *regs = (const memdbg_debug_regs_t *)regs_resp;
          uint64_t wp_addr = (uint64_t)regs->r_rsp;

          memdbg_debug_watchpoint_request_t wp = { wp_addr, 8, 1 };
          e2e_quiet_errors = 1;
          int rc = e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_SET_WATCHPOINT,
                                    &wp, sizeof(wp), response, &response_len);
          e2e_quiet_errors = 0;

          if (rc != 0) {
            printf("WARN: DEBUG_SET_WATCHPOINT at RSP=0x%" PRIx64 " failed\n", wp_addr);
          } else {
            printf("  DEBUG_SET_WATCHPOINT at RSP=0x%" PRIx64 ": OK\n", wp_addr);
            uint8_t wp_list[65536];
            uint32_t wp_len = sizeof(wp_list);
            if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_GET_WATCHPOINTS,
                                 NULL, 0, wp_list, &wp_len) == 0 &&
                wp_len >= sizeof(memdbg_debug_watchpoint_list_prefix_t)) {
              const memdbg_debug_watchpoint_list_prefix_t *wp_pfx =
                  (const memdbg_debug_watchpoint_list_prefix_t *)wp_list;
              printf("  DEBUG_GET_WATCHPOINTS: count=%u\n", wp_pfx->count);
            }
            memdbg_debug_watchpoint_request_t wp_clr = { wp_addr, 0, 0 };
            if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_DEBUG_CLEAR_WATCHPOINT,
                                 &wp_clr, sizeof(wp_clr), response, &response_len) != 0)
              { printf("FAIL: DEBUG_CLEAR_WATCHPOINT\n"); failures++; }
            else printf("  DEBUG_CLEAR_WATCHPOINT: OK\n");
          }
        }
      }
    }
  }

  /* 12. Batch clear-all */
  e2e_quiet_errors = 1;
  if (e2e_send_cmd(e2e_test_socket, MEMDBG_CMD_DEBUG_CLEAR_ALL_BREAKPOINTS) == 0)
    printf("  DEBUG_CLEAR_ALL_BREAKPOINTS: OK\n");
  else printf("WARN: CLEAR_ALL_BREAKPOINTS failed (may be expected)\n");
  if (e2e_send_cmd(e2e_test_socket, MEMDBG_CMD_DEBUG_CLEAR_ALL_WATCHPOINTS) == 0)
    printf("  DEBUG_CLEAR_ALL_WATCHPOINTS: OK\n");
  else printf("WARN: CLEAR_ALL_WATCHPOINTS failed (may be expected)\n");
  e2e_quiet_errors = 0;

  /* 13. DEBUG_DETACH */
  if (e2e_send_cmd(e2e_test_socket, MEMDBG_CMD_DEBUG_DETACH) != 0)
    { printf("FAIL: DEBUG_DETACH\n"); failures++; }
  else printf("  DEBUG_DETACH: OK\n");

  /* 14. Clean up child */
  if (child_pid > 0) {
    kill(child_pid, SIGTERM);
    sleep_ms(100U);
    kill(child_pid, SIGKILL);
    waitpid(child_pid, NULL, 0);
    printf("  Child cleaned up\n");
  }

  /* 15. PING */
  if (e2e_send_cmd(e2e_test_socket, MEMDBG_CMD_PING) != 0)
    { printf("FAIL: PING after debugger ops\n"); failures++; }
  else printf("  PING: OK\n");

  close(e2e_test_socket);

  if (failures == 0)
    printf("\nE2E Debugger test PASSED.\n");
  else
    printf("\nE2E Debugger test: %d failure(s).\n", failures);

  return failures > 0 ? 1 : 0;
}
