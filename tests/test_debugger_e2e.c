/*
 * memDBG - E2E test: debugger subsystem against a live target.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Spawns a simple child process (sleep), starts the host payload, connects,
 * sends HELLO + debugger commands, and verifies responses against the
 * real OS process via ptrace.
 *
 * Gracefully skips when:
 *   - Platform lacks ptrace (macOS, etc.) → payload won't advertise DEBUGGER
 *   - Permissions prevent ptrace attach (yama, etc.)
 *   - Payload build doesn't include debugger support
 */

#include "memdbg/core/memdbg_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int test_socket = -1;
static uint32_t next_id = 1;
static int quiet_payload_errors = 0;

static void sleep_ms(unsigned int ms) {
  struct timespec ts;
  ts.tv_sec = (time_t)(ms / 1000U);
  ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
  }
}

/* ---- Socket helpers (same pattern as test_process_aob_e2e.c) ---- */

static int connect_to(const char *host, uint16_t port, int timeout_sec) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { perror("socket"); return -1; }

  struct timeval tv = { timeout_sec, 0 };
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(port);
  if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
    fprintf(stderr, "inet_pton failed\n"); close(fd); return -1;
  }

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("connect"); close(fd); return -1;
  }
  return fd;
}

static int read_all(int fd, void *buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t n = recv(fd, (uint8_t *)buf + total, len - total, 0);
    if (n <= 0) {
      if (n == 0) fprintf(stderr, "  connection closed by peer\n");
      else perror("  recv");
      return -1;
    }
    total += (size_t)n;
  }
  return 0;
}

static int send_request(int fd, uint16_t cmd, const void *body, uint32_t body_len,
                        uint8_t *response, uint32_t *response_len) {
  memdbg_packet_header_t hdr = {0};
  hdr.magic      = MEMDBG_PACKET_MAGIC;
  hdr.version    = MEMDBG_PROTOCOL_VERSION;
  hdr.command    = cmd;
  hdr.request_id = next_id++;
  hdr.length     = body_len;

  if (send(fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr)) {
    perror("  send header"); return -1;
  }
  if (body_len > 0 && send(fd, body, body_len, 0) != (ssize_t)body_len) {
    perror("  send body"); return -1;
  }

  memdbg_response_header_t rhdr;
  if (read_all(fd, &rhdr, sizeof(rhdr)) != 0) return -1;
  if (rhdr.magic != MEMDBG_PACKET_MAGIC ||
      rhdr.version != MEMDBG_PROTOCOL_VERSION ||
      rhdr.command != cmd ||
      rhdr.request_id != hdr.request_id) {
    fprintf(stderr, "  response header mismatch\n");
    return -1;
  }
  if (rhdr.status != 0) {
    if (!quiet_payload_errors)
      fprintf(stderr, "  payload error status: %d\n", (int)rhdr.status);
    return -1;
  }
  if (rhdr.length > *response_len) {
    fprintf(stderr, "  response too large: %u > %u\n",
            rhdr.length, *response_len);
    return -1;
  }
  if (rhdr.length > 0 && read_all(fd, response, rhdr.length) != 0) return -1;
  *response_len = rhdr.length;
  return 0;
}

/* ---- Simple request with no body, no response interest ---- */

static int send_cmd(int fd, uint16_t cmd) {
  uint8_t resp[256];
  uint32_t resp_len = sizeof(resp);
  return send_request(fd, cmd, NULL, 0, resp, &resp_len);
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
  test_socket = connect_to(host, port, 5);
  if (test_socket < 0) { printf("FAIL: connect\n"); return 1; }
  printf("  connected\n");

  /* 2. HELLO */
  uint8_t response[65536];
  uint32_t response_len = sizeof(response);

  if (send_request(test_socket, MEMDBG_CMD_HELLO, NULL, 0,
                   response, &response_len) != 0) {
    printf("FAIL: hello\n"); close(test_socket); return 1;
  }
  memdbg_hello_response_t hello;
  memcpy(&hello, response, sizeof(hello));
  printf("  HELLO: protocol=%u platform=%u caps=0x%08x\n",
         hello.protocol_version, hello.platform_id, hello.capabilities);

  if (!(hello.capabilities & MEMDBG_CAP_DEBUGGER)) {
    printf("SKIP: payload does not advertise DEBUGGER capability\n");
    printf("  This is expected on platforms without ptrace (macOS, etc.)\n");
    close(test_socket);
    return 0;
  }

  printf("  DEBUGGER capability detected — proceeding with live test.\n");

  /* 3. Spawn a child process to debug.
   * Use a simple sleep process — it does minimal syscalls and has a
   * predictable RIP in the sleep/nanosleep syscall, ideal for testing. */
  pid_t child_pid = fork();
  if (child_pid < 0) {
    perror("fork");
    printf("FAIL: fork child\n");
    close(test_socket); return 1;
  }

  if (child_pid == 0) {
    /* Child: sleep a long time, then exit. */
    execlp("sleep", "sleep", "60", (char *)NULL);
    _exit(127);
  }

  printf("  Child PID: %d\n", (int)child_pid);
  /* Give the child a moment to exec. */
  sleep_ms(100U);

  /* 4. DEBUG_ATTACH */
  {
    memdbg_debug_attach_request_t ar = { (int32_t)child_pid, 0 };
    response_len = sizeof(response);
    quiet_payload_errors = 1;
    int rc = send_request(test_socket, MEMDBG_CMD_DEBUG_ATTACH,
                          &ar, sizeof(ar), response, &response_len);
    quiet_payload_errors = 0;

    if (rc != 0) {
      printf("SKIP: DEBUG_ATTACH failed — likely ptrace permissions (yama, etc.)\n");
      printf("  Try: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n");
      kill(child_pid, SIGKILL);
      waitpid(child_pid, NULL, 0);
      close(test_socket);
      return 0;
    }
    printf("  DEBUG_ATTACH: OK\n");
  }

  /* After attach the process should be stopped (initial SIGTRAP). */

  /* 5. DEBUG_STOP — re-stop (should be idempotent when already stopped) */
  {
    int rc = send_cmd(test_socket, MEMDBG_CMD_DEBUG_STOP);
    if (rc != 0) { printf("FAIL: DEBUG_STOP\n"); failures++; }
    else printf("  DEBUG_STOP: OK\n");
  }

  /* 6. DEBUG_GET_THREADS — verify we get at least the main thread */
  {
    response_len = sizeof(response);
    if (send_request(test_socket, MEMDBG_CMD_DEBUG_GET_THREADS,
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
          for (uint32_t i = 0; i < prefix->count && i < 4; ++i) {
            printf("    LWP %d: \"%.24s\"\n",
                   (int)entries[i].lwp, entries[i].name);
          }
        }
      }
    }
  }

  /* 7. DEBUG_GET_REGS — read registers of the first thread.
   * Use the thread list stored in 'response' from step 6 (still intact). */
  {
    /* response from step 6 still holds the thread list */
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
        if (send_request(test_socket, MEMDBG_CMD_DEBUG_GET_REGS,
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
            /* RIP should be non-zero for a live process */
            if (regs->r_rip == 0) {
              printf("WARN: RIP is zero (unusual for a live process)\n");
            }
          }
        }
      }
    }
  }

  /* 8. DEBUG_GET_DBREGS — read debug registers */
  {
    /* Get a fresh thread list (step 7 overwrote 'response' with regs). */
    uint8_t tl_resp[65536];
    uint32_t tl_len = sizeof(tl_resp);
    if (send_request(test_socket, MEMDBG_CMD_DEBUG_GET_THREADS,
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
        if (send_request(test_socket, MEMDBG_CMD_DEBUG_GET_DBREGS,
                         &tr, sizeof(tr), response, &response_len) != 0) {
          printf("WARN: DEBUG_GET_DBREGS failed (may not be supported)\n");
        } else {
          const memdbg_debug_dbregs_t *dbregs =
              (const memdbg_debug_dbregs_t *)response;
          printf("  DEBUG_GET_DBREGS: dr7=0x%016" PRIx64 "\n", dbregs->dr[7]);
        }
      }
    }
  }

  /* 9. DEBUG_CONTINUE — resume, then stop again */
  {
    int rc = send_cmd(test_socket, MEMDBG_CMD_DEBUG_CONTINUE);
    if (rc != 0) { printf("FAIL: DEBUG_CONTINUE\n"); failures++; }
    else printf("  DEBUG_CONTINUE: OK\n");

    /* Small delay to let the process run a bit */
    sleep_ms(50U);

    rc = send_cmd(test_socket, MEMDBG_CMD_DEBUG_STOP);
    if (rc != 0) { printf("FAIL: DEBUG_STOP after continue\n"); failures++; }
    else printf("  DEBUG_STOP: OK\n");
  }

  /* 10. DEBUG_SET_BREAKPOINT + DEBUG_CLEAR_BREAKPOINT
   * Read RIP first, set a software breakpoint there, clear it. */
  {
    int32_t lwp = 0;
    /* Get thread list to find first LWP */
    response_len = sizeof(response);
    if (send_request(test_socket, MEMDBG_CMD_DEBUG_GET_THREADS,
                     NULL, 0, response, &response_len) == 0 &&
        response_len >= sizeof(memdbg_debug_threads_response_prefix_t)) {
      const memdbg_debug_threads_response_prefix_t *pfx =
          (const memdbg_debug_threads_response_prefix_t *)response;
      if (pfx->count > 0) {
        lwp = ((const memdbg_debug_thread_entry_t *)
                  (response + sizeof(*pfx)))->lwp;

        /* Get RIP */
        memdbg_debug_thread_request_t tr = { 0, lwp };
        uint8_t regs_resp[65536];
        uint32_t regs_len = sizeof(regs_resp);
        if (send_request(test_socket, MEMDBG_CMD_DEBUG_GET_REGS,
                         &tr, sizeof(tr), regs_resp, &regs_len) == 0 &&
            regs_len >= sizeof(memdbg_debug_regs_t)) {
          const memdbg_debug_regs_t *regs =
              (const memdbg_debug_regs_t *)regs_resp;
          uint64_t bp_addr = (uint64_t)regs->r_rip;

          /* Set software breakpoint at current RIP */
          memdbg_debug_breakpoint_request_t bp_req = { bp_addr,
                                                       0, /* software */
                                                       0 };

          /* Set breakpoint — may fail if the map isn't writable */
          quiet_payload_errors = 1;
          int rc = send_request(test_socket, MEMDBG_CMD_DEBUG_SET_BREAKPOINT,
                                &bp_req, sizeof(bp_req), response, &response_len);
          quiet_payload_errors = 0;

          if (rc != 0) {
            printf("WARN: DEBUG_SET_BREAKPOINT at RIP=0x%" PRIx64
                   " failed (may be read-only map)\n",
                   bp_addr);
          } else {
            printf("  DEBUG_SET_BREAKPOINT at RIP=0x%" PRIx64 ": OK\n", bp_addr);

            /* Verify breakpoint appears in the list */
            {
              uint8_t bp_list[65536];
              uint32_t bp_len = sizeof(bp_list);
              if (send_request(test_socket, MEMDBG_CMD_DEBUG_GET_BREAKPOINTS,
                               NULL, 0, bp_list, &bp_len) == 0 &&
                  bp_len >= sizeof(memdbg_debug_breakpoint_list_prefix_t)) {
                const memdbg_debug_breakpoint_list_prefix_t *bp_pfx =
                    (const memdbg_debug_breakpoint_list_prefix_t *)bp_list;
                printf("  DEBUG_GET_BREAKPOINTS: count=%u\n", bp_pfx->count);

                int found = 0;
                const memdbg_debug_breakpoint_list_entry_t *bp_entries =
                    (const memdbg_debug_breakpoint_list_entry_t *)
                        (bp_list + sizeof(*bp_pfx));
                for (uint32_t i = 0; i < bp_pfx->count; ++i) {
                  if (bp_entries[i].address == bp_addr &&
                      (bp_entries[i].flags & 1)) { /* installed */
                    found = 1;
                    break;
                  }
                }
                if (!found) printf("WARN: BP not found in breakpoint list\n");
              }

              /* Clear it */
              memdbg_debug_breakpoint_request_t clr_req = { bp_addr, 0, 0 };
              if (send_request(test_socket, MEMDBG_CMD_DEBUG_CLEAR_BREAKPOINT,
                               &clr_req, sizeof(clr_req),
                               response, &response_len) != 0) {
                printf("FAIL: DEBUG_CLEAR_BREAKPOINT\n"); failures++;
              } else {
                printf("  DEBUG_CLEAR_BREAKPOINT: OK\n");
              }

              /* Step over the breakpoint before continuing */
              /* Actually, we haven't continued after setting the BP,
               * so we're still at the BP address. Just continue. */
            }
          }
        }
      }
    }
  }

  /* 11. DEBUG_SET_WATCHPOINT + DEBUG_CLEAR_WATCHPOINT
   * Set a write watchpoint at a plausible data address (RSP-ish). */
  {
    /* Get thread list again */
    uint8_t tl_resp[65536];
    uint32_t tl_len = sizeof(tl_resp);
    if (send_request(test_socket, MEMDBG_CMD_DEBUG_GET_THREADS,
                     NULL, 0, tl_resp, &tl_len) == 0 &&
        tl_len >= sizeof(memdbg_debug_threads_response_prefix_t)) {
      const memdbg_debug_threads_response_prefix_t *tl_pfx =
          (const memdbg_debug_threads_response_prefix_t *)tl_resp;
      if (tl_pfx->count > 0) {
        int32_t lwp = ((const memdbg_debug_thread_entry_t *)
                          (tl_resp + sizeof(*tl_pfx)))->lwp;

        /* Get RSP to use as watchpoint address */
        memdbg_debug_thread_request_t tr = { 0, lwp };
        uint8_t regs_resp[65536];
        uint32_t regs_len = sizeof(regs_resp);
        if (send_request(test_socket, MEMDBG_CMD_DEBUG_GET_REGS,
                         &tr, sizeof(tr), regs_resp, &regs_len) == 0 &&
            regs_len >= sizeof(memdbg_debug_regs_t)) {
          const memdbg_debug_regs_t *regs =
              (const memdbg_debug_regs_t *)regs_resp;
          uint64_t wp_addr = (uint64_t)regs->r_rsp;

          /* Set write watchpoint, 8 bytes, at RSP */
          memdbg_debug_watchpoint_request_t wp = { wp_addr, 8, 1 };
          quiet_payload_errors = 1;
          response_len = sizeof(response);
          int rc = send_request(test_socket, MEMDBG_CMD_DEBUG_SET_WATCHPOINT,
                                &wp, sizeof(wp), response, &response_len);
          quiet_payload_errors = 0;

          if (rc != 0) {
            printf("WARN: DEBUG_SET_WATCHPOINT at RSP=0x%" PRIx64
                   " failed (dbregs may be HW-limited)\n",
                   wp_addr);
          } else {
            printf("  DEBUG_SET_WATCHPOINT at RSP=0x%" PRIx64 ": OK\n", wp_addr);

            /* Verify in watchpoint list */
            {
              uint8_t wp_list[65536];
              uint32_t wp_len = sizeof(wp_list);
              if (send_request(test_socket, MEMDBG_CMD_DEBUG_GET_WATCHPOINTS,
                               NULL, 0, wp_list, &wp_len) == 0 &&
                  wp_len >= sizeof(memdbg_debug_watchpoint_list_prefix_t)) {
                const memdbg_debug_watchpoint_list_prefix_t *wp_pfx =
                    (const memdbg_debug_watchpoint_list_prefix_t *)wp_list;
                printf("  DEBUG_GET_WATCHPOINTS: count=%u\n", wp_pfx->count);

                const memdbg_debug_watchpoint_list_entry_t *wp_entries =
                    (const memdbg_debug_watchpoint_list_entry_t *)
                        (wp_list + sizeof(*wp_pfx));
                for (uint32_t i = 0; i < wp_pfx->count; ++i) {
                  if (wp_entries[i].flags & 1) { /* installed */
                    printf("    WP: addr=0x%" PRIx64 " len=%u type=%u slot=%u\n",
                           wp_entries[i].address, wp_entries[i].length,
                           wp_entries[i].type, wp_entries[i].slot);
                  }
                }
              }

              /* Clear it */
              memdbg_debug_watchpoint_request_t wp_clr = { wp_addr, 0, 0 };
              if (send_request(test_socket, MEMDBG_CMD_DEBUG_CLEAR_WATCHPOINT,
                               &wp_clr, sizeof(wp_clr),
                               response, &response_len) != 0) {
                printf("FAIL: DEBUG_CLEAR_WATCHPOINT\n"); failures++;
              } else {
                printf("  DEBUG_CLEAR_WATCHPOINT: OK\n");
              }
            }
          }
        }
      }
    }
  }

  /* 12. Batch clear-all */
  /* Step 13: Make sure we don't leave breakpoints behind */
  {
    quiet_payload_errors = 1;
    int rc = send_cmd(test_socket, MEMDBG_CMD_DEBUG_CLEAR_ALL_BREAKPOINTS);
    quiet_payload_errors = 0;
    if (rc == 0) printf("  DEBUG_CLEAR_ALL_BREAKPOINTS: OK\n");
    else printf("WARN: CLEAR_ALL_BREAKPOINTS failed (may be expected)\n");

    quiet_payload_errors = 1;
    rc = send_cmd(test_socket, MEMDBG_CMD_DEBUG_CLEAR_ALL_WATCHPOINTS);
    quiet_payload_errors = 0;
    if (rc == 0) printf("  DEBUG_CLEAR_ALL_WATCHPOINTS: OK\n");
    else printf("WARN: CLEAR_ALL_WATCHPOINTS failed (may be expected)\n");
  }

  /* 13. DEBUG_DETACH */
  {
    int rc = send_cmd(test_socket, MEMDBG_CMD_DEBUG_DETACH);
    if (rc != 0) { printf("FAIL: DEBUG_DETACH\n"); failures++; }
    else printf("  DEBUG_DETACH: OK\n");
  }

  /* 14. Clean up child */
  if (child_pid > 0) {
    /* Child may have terminated after detach, or may still be sleeping.
     * SIGTERM first, then SIGKILL after a short wait. */
    kill(child_pid, SIGTERM);
    sleep_ms(100U);
    kill(child_pid, SIGKILL);
    waitpid(child_pid, NULL, 0);
    printf("  Child cleaned up\n");
  }

  /* 15. PING to verify connection still alive */
  {
    int rc = send_cmd(test_socket, MEMDBG_CMD_PING);
    if (rc != 0) { printf("FAIL: PING after debugger ops\n"); failures++; }
    else printf("  PING: OK\n");
  }

  close(test_socket);

  if (failures == 0) {
    printf("\nE2E Debugger test PASSED.\n");
  } else {
    printf("\nE2E Debugger test: %d failure(s).\n", failures);
  }

  return failures > 0 ? 1 : 0;
}
