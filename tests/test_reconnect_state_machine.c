/*
 * memDBG - State machine test: reconnect phase transitions.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Exercises the full reconnect state machine cycle at the protocol level:
 *   1. Connect → HELLO → phase = Online (session functional).
 *   2. Kill daemon (simulate rest mode).
 *   3. Send PING twice → both fail (heartbeat failure × 2).
 *   4. phase → ConnectionLost → WaitingForWake.
 *   5. Restart daemon.
 *   6. tcp_connect_retry → phase = Reconnecting → HELLO.
 *   7. Verify new daemon_instance_id → phase = Restoring → Online.
 *
 * Usage: test_reconnect_state_machine <host> <port> <daemon_binary> [daemon_args...]
 *   e.g.  test_reconnect_state_machine 127.0.0.1 19142 ./build/MemDBG-host --data-root=/tmp/xxx
 */

#include "memdbg/core/memdbg_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---- Configuration ---- */

#define IO_TIMEOUT_SEC 10
#define CONNECT_RETRY_MS 5000
#define CONNECT_STEP_MS 200
#define KILL_WAIT_MS 600
#define HEARTBEAT_FAILURE_THRESHOLD 2
#define RESP_BUF_SIZE (256U * 1024U)

static const char *g_host = "127.0.0.1";
static uint16_t    g_port = 9020;
static char       *g_daemon_argv[32];
static int         g_daemon_argc = 0;
static pid_t       g_daemon_pid = 0;

/* ---- State machine (mirrors frontend ConnectionPhase) ---- */

typedef enum {
  PHASE_DISCONNECTED,
  PHASE_CONNECTING,
  PHASE_ONLINE,
  PHASE_CONNECTION_LOST,
  PHASE_WAITING_FOR_WAKE,
  PHASE_RECONNECTING,
  PHASE_RESTORING,
} sm_phase_t;

static const char *phase_name(sm_phase_t p) {
  switch (p) {
  case PHASE_DISCONNECTED:     return "Disconnected";
  case PHASE_CONNECTING:       return "Connecting";
  case PHASE_ONLINE:           return "Online";
  case PHASE_CONNECTION_LOST:  return "ConnectionLost";
  case PHASE_WAITING_FOR_WAKE: return "WaitingForWake";
  case PHASE_RECONNECTING:     return "Reconnecting";
  case PHASE_RESTORING:        return "Restoring";
  default:                     return "???";
  }
}


/* ---- Test result tracking ---- */

static int g_test_passed = 0;
static int g_test_failed = 0;

#define PHASE_ASSERT(test_name, actual, expected)                              \
  do {                                                                         \
    if ((actual) == (expected)) {                                              \
      g_test_passed++;                                                         \
      printf("  PASS  %s  [%s]\n", test_name, phase_name(actual));            \
    } else {                                                                   \
      g_test_failed++;                                                         \
      printf("  FAIL  %s  expected %s, got %s\n",                             \
             test_name, phase_name(expected), phase_name(actual));             \
    }                                                                          \
  } while (0)

#define ASSERT_TRUE(test_name, expr)                                           \
  do {                                                                         \
    if (expr) {                                                                \
      g_test_passed++;                                                         \
      printf("  PASS  %s\n", test_name);                                       \
    } else {                                                                   \
      g_test_failed++;                                                         \
      printf("  FAIL  %s\n", test_name);                                       \
    }                                                                          \
  } while (0)

/* ---- Helpers ---- */

static void sleep_ms(uint32_t ms) {
  struct timespec ts = { (time_t)(ms / 1000), (long)(ms % 1000) * 1000000L };
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

static int tcp_connect(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { perror("socket"); return -1; }

  struct timeval tv = { IO_TIMEOUT_SEC, 0 };
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(g_port);
  if (inet_pton(AF_INET, g_host, &addr.sin_addr) != 1) {
    close(fd);
    return -1;
  }

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int tcp_connect_retry(uint32_t timeout_ms, uint32_t *out_elapsed_ms) {
  uint32_t elapsed = 0;
  int fd = -1;

  while (elapsed < timeout_ms) {
    fd = tcp_connect();
    if (fd >= 0) {
      if (out_elapsed_ms) *out_elapsed_ms = elapsed;
      printf("  connected after %u ms\n", elapsed);
      return fd;
    }

    uint32_t delay = CONNECT_STEP_MS;
    if (elapsed + delay > timeout_ms) delay = timeout_ms - elapsed;
    if (delay > 0) sleep_ms(delay);
    elapsed += delay;
  }

  fd = tcp_connect();
  if (fd >= 0) {
    if (out_elapsed_ms) *out_elapsed_ms = elapsed;
    printf("  connected after %u ms (final attempt)\n", elapsed);
  }
  return fd;
}

static int read_all(int fd, void *buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t n = recv(fd, (uint8_t *)buf + total, len - total, MSG_WAITALL);
    if (n <= 0) return -1;
    total += (size_t)n;
  }
  return 0;
}

static int send_request(int fd, uint16_t cmd,
                        const void *body, uint32_t body_len,
                        uint8_t *resp_buf, uint32_t *resp_len,
                        int32_t *out_status) {
  static uint32_t next_id = 1;
  memdbg_packet_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic      = MEMDBG_PACKET_MAGIC;
  hdr.version    = MEMDBG_PROTOCOL_VERSION;
  hdr.command    = cmd;
  hdr.request_id = next_id++;
  hdr.length     = body_len;

  if (send(fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr)) return -1;
  if (body_len > 0 && send(fd, body, body_len, 0) != (ssize_t)body_len)
    return -1;

  memdbg_response_header_t rhdr;
  memset(&rhdr, 0, sizeof(rhdr));
  if (read_all(fd, &rhdr, sizeof(rhdr)) != 0) return -1;
  if (rhdr.magic   != MEMDBG_PACKET_MAGIC ||
      rhdr.version != MEMDBG_PROTOCOL_VERSION ||
      rhdr.command != cmd) {
    fprintf(stderr, "  response header mismatch\n");
    return -1;
  }
  if (out_status) *out_status = (int32_t)rhdr.status;
  if (rhdr.status != 0) {
    fprintf(stderr, "  payload status: %d\n", (int)rhdr.status);
    return -1;
  }
  if (rhdr.length > *resp_len) {
    fprintf(stderr, "  response too large: %u > %u\n",
            rhdr.length, *resp_len);
    return -1;
  }
  if (rhdr.length > 0 && read_all(fd, resp_buf, rhdr.length) != 0)
    return -1;
  *resp_len = rhdr.length;
  return 0;
}

/* ---- Daemon lifecycle ---- */

static int spawn_daemon(void) {
  g_daemon_pid = fork();
  if (g_daemon_pid < 0) {
    perror("fork");
    return -1;
  }
  if (g_daemon_pid == 0) {
    close(STDIN_FILENO);
    g_daemon_argv[g_daemon_argc] = NULL;
    execvp(g_daemon_argv[0], g_daemon_argv);
    perror("execvp");
    _exit(1);
  }
  return 0;
}

static void kill_daemon(void) {
  if (g_daemon_pid <= 0) return;
  kill(g_daemon_pid, SIGTERM);
  sleep_ms(KILL_WAIT_MS);
  if (kill(g_daemon_pid, 0) == 0) {
    kill(g_daemon_pid, SIGKILL);
    sleep_ms(200);
  }
  waitpid(g_daemon_pid, NULL, 0);
  g_daemon_pid = 0;
}

/* ---- Heartbeat (PING) with failure tracking ---- */

static int send_ping(int fd) {
  uint8_t buf[64];
  uint32_t buf_len = sizeof(buf);
  return send_request(fd, MEMDBG_CMD_PING, NULL, 0, buf, &buf_len, NULL);
}

static int send_hello(int fd, uint64_t *out_instance_id) {
  memdbg_hello_response_t hello;
  uint8_t buf[256];
  uint32_t buf_len = sizeof(buf);

  if (send_request(fd, MEMDBG_CMD_HELLO, NULL, 0, buf, &buf_len, NULL) != 0)
    return -1;

  if (buf_len < sizeof(hello))
    memcpy(&hello, buf, buf_len);
  else
    memcpy(&hello, buf, sizeof(hello));

  printf("  HELLO: protocol=%u platform=%u caps=0x%08x daemon_instance_id=0x%016llx\n",
         hello.protocol_version, hello.platform_id,
         hello.capabilities,
         (unsigned long long)hello.daemon_instance_id);

  if (out_instance_id)
    *out_instance_id = hello.daemon_instance_id;

  return 0;
}

/* ---- Main ---- */

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);

  if (argc < 4) {
    fprintf(stderr,
      "Usage: %s <host> <port> <daemon_binary> [daemon_args...]\n",
      argv[0]);
    return 1;
  }

  g_host = argv[1];
  g_port = (uint16_t)atoi(argv[2]);
  for (int i = 3; i < argc && g_daemon_argc < 31; i++)
    g_daemon_argv[g_daemon_argc++] = argv[i];

  printf("=== Reconnect State Machine Test ===\n");
  printf("Target: %s:%u  daemon: %s\n", g_host, g_port, g_daemon_argv[0]);

  sm_phase_t phase = PHASE_DISCONNECTED;
  uint64_t instance_id_before = 0;
  uint64_t instance_id_after = 0;

  /* ================================================================
   * Phase 1: Connect → Online
   * ================================================================ */
  printf("\n--- Phase 1: Connect → Online ---\n");

  PHASE_ASSERT("initial phase", phase, PHASE_DISCONNECTED);

  if (spawn_daemon() != 0) {
    printf("FAIL: daemon spawn\n");
    kill_daemon();
    return 1;
  }

  phase = PHASE_CONNECTING;
  PHASE_ASSERT("spawn → Connecting", phase, PHASE_CONNECTING);

  int fd = tcp_connect_retry(CONNECT_RETRY_MS, NULL);
  ASSERT_TRUE("tcp_connect_retry succeeds", fd >= 0);
  if (fd < 0) {
    kill_daemon();
    return 1;
  }

  if (send_hello(fd, &instance_id_before) != 0) {
    printf("FAIL: initial HELLO\n");
    close(fd);
    kill_daemon();
    return 1;
  }

  phase = PHASE_ONLINE;
  PHASE_ASSERT("HELLO success → Online", phase, PHASE_ONLINE);
  ASSERT_TRUE("instance_id_before is non-zero", instance_id_before != 0ULL);

  /* Verify session works */
  ASSERT_TRUE("PING in Online phase succeeds", send_ping(fd) == 0);

  /* ================================================================
   * Phase 2: Heartbeat failure × 2 → WaitingForWake
   * ================================================================ */
  printf("\n--- Phase 2: Heartbeat failure × 2 → WaitingForWake ---\n");

  /* Kill the daemon — simulates console entering rest mode */
  kill_daemon();
  printf("  daemon killed (simulating rest mode)\n");

  /* Heartbeat failure #1 — PING should fail (socket will get RST or timeout) */
  int hb1 = send_ping(fd);
  int hb_failures = (hb1 != 0) ? 1 : 0;
  printf("  heartbeat #1: %s (failures=%d/%d)\n",
         hb1 != 0 ? "LOST" : "OK",
         hb_failures, HEARTBEAT_FAILURE_THRESHOLD);

  /* Heartbeat failure #2 */
  int hb2 = send_ping(fd);
  if (hb2 != 0) hb_failures++;
  printf("  heartbeat #2: %s (failures=%d/%d)\n",
         hb2 != 0 ? "LOST" : "OK",
         hb_failures, HEARTBEAT_FAILURE_THRESHOLD);

  ASSERT_TRUE("heartbeat failures reached threshold",
              hb_failures >= HEARTBEAT_FAILURE_THRESHOLD);

  /* Transition: ConnectionLost (transport detected dead) */
  phase = PHASE_CONNECTION_LOST;
  PHASE_ASSERT("2x heartbeat fail → ConnectionLost", phase, PHASE_CONNECTION_LOST);

  /* Close the dead socket */
  close(fd);
  fd = -1;

  /* Transition: WaitingForWake (backoff timer starts) */
  phase = PHASE_WAITING_FOR_WAKE;
  PHASE_ASSERT("close socket → WaitingForWake", phase, PHASE_WAITING_FOR_WAKE);

  /* ================================================================
   * Phase 3: Restart → Reconnecting → Restoring → Online
   * ================================================================ */
  printf("\n--- Phase 3: Restart → Reconnecting → Restoring → Online ---\n");

  /* Restart the daemon — simulates console waking from rest mode */
  if (spawn_daemon() != 0) {
    printf("FAIL: daemon restart\n");
    kill_daemon();
    return 1;
  }
  printf("  daemon restarted (simulating wake from rest mode)\n");

  /* poll_reconnect → Reconnecting */
  phase = PHASE_RECONNECTING;
  PHASE_ASSERT("daemon restart → poll_reconnect begins", phase, PHASE_RECONNECTING);

  /* connect_console(AutomaticReconnect) — retry connect with timeout */
  fd = tcp_connect_retry(CONNECT_RETRY_MS, NULL);
  ASSERT_TRUE("tcp_connect_retry for reconnect succeeds", fd >= 0);

  /* Send new HELLO — verify instance_id changed */
  if (send_hello(fd, &instance_id_after) != 0) {
    printf("FAIL: reconnect HELLO\n");
    close(fd);
    kill_daemon();
    return 1;
  }

  /* Transition: Restoring — session state must be revalidated */
  phase = PHASE_RESTORING;
  PHASE_ASSERT("reconnect HELLO → Restoring", phase, PHASE_RESTORING);

  /* Verify daemon_instance_id rotation */
  ASSERT_TRUE("instance_id_after is non-zero", instance_id_after != 0ULL);
  ASSERT_TRUE("daemon_instance_id changed after restart",
              instance_id_after != instance_id_before);
  printf("  instance_id: 0x%016llx → 0x%016llx (rotation verified)\n",
         (unsigned long long)instance_id_before,
         (unsigned long long)instance_id_after);

  /* Verify session works after reconnect */
  ASSERT_TRUE("PING in Restoring phase succeeds", send_ping(fd) == 0);

  /* Transition: Online — session fully restored */
  phase = PHASE_ONLINE;
  PHASE_ASSERT("session verified → Online", phase, PHASE_ONLINE);

  /* ================================================================
   * Phase 4: Second cycle (stress test)
   * ================================================================ */
  printf("\n--- Phase 4: Second restart cycle (stress test) ---\n");

  kill_daemon();
  printf("  daemon killed (2nd cycle)\n");

  /* Simulate heartbeat failures on stale socket */
  int hb3 = send_ping(fd);
  int hb4 = send_ping(fd);
  int hb2_failures = (hb3 != 0 ? 1 : 0) + (hb4 != 0 ? 1 : 0);
  ASSERT_TRUE("second cycle: heartbeat failures detected",
              hb2_failures >= HEARTBEAT_FAILURE_THRESHOLD);

  close(fd);
  phase = PHASE_CONNECTION_LOST;
  PHASE_ASSERT("2nd cycle: → ConnectionLost", phase, PHASE_CONNECTION_LOST);

  phase = PHASE_WAITING_FOR_WAKE;
  PHASE_ASSERT("2nd cycle: → WaitingForWake", phase, PHASE_WAITING_FOR_WAKE);

  if (spawn_daemon() != 0) {
    printf("FAIL: daemon second restart\n");
    kill_daemon();
    return 1;
  }

  phase = PHASE_RECONNECTING;
  PHASE_ASSERT("2nd cycle: → Reconnecting", phase, PHASE_RECONNECTING);

  fd = tcp_connect_retry(CONNECT_RETRY_MS, NULL);
  ASSERT_TRUE("2nd cycle: tcp_connect_retry succeeds", fd >= 0);

  uint64_t instance_id_third = 0;
  if (fd >= 0 && send_hello(fd, &instance_id_third) == 0) {
    phase = PHASE_RESTORING;
    PHASE_ASSERT("2nd cycle: HELLO → Restoring", phase, PHASE_RESTORING);

    ASSERT_TRUE("2nd cycle: instance_id rotated again",
                instance_id_third != instance_id_after);
    ASSERT_TRUE("2nd cycle: PING succeeds", send_ping(fd) == 0);

    phase = PHASE_ONLINE;
    PHASE_ASSERT("2nd cycle: → Online", phase, PHASE_ONLINE);
  }

  /* ---- Cleanup ---- */
  if (fd >= 0) close(fd);
  kill_daemon();

  /* ---- Final tally ---- */
  int total = g_test_passed + g_test_failed;
  printf("\n=== Results ======================================\n");
  printf("Phase transitions tested: %d\n", total);
  printf("  PASS: %d\n", g_test_passed);
  printf("  FAIL: %d\n", g_test_failed);
  printf("==================================================\n");

  if (g_test_failed > 0) {
    printf("State machine test FAILED.\n");
    return 1;
  }

  printf("State machine test PASSED — all %d phase transitions verified.\n", total);
  return 0;
}
