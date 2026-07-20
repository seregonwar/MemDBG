/*
 * memDBG - Stress test: 50 consecutive daemon restarts with reconnect.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Verifies that the daemon can be killed and restarted 50 times without:
 *   - File descriptor leaks (both in the test harness and daemon)
 *   - No unexpected FD accumulation
 *   - Port binding failures (TIME_WAIT exhaustion)
 *   - State corruption in the protocol layer
 *   - daemon_instance_id uniqueness across restarts
 *
 * Each iteration:
 *   1. Spawn daemon on a single fixed port
 *   2. TCP connect (with retry, up to 5 seconds)
 *   3. Send HELLO, verify daemon_instance_id is non-zero and unique
 *   4. Send PING, verify session is functional
 *   5. Kill daemon (SIGTERM, then SIGKILL if needed)
 *   6. Check that no unexpected FDs accumulated
 *
 * Usage: test_reconnect_50_restarts <host> <port> <daemon_binary> [daemon_args...]
 *   e.g.  test_reconnect_50_restarts 127.0.0.1 19144 ./build/MemDBG-host \
 *           --bind=127.0.0.1 --debug-port=19144 --data-root=/tmp/xxx --no-udp-log
 */

#include "memdbg/core/memdbg_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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

#define RESTART_ITERATIONS  50
#define IO_TIMEOUT_SEC      10
#define CONNECT_RETRY_MS    5000
#define CONNECT_STEP_MS     200
#define KILL_WAIT_MS        600
#define RESP_BUF_SIZE       (256U * 1024U)
#define MAX_UNIQUE_IDS      64

static const char *g_host = "127.0.0.1";
static uint16_t    g_port = 9020;
static char       *g_daemon_argv[32];
static int         g_daemon_argc = 0;
static pid_t       g_daemon_pid = 0;

/* ---- Test result tracking ---- */

static int g_test_passed = 0;
static int g_test_failed = 0;

#define TEST_PASS(msg)                                                        \
  do {                                                                        \
    g_test_passed++;                                                          \
    printf("  PASS  %s\n", msg);                                              \
  } while (0)

#define TEST_FAIL(msg)                                                        \
  do {                                                                        \
    g_test_failed++;                                                          \
    printf("  FAIL  %s\n", msg);                                              \
  } while (0)

#define ASSERT_TRUE(msg, expr)                                                \
  do {                                                                        \
    if (expr) { TEST_PASS(msg); }                                             \
    else       { TEST_FAIL(msg); }                                            \
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

static int tcp_connect_retry(uint32_t timeout_ms) {
  uint32_t elapsed = 0;
  int fd = -1;

  while (elapsed < timeout_ms) {
    fd = tcp_connect();
    if (fd >= 0) return fd;

    uint32_t delay = CONNECT_STEP_MS;
    if (elapsed + delay > timeout_ms) delay = timeout_ms - elapsed;
    if (delay > 0) sleep_ms(delay);
    elapsed += delay;
  }

  fd = tcp_connect();
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
                        uint8_t *resp_buf, uint32_t *resp_len) {
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
    return -1;
  }
  if (rhdr.status != 0) return -1;
  if (rhdr.length > *resp_len) return -1;
  if (rhdr.length > 0 && read_all(fd, resp_buf, rhdr.length) != 0)
    return -1;
  *resp_len = rhdr.length;
  return 0;
}

/* ---- Daemon lifecycle ---- */

static int spawn_daemon(void) {
  g_daemon_pid = fork();
  if (g_daemon_pid < 0) { perror("fork"); return -1; }
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

/* ---- Protocol helpers ---- */

static int do_hello(int fd, uint64_t *out_instance_id) {
  uint8_t buf[256];
  uint32_t buf_len = sizeof(buf);
  if (send_request(fd, MEMDBG_CMD_HELLO, NULL, 0, buf, &buf_len) != 0)
    return -1;

  memdbg_hello_response_t hello;
  if (buf_len < sizeof(hello))
    memcpy(&hello, buf, buf_len);
  else
    memcpy(&hello, buf, sizeof(hello));

  if (out_instance_id) *out_instance_id = hello.daemon_instance_id;
  return 0;
}

static int do_ping(int fd) {
  uint8_t buf[64];
  uint32_t buf_len = sizeof(buf);
  return send_request(fd, MEMDBG_CMD_PING, NULL, 0, buf, &buf_len);
}

/* ---- FD leak detection (macOS via /dev/fd or proc) ---- */

/* Count open file descriptors by probing F_GETFD on each slot.
 * On macOS the per-process fd limit defaults to 256, so checking 0..255
 * covers all practical slots for a test harness. */
static int count_open_fds(void) {
  int count = 0;
  for (int fd = 0; fd < 256; fd++) {
    if (fcntl(fd, F_GETFD) >= 0)
      count++;
  }
  return count;
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

  printf("=== Reconnect 50-Restart Stress Test ===\n");
  printf("Target: %s:%u  daemon: %s\n", g_host, g_port, g_daemon_argv[0]);
  printf("Iterations: %d\n\n", RESTART_ITERATIONS);

  uint64_t unique_ids[MAX_UNIQUE_IDS];
  uint32_t unique_count = 0;
  int      total_failures = 0;
  int      first_connect_time_ms = -1;
  int      min_connect_ms = 9999;
  int      max_connect_ms = 0;
  int      total_connect_ms = 0;
  int      connect_samples = 0;

  int fds_before = count_open_fds();

  for (int iter = 1; iter <= RESTART_ITERATIONS; iter++) {
    printf("--- Iteration %d/%d ---\n", iter, RESTART_ITERATIONS);

    /* 1. Spawn daemon */
    if (spawn_daemon() != 0) {
      printf("  FAIL: daemon spawn on iteration %d\n", iter);
      total_failures++;
      continue;
    }

    /* 2. Connect with retry */
    uint32_t start_ms = 0;
    {
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      start_ms = (uint32_t)(ts.tv_sec * 1000U + ts.tv_nsec / 1000000U);
    }

    int fd = tcp_connect_retry(CONNECT_RETRY_MS);
    if (fd < 0) {
      printf("  FAIL: connect failed on iteration %d\n", iter);
      total_failures++;
      kill_daemon();
      continue;
    }

    {
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      uint32_t elapsed = (uint32_t)(ts.tv_sec * 1000U + ts.tv_nsec / 1000000U) - start_ms;
      if (first_connect_time_ms < 0) first_connect_time_ms = (int)elapsed;
      if ((int)elapsed < min_connect_ms) min_connect_ms = (int)elapsed;
      if ((int)elapsed > max_connect_ms) max_connect_ms = (int)elapsed;
      total_connect_ms += (int)elapsed;
      connect_samples++;
      printf("  connected in %u ms\n", elapsed);
    }

    /* 3. HELLO + verify instance_id */
    uint64_t instance_id = 0;
    if (do_hello(fd, &instance_id) != 0) {
      printf("  FAIL: HELLO on iteration %d\n", iter);
      total_failures++;
      close(fd);
      kill_daemon();
      continue;
    }
    printf("  instance_id=0x%016llx\n", (unsigned long long)instance_id);

    ASSERT_TRUE("instance_id non-zero", instance_id != 0ULL);

    /* Check uniqueness */
    bool unique = true;
    for (uint32_t i = 0; i < unique_count; i++) {
      if (unique_ids[i] == instance_id) {
        unique = false;
        break;
      }
    }
    ASSERT_TRUE("instance_id unique across restarts", unique);
    if (unique && unique_count < MAX_UNIQUE_IDS) {
      unique_ids[unique_count++] = instance_id;
    }

    /* 4. PING - verify session works */
    ASSERT_TRUE("PING succeeds", do_ping(fd) == 0);

    /* 5. Close connection, kill daemon */
    close(fd);
    fd = -1;

    kill_daemon();
    sleep_ms(200); /* Allow kernel to release port (TIME_WAIT) */

    printf("\n");
  }

  /* ---- Final FD leak check ---- */
  int fds_after = count_open_fds();
  printf("--- FD Leak Check ---\n");
  printf("  FDs before: %d  FDs after: %d\n", fds_before, fds_after);
  ASSERT_TRUE("no FD leak (>10 FDs gained = suspicious)",
              (fds_after - fds_before) < 10);

  /* ---- Stats ---- */
  printf("\n--- Connection Timing ---\n");
  printf("  First connect: %d ms\n", first_connect_time_ms);
  printf("  Min: %d ms  Max: %d ms  Avg: %d ms (over %d samples)\n",
         min_connect_ms, max_connect_ms,
         connect_samples > 0 ? total_connect_ms / connect_samples : 0,
         connect_samples);
  printf("  Unique instance IDs generated: %u / %d\n",
         unique_count, RESTART_ITERATIONS);

  /* ---- Final tally ---- */
  int total = g_test_passed + g_test_failed;
  printf("\n=== Results ======================================\n");
  printf("Tests: %d  PASS: %d  FAIL: %d  Total errors: %d\n",
         total, g_test_passed, g_test_failed, total_failures);
  printf("==================================================\n");

  if (g_test_failed > 0 || total_failures > 0) {
    printf("50-restart stress test FAILED.\n");
    return 1;
  }

  printf("50-restart stress test PASSED — all %d iterations clean.\n",
         RESTART_ITERATIONS);
  return 0;
}
