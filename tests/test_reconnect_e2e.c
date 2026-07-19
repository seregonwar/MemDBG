/*
 * memDBG - E2E test: daemon restart and reconnect resilience.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Simulates a rest-mode cycle by:
 *   1. Connecting to the daemon and verifying the session is functional.
 *   2. Killing the daemon (simulating console rest mode).
 *   3. Restarting the daemon on the same port.
 *   4. Reconnecting and verifying the session works again.
 *   5. Checking that daemon_instance_id changed (new payload instance).
 *
 * Usage: test_reconnect_e2e <host> <port> <daemon_cmd...>
 *   e.g.  test_reconnect_e2e 127.0.0.1 19140 ./build/MemDBG-host --data-root=/tmp/xxx
 *
 * The test kills and restarts the daemon itself; the Makefile rule just
 * spawns the initial daemon and passes its PID + command line as args.
 */

#include "memdbg/core/memdbg_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
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
#define RESTART_SLEEP_MS 800
#define KILL_WAIT_MS 600
#define RESP_BUF_SIZE (256U * 1024U)

static const char *g_host = "127.0.0.1";
static uint16_t    g_port = 9020;
static char       *g_daemon_argv[32];
static int         g_daemon_argc = 0;
static pid_t       g_daemon_pid = 0;

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
    perror("connect");
    close(fd);
    return -1;
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

/* Send command with body, read response header + body into caller buffer.
 * Returns 0 on success (status=0), -1 on transport error or non-zero status. */
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
    /* Child: exec the daemon.  Close stdin so the daemon cannot read from
     * the test's input.  stdout/stderr go to inherited fds (the Makefile
     * redirects them to a log file). */
    close(STDIN_FILENO);
    g_daemon_argv[g_daemon_argc] = NULL;
    execvp(g_daemon_argv[0], g_daemon_argv);
    perror("execvp");
    _exit(1);
  }
  /* Give the daemon time to bind the port. */
  sleep_ms(RESTART_SLEEP_MS);
  return 0;
}

static void kill_daemon(void) {
  if (g_daemon_pid <= 0) return;
  /* Graceful shutdown first, then force-kill. */
  kill(g_daemon_pid, SIGTERM);
  sleep_ms(KILL_WAIT_MS);
  if (kill(g_daemon_pid, 0) == 0) {
    kill(g_daemon_pid, SIGKILL);
    sleep_ms(200);
  }
  waitpid(g_daemon_pid, NULL, 0);
  g_daemon_pid = 0;
}

/* ---- Test cases ---- */

static int test_hello_instance_id(int fd, uint64_t *out_instance_id) {
  memdbg_hello_response_t hello;
  uint8_t buf[256];
  uint32_t buf_len = sizeof(buf);

  if (send_request(fd, MEMDBG_CMD_HELLO, NULL, 0, buf, &buf_len, NULL) != 0) {
    printf("FAIL: HELLO\n");
    return 1;
  }

  if (buf_len < sizeof(hello)) {
    memcpy(&hello, buf, buf_len);
  } else {
    memcpy(&hello, buf, sizeof(hello));
  }

  printf("  HELLO: protocol=%u platform=%u caps=0x%08x level=%u\n",
         hello.protocol_version, hello.platform_id,
         hello.capabilities, hello.feature_level);
  printf("  daemon_instance_id=0x%016llx start_ns=%llu\n",
         (unsigned long long)hello.daemon_instance_id,
         (unsigned long long)hello.daemon_start_monotonic_ns);

  if (out_instance_id)
    *out_instance_id = hello.daemon_instance_id;

  if (hello.daemon_instance_id == 0U) {
    printf("  WARNING: daemon_instance_id is zero (pre-v2 payload?)\n");
  }

  return 0;
}

static int test_process_list(int fd) {
  static uint8_t buf[RESP_BUF_SIZE];
  uint32_t buf_len = sizeof(buf);

  if (send_request(fd, MEMDBG_CMD_PROCESS_LIST, NULL, 0, buf, &buf_len,
                   NULL) != 0) {
    printf("FAIL: PROCESS_LIST\n");
    return 1;
  }

  /* Response is a flat list of memdbg_process_entry_t (52 bytes each).
   * Entry count is response_len / sizeof(memdbg_process_entry_t). */
  uint32_t count = buf_len / (uint32_t)sizeof(memdbg_process_entry_t);
  printf("  PROCESS_LIST: %u entries (%u bytes)\n", count, buf_len);
  return 0;
}

/* ---- Main ---- */

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);

  /* ---- Parse args: <host> <port> <daemon_binary> [daemon_args...] ---- */
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

  printf("--- E2E Reconnect Resilience Test ---\n");
  printf("Target: %s:%u  daemon: %s\n", g_host, g_port, g_daemon_argv[0]);
  int failures = 0;

  /* ---- Test 1: Initial connection ---- */
  printf("\n[1] Initial connection\n");

  if (spawn_daemon() != 0) {
    printf("FAIL: daemon spawn\n");
    kill_daemon();
    return 1;
  }

  int fd = tcp_connect();
  if (fd < 0) {
    printf("FAIL: initial connect\n");
    kill_daemon();
    return 1;
  }
  printf("  connected\n");

  uint64_t instance_id_1 = 0;
  if (test_hello_instance_id(fd, &instance_id_1) != 0) failures++;
  if (test_process_list(fd) != 0) failures++;
  close(fd);

  /* ---- Test 2: Daemon restart ---- */
  printf("\n[2] Daemon restart (simulating rest mode)\n");

  kill_daemon();
  printf("  daemon killed\n");

  if (spawn_daemon() != 0) {
    printf("FAIL: daemon restart\n");
    kill_daemon();
    return 1;
  }
  printf("  daemon restarted\n");

  /* ---- Test 3: Reconnect after restart ---- */
  printf("\n[3] Reconnect after restart\n");

  fd = tcp_connect();
  if (fd < 0) {
    printf("FAIL: reconnect after restart\n");
    kill_daemon();
    return 1;
  }
  printf("  reconnected\n");

  uint64_t instance_id_2 = 0;
  if (test_hello_instance_id(fd, &instance_id_2) != 0) failures++;
  if (test_process_list(fd) != 0) failures++;
  close(fd);

  /* ---- Test 4: Instance ID rotation ---- */
  printf("\n[4] daemon_instance_id rotation\n");

  if (instance_id_1 == 0U || instance_id_2 == 0U) {
    printf("  SKIP: instance_id not available (pre-v2 payload)\n");
  } else if (instance_id_1 == instance_id_2) {
    printf("FAIL: daemon_instance_id unchanged after restart!\n");
    printf("  old=0x%016llx new=0x%016llx\n",
           (unsigned long long)instance_id_1,
           (unsigned long long)instance_id_2);
    failures++;
  } else {
    printf("  instance_id changed: 0x%016llx → 0x%016llx ✓\n",
           (unsigned long long)instance_id_1,
           (unsigned long long)instance_id_2);
  }

  /* ---- Test 5: Second restart cycle ---- */
  printf("\n[5] Second restart cycle\n");

  kill_daemon();
  printf("  daemon killed (2nd cycle)\n");

  if (spawn_daemon() != 0) {
    printf("FAIL: daemon second restart\n");
    kill_daemon();
    return 1;
  }
  printf("  daemon restarted (2nd cycle)\n");

  fd = tcp_connect();
  if (fd < 0) {
    printf("FAIL: reconnect after second restart\n");
    kill_daemon();
    return 1;
  }
  printf("  reconnected (2nd cycle)\n");

  uint64_t instance_id_3 = 0;
  if (test_hello_instance_id(fd, &instance_id_3) != 0) failures++;
  if (test_process_list(fd) != 0) failures++;
  close(fd);

  if (instance_id_3 != 0U && instance_id_2 != 0U &&
      instance_id_3 != instance_id_2) {
    printf("  instance_id changed again ✓\n");
  }

  /* ---- Cleanup ---- */
  kill_daemon();

  printf("\n=== VERDICT: %d failure(s) ===\n", failures);
  if (failures == 0) {
    printf("E2E reconnect resilience test PASSED.\n");
    return 0;
  }
  printf("E2E reconnect resilience test FAILED.\n");
  return 1;
}
