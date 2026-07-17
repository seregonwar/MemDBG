/*
 * memDBG - E2E test: idle timeout disconnection.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Connects to the daemon, sends HELLO to confirm the connection is alive,
 * then waits longer than the idle timeout.  After the timeout fires the
 * daemon should close the connection, so the next request must fail.
 *
 * Usage: test_idle_timeout_e2e <host> <port> [idle_timeout_ms]
 *   Default idle_timeout_ms = 3000 (must match daemon's --idle-timeout=MS)
 */

#include "memdbg/core/memdbg_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ---- Configuration ---- */

#define IO_TIMEOUT_SEC 10

static const char *g_host   = "127.0.0.1";
static uint16_t    g_port   = 9020;
static uint32_t    g_idle_ms = 3000;

/* ---- Helpers ---- */

static void sleep_ms(uint32_t ms) {
  struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

static int tcp_connect(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct timeval tv = { IO_TIMEOUT_SEC, 0 };
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(g_port);
  if (inet_pton(AF_INET, g_host, &addr.sin_addr) != 1) { close(fd); return -1; }

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

/* Send a command (no body) and return 0 on success (status=0), -1 on failure. */
static int send_cmd(int fd, uint16_t cmd) {
  memdbg_packet_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic      = MEMDBG_PACKET_MAGIC;
  hdr.version    = MEMDBG_PROTOCOL_VERSION;
  hdr.command    = cmd;
  hdr.request_id = 1;
  hdr.length     = 0;

  if (send(fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr)) return -1;

  memdbg_response_header_t rhdr;
  memset(&rhdr, 0, sizeof(rhdr));
  ssize_t n = recv(fd, &rhdr, sizeof(rhdr), MSG_WAITALL);
  if (n <= 0) return -1;

  if (rhdr.magic   != MEMDBG_PACKET_MAGIC ||
      rhdr.version != MEMDBG_PROTOCOL_VERSION ||
      rhdr.command != cmd) return -1;

  return (rhdr.status == 0) ? 0 : -1;
}

/* ---- Main ---- */

int main(int argc, char **argv) {
  if (argc >= 2) g_host    = argv[1];
  if (argc >= 3) g_port    = (uint16_t)atoi(argv[2]);
  if (argc >= 4) g_idle_ms = (uint32_t)atoi(argv[3]);

  int failures = 0;

  printf("--- E2E idle timeout test ---\n");
  printf("Target: %s:%u  idle_timeout=%u ms\n", g_host, g_port, g_idle_ms);

  /* 1. Connect */
  int fd = tcp_connect();
  if (fd < 0) {
    printf("FAIL: connect\n");
    return 1;
  }
  printf("  connected\n");

  /* 2. HELLO — must succeed (connection is alive) */
  if (send_cmd(fd, MEMDBG_CMD_HELLO) != 0) {
    printf("FAIL: HELLO before idle timeout\n");
    close(fd);
    return 1;
  }
  printf("  HELLO: OK (connection alive)\n");

  /* 3. Wait for the idle timeout to fire, plus margin.
   *    The daemon closes the connection after g_idle_ms of inactivity. */
  uint32_t wait_ms = g_idle_ms + 1500U;  /* timeout + 1.5s margin */
  printf("  sleeping %u ms (timeout=%u + margin)...\n", wait_ms, g_idle_ms);
  sleep_ms(wait_ms);

  /* 4. PING — must FAIL because the daemon should have closed the connection */
  int rc = send_cmd(fd, MEMDBG_CMD_PING);
  if (rc == 0) {
    printf("  PING: OK (unexpected — connection still alive after idle timeout!)\n");
  } else {
    printf("  PING: failed (expected after idle timeout) ✓\n");
  }

  /* 5. Also try to send raw data to verify the socket is really dead */
  {
    char junk = 0;
    ssize_t n = send(fd, &junk, 1, 0);
    if (n < 0) {
      printf("  send: %s (expected after idle timeout) ✓\n", strerror(errno));
    } else {
      printf("  send: succeeded (unexpected — socket still writable)\n");
    }
  }

  close(fd);

  /* Verdict: PING should have failed (idle timeout fired) */
  if (rc == 0) {
    printf("\nVERDICT: ✗ idle timeout NOT enforced\n");
    failures++;
  } else {
    printf("\nVERDICT: ✓ idle timeout enforced\n");
  }

  if (failures == 0) {
    printf("\nE2E idle timeout test PASSED.\n");
    return 0;
  }

  printf("\nE2E idle timeout test: %d failure(s).\n", failures);
  return 1;
}
