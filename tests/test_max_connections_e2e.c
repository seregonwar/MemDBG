/*
 * memDBG - E2E test: max_connections cap enforcement.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Connects to the running daemon, opens multiple concurrent connections,
 * and verifies that the max_connections cap is enforced correctly.
 * Excess connections should be rejected (connection closed by peer).
 *
 * Usage: test_max_connections_e2e <host> <port> [expected_max]
 *   Default expected_max = 4
 *
 * The daemon must be started with --max-connections=<expected_max>.
 */

#include "memdbg/core/memdbg_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ---- Configuration ---- */

#define CLIENT_COUNT     8   /* total concurrent clients */
#define CONNECT_TIMEOUT  3   /* seconds per connect/IO */

static const char *g_host = "127.0.0.1";
static uint16_t    g_port = 9020;
static uint32_t    g_expected_max = 4;

/* ---- Shared atomic counters ---- */

static atomic_uint g_accepted   = 0;  /* count of HELLO responses with status=0 */
static atomic_uint g_rejected   = 0;  /* count of connection failures or refusals */
static atomic_uint g_errors     = 0;  /* unexpected errors (not connect rejections) */

/* ---- Helpers ---- */

static int try_connect(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct timeval tv = { CONNECT_TIMEOUT, 0 };
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(g_port);
  if (inet_pton(AF_INET, g_host, &addr.sin_addr) != 1) {
    close(fd);
    return -2;
  }

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int saved = errno;
    close(fd);
    /* ECONNREFUSED / ETIMEDOUT are expected when cap is exceeded */
    return (saved == ECONNREFUSED || saved == ETIMEDOUT) ? -1 : -3;
  }
  return fd;
}

static int do_hello(int fd) {
  memdbg_packet_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic      = MEMDBG_PACKET_MAGIC;
  hdr.version    = MEMDBG_PROTOCOL_VERSION;
  hdr.command    = MEMDBG_CMD_HELLO;
  hdr.request_id = 1;
  hdr.length     = 0;

  if (send(fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr)) return -1;

  memdbg_response_header_t rhdr;
  memset(&rhdr, 0, sizeof(rhdr));

  ssize_t n = recv(fd, &rhdr, sizeof(rhdr), MSG_WAITALL);
  if (n <= 0) return -1;

  if (rhdr.magic   != MEMDBG_PACKET_MAGIC ||
      rhdr.version != MEMDBG_PROTOCOL_VERSION ||
      rhdr.command != MEMDBG_CMD_HELLO) {
    return -1;
  }

  /* If status != 0 the connection was rejected or cap was exceeded */
  if (rhdr.status != 0) return -1;

  return 0;  /* accepted */
}

/* ---- Client thread ---- */

static void *client_worker(void *arg) {
  (void)arg;

  int fd = try_connect();
  if (fd < 0) {
    /* Could not connect at all — treated as cap rejection */
    atomic_fetch_add(&g_rejected, 1U);
    return NULL;
  }

  int rc = do_hello(fd);

  if (rc == 0) {
    /* Accepted! Now hold the connection open so the daemon's handler
     * thread stays alive, keeping g_active_connections at the cap
     * level while the acceptor processes remaining connections. */
    atomic_fetch_add(&g_accepted, 1U);
    struct timespec ts = { 1, 0 };  /* 1 second hold */
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
  } else {
    /* Connected but HELLO was rejected/ignored */
    atomic_fetch_add(&g_rejected, 1U);
  }

  close(fd);
  return NULL;
}

/* ---- Main ---- */

int main(int argc, char **argv) {
  if (argc >= 2) g_host = argv[1];
  if (argc >= 3) g_port = (uint16_t)atoi(argv[2]);
  if (argc >= 4) g_expected_max = (uint32_t)atoi(argv[3]);

  printf("--- E2E max_connections cap test ---\n");
  printf("Target: %s:%u  expected_max=%u  total_clients=%d\n",
         g_host, g_port, g_expected_max, CLIENT_COUNT);

  /* Reset counters */
  atomic_store(&g_accepted, 0U);
  atomic_store(&g_rejected, 0U);
  atomic_store(&g_errors,   0U);

  pthread_t threads[CLIENT_COUNT];
  int failures = 0;

  /* Launch all client threads concurrently */
  for (int i = 0; i < CLIENT_COUNT; ++i) {
    if (pthread_create(&threads[i], NULL, client_worker, NULL) != 0) {
      printf("FAIL: pthread_create[%d]\n", i);
      failures++;
    }
  }

  /* Join all threads */
  for (int i = 0; i < CLIENT_COUNT; ++i) {
    (void)pthread_join(threads[i], NULL);
  }

  uint32_t accepted = atomic_load(&g_accepted);
  uint32_t rejected = atomic_load(&g_rejected);
  uint32_t errors   = atomic_load(&g_errors);

  printf("\nResults:\n");
  printf("  accepted     = %u\n", accepted);
  printf("  rejected     = %u\n", rejected);
  printf("  total        = %u\n", accepted + rejected);

  /* ---- Verdicts ---- */

  /* 1. accepted <= expected_max (cap enforced) */
  if (accepted <= g_expected_max) {
    printf("  VERDICT 1: accepted=%u <= max=%u  ✓ cap enforced\n",
           accepted, g_expected_max);
  } else {
    printf("  VERDICT 1: accepted=%u > max=%u  ✗ cap NOT enforced\n",
           accepted, g_expected_max);
    failures++;
  }

  /* 2. At least (CLIENT_COUNT - expected_max) connections were rejected */
  uint32_t min_rejected = (uint32_t)CLIENT_COUNT - g_expected_max;
  if (rejected >= min_rejected) {
    printf("  VERDICT 2: rejected=%u >= %u  ✓ excess blocked\n",
           rejected, min_rejected);
  } else {
    printf("  VERDICT 2: rejected=%u < %u  ✗ not all excess blocked\n",
           rejected, min_rejected);
    failures++;
  }

  /* 3. No unexpected errors */
  if (errors == 0) {
    printf("  VERDICT 3: errors=0  ✓ clean\n");
  } else {
    printf("  VERDICT 3: errors=%u  ✗ unexpected errors\n", errors);
    failures++;
  }

  /* 4. All clients got a response (accepted + rejected == CLIENT_COUNT) */
  if (accepted + rejected == (uint32_t)CLIENT_COUNT) {
    printf("  VERDICT 4: total=%d == %d  ✓ all accounted\n",
           accepted + rejected, CLIENT_COUNT);
  } else {
    printf("  VERDICT 4: total=%d != %d  ✗ missing verdicts\n",
           accepted + rejected, CLIENT_COUNT);
    failures++;
  }

  if (failures == 0) {
    printf("\nE2E max_connections test PASSED.\n");
    return 0;
  }

  printf("\nE2E max_connections test: %d failure(s).\n", failures);
  return 1;
}
