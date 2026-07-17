/*
 * memDBG - Dynamic thread pool unit test.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tests the acceptor/handler connection model:
 * - Single acceptor thread with poll-based accept polling
 * - Per-connection detached handler threads
 * - max_connections cap enforcement
 * - No connection count leaks on shutdown
 * - Concurrent client connect/rejection correctness
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ---- Test configuration ---- */

#define MAX_CONNECTIONS  4   /* accept cap under test */
#define CLIENT_COUNT     8   /* total concurrent connects (> cap) */
#define CONNECT_TIMEOUT_S 3  /* per-connect timeout */
#define POLL_MS           10 /* acceptor poll interval (ms) */
#define HANDLER_SLEEP_MS  100 /* simulated work per handler */

/* ---- Shared state ---- */

/* Zero-initialized by virtue of being static / file-scope. */
static atomic_uint g_active_connections;
static atomic_bool  g_stop_requested;
static atomic_int   g_accepted_count;
static atomic_int   g_rejected_count;
static atomic_int   g_connected_count;

/* ---- Minimal random port binding ---- */

static int bind_any_port(uint16_t *out_port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { perror("socket"); return -1; }

  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0; /* any port */

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("bind"); close(fd); return -1;
  }

  if (listen(fd, 16) != 0) {
    perror("listen"); close(fd); return -1;
  }

  socklen_t len = sizeof(addr);
  if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
    perror("getsockname"); close(fd); return -1;
  }

  *out_port = ntohs(addr.sin_port);
  return fd;
}

/* ---- Per-connection handler (simulates handle_client) ---- */

typedef struct {
  int client_fd;
} handler_args_t;

static void *handler_thread(void *arg) {
  handler_args_t *hargs = (handler_args_t *)arg;
  int fd = hargs->client_fd;
  free(hargs);

  /* Simulate processing (e.g. HELLO, protocol loop, etc.) */
  {
    struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)HANDLER_SLEEP_MS * 1000000L };
    nanosleep(&ts, NULL);
  }

  /* Close the fd — handle_client does pal_socket_close() */
  close(fd);

  atomic_fetch_sub_explicit(&g_active_connections, 1U, memory_order_relaxed);
  return NULL;
}

/* Arguments passed to the acceptor thread.  Mirrors daemon's acceptor_args_t. */
typedef struct {
  int listen_fd;
} acceptor_args_t;

/* ---- Acceptor thread (mirrors daemon's acceptor_thread) ---- */

static void *acceptor_thread(void *arg) {
  acceptor_args_t *aargs = (acceptor_args_t *)arg;
  int listen_fd = aargs->listen_fd;
  free(aargs);

  while (!atomic_load_explicit(&g_stop_requested, memory_order_relaxed)) {
    /* Poll with short timeout (simulates epoll_wait/kevent with 1ms). */
    struct pollfd pfd;
    pfd.fd     = listen_fd;
    pfd.events = POLLIN;
    int rc = poll(&pfd, 1, POLL_MS);
    if (rc < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (rc == 0) continue; /* timeout — check stop flag */

    struct sockaddr_in peer;
    socklen_t slen = sizeof(peer);
    int client_fd = accept(listen_fd, (struct sockaddr *)&peer, &slen);
    if (client_fd < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        continue;
      break;
    }

    /* Enforce the connection cap: accept first to drain the TCP backlog,
     * then reject if over limit.  This mirrors the daemon's logic. */
    uint32_t active = atomic_load_explicit(&g_active_connections,
                                            memory_order_acquire);
    if (active >= MAX_CONNECTIONS) {
      atomic_fetch_add_explicit(&g_rejected_count, 1, memory_order_relaxed);
      close(client_fd);
      continue;
    }

    atomic_fetch_add_explicit(&g_active_connections, 1U, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_accepted_count, 1, memory_order_relaxed);

    /* Spawn detached handler. */
    handler_args_t *hargs = (handler_args_t *)malloc(sizeof(*hargs));
    if (hargs == NULL) {
      fprintf(stderr, "  ERROR: malloc handler args failed\n");
      close(client_fd);
      atomic_fetch_sub_explicit(&g_active_connections, 1U, memory_order_relaxed);
      continue;
    }
    hargs->client_fd = client_fd;

    pthread_t tid;
    if (pthread_create(&tid, NULL, handler_thread, hargs) != 0) {
      fprintf(stderr, "  ERROR: pthread_create handler failed\n");
      free(hargs);
      close(client_fd);
      atomic_fetch_sub_explicit(&g_active_connections, 1U, memory_order_relaxed);
      continue;
    }
    pthread_detach(tid);
  }

  return NULL;
}

/* ---- Client thread ---- */

static int g_port = 0; /* set before client threads start */

static void *client_thread(void *arg) {
  (void)arg;

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { perror("client socket"); return NULL; }

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port   = htons((uint16_t)g_port);
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

  /* Set connect timeout. */
  struct timeval tv = { CONNECT_TIMEOUT_S, 0 };
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (rc != 0) {
    /* Connection refused — expected for rejected clients. */
    close(fd);
    return NULL;
  }

  /* The client got past connect().  The handler may close the fd
   * shortly, but we've verified the connection was accepted. */
  atomic_fetch_add_explicit(&g_connected_count, 1, memory_order_relaxed);

  /* Sleep briefly so the handler has time to process and close. */
  {
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 200 * 1000000L };
    nanosleep(&ts, NULL);
  }

  /* Attempt a write — should fail with EPIPE if the handler already
   * closed the fd (expected for accepted clients). */
  (void)send(fd, "x", 1, 0);

  close(fd);
  return NULL;
}

/* ---- Monotonic time helper ---- */

static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ---- Main ---- */

static int test_passed = 1;

static void check(const char *label, int condition) {
  if (!condition) {
    fprintf(stderr, "  FAIL: %s\n", label);
    test_passed = 0;
  } else {
    printf("  PASS: %s\n", label);
  }
}

int main(void) {
  /* Suppress SIGPIPE so send() on closed socket returns EPIPE. */
  signal(SIGPIPE, SIG_IGN);

  printf("\n=== Dynamic Thread Pool Test ===\n\n");

  uint16_t port = 0;
  int listen_fd = bind_any_port(&port);
  if (listen_fd < 0) {
    fprintf(stderr, "FATAL: could not bind listen socket\n");
    return 1;
  }
  g_port = (int)port;
  printf("Listening on 127.0.0.1:%u  (cap=%d, clients=%d)\n",
         port, MAX_CONNECTIONS, CLIENT_COUNT);

  /* Start the single acceptor thread. */
  acceptor_args_t *aargs = (acceptor_args_t *)malloc(sizeof(*aargs));
  if (aargs == NULL) {
    fprintf(stderr, "FATAL: malloc acceptor args\n");
    close(listen_fd);
    return 1;
  }
  aargs->listen_fd = listen_fd;

  pthread_t acceptor_tid;
  if (pthread_create(&acceptor_tid, NULL, acceptor_thread, aargs) != 0) {
    fprintf(stderr, "FATAL: could not create acceptor thread\n");
    free(aargs);
    close(listen_fd);
    return 1;
  }

  /* Allow the listen backlog to settle. */
  {
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 50000000L };
    nanosleep(&ts, NULL);
  }

  /* Launch all client threads simultaneously. */
  printf("Launching %d concurrent clients...\n", CLIENT_COUNT);

  pthread_t clients[CLIENT_COUNT];
  uint64_t t0 = now_ms();

  for (int i = 0; i < CLIENT_COUNT; ++i) {
    if (pthread_create(&clients[i], NULL, client_thread, NULL) != 0) {
      fprintf(stderr, "FATAL: could not create client thread %d\n", i);
      return 1;
    }
  }

  /* Join all client threads. */
  for (int i = 0; i < CLIENT_COUNT; ++i)
    pthread_join(clients[i], NULL);

  uint64_t dt = now_ms() - t0;
  printf("Clients finished in %llu ms\n", (unsigned long long)dt);

  /* Signal the acceptor to stop. */
  atomic_store_explicit(&g_stop_requested, true, memory_order_relaxed);
  close(listen_fd); /* unblock poll() */
  pthread_join(acceptor_tid, NULL);

  /* Drain: wait for all handler threads to finish. */
  printf("Draining %u active handlers...\n",
         atomic_load_explicit(&g_active_connections, memory_order_relaxed));
  uint64_t drain_start = now_ms();
  while (atomic_load_explicit(&g_active_connections, memory_order_relaxed) > 0U) {
    {
      struct timespec ts = { .tv_sec = 0, .tv_nsec = 5000000L };
      nanosleep(&ts, NULL);
    }
    if (now_ms() - drain_start > 5000) {
      fprintf(stderr, "  TIMEOUT waiting for handlers to drain\n");
      test_passed = 0;
      break;
    }
  }

  int accepted  = atomic_load_explicit(&g_accepted_count, memory_order_relaxed);
  int rejected  = atomic_load_explicit(&g_rejected_count, memory_order_relaxed);
  int connected = atomic_load_explicit(&g_connected_count, memory_order_relaxed);
  uint32_t remaining = atomic_load_explicit(&g_active_connections,
                                             memory_order_relaxed);

  printf("\n--- Results ---\n");
  printf("  accepted:   %d\n", accepted);
  printf("  rejected:   %d\n", rejected);
  printf("  connected:  %d (clients that got past connect())\n", connected);
  printf("  active at drain end: %u\n", remaining);
  printf("  unaccounted: %d (clients that failed connect())\n",
         CLIENT_COUNT - accepted - rejected);

  printf("\n--- Verdicts ---\n");

  /* 1. The acceptor must not accept more than MAX_CONNECTIONS. */
  check("accepted <= max_connections", accepted <= MAX_CONNECTIONS);

  /* 2. Total (accepted + rejected) should cover all clients.
   *    Some clients may fail to connect() if the listen backlog
   *    is full, so we allow a tiny margin. */
  int total = accepted + rejected;
  check("accepted+rejected covers most clients",
        total >= (int)(CLIENT_COUNT - (CLIENT_COUNT > 4 ? CLIENT_COUNT / 4 : 1)));

  /* 3. At least 2 clients must have been rejected (cap=4, clients=8). */
  check("at least 2 clients rejected", rejected >= 2);

  /* 4. Accepted count >= 1 (at least one got through). */
  check("at least 1 accepted", accepted >= 1);

  /* 5. Zero active connections after drain. */
  check("zero active connections after drain", remaining == 0U);

  /* 6. At least as many clients got past connect() as were accepted.
   *    On loopback the kernel TCP backlog allows more connect()-level
   *    handshakes than the application accept(), which is expected. */
  check("connected >= accepted", connected >= accepted);

  printf("\n=== %s ===\n\n",
         test_passed ? "ALL PASSED" : "SOME FAILED");

  close(listen_fd);
  return test_passed ? 0 : 1;
}
