/*
 * memDBG - Unit test: idle timeout via select().
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Self-contained test (no daemon required).  Creates a socketpair,
 * spawns a reader thread with a short timeout, and verifies that
 * select() correctly times out when no data arrives.
 *
 * Tests:
 *   1. read times out after ~TIMEOUT_MS of inactivity
 *   2. data arriving within the timeout is delivered successfully
 *   3. elapsed time for the timeout path is within tolerance
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ---- Configuration ---- */

#define TIMEOUT_MS  500U    /* idle timeout for the reader */
#define MARGIN_MS   200U    /* acceptable deviation from TIMEOUT_MS */
#define SLEEP_AFTER 100U    /* writer sleeps this long before sending */

/* ---- Helpers ---- */

static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL +
         (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void do_sleep(uint32_t ms) {
  struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

/* ---- Shared state between main and reader thread ---- */

typedef struct {
  int      fd;             /* socket to read from */
  int      expect_data;    /* 1 = data will arrive, 0 = timeout expected */
  int      result;         /* 1 = data read, 0 = timeout, -1 = error */
  uint64_t elapsed_ms;     /* actual time spent in select+recv */
} reader_ctx_t;

static void *reader_thread(void *arg) {
  reader_ctx_t *ctx = (reader_ctx_t *)arg;
  int fd = ctx->fd;

  uint64_t start = now_ms();

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);

  struct timeval tv;
  tv.tv_sec  = TIMEOUT_MS / 1000;
  tv.tv_usec = (suseconds_t)(TIMEOUT_MS % 1000) * 1000;

  int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
  if (rc < 0) {
    ctx->result = -1;
    return NULL;
  }

  if (rc == 0) {
    /* Timeout — no data */
    ctx->result     = 0;
    ctx->elapsed_ms = now_ms() - start;
    return NULL;
  }

  /* Data available — read it */
  char buf[64];
  ssize_t n = recv(fd, buf, sizeof(buf), 0);
  if (n <= 0) {
    ctx->result = -1;
    return NULL;
  }

  ctx->result     = 1;
  ctx->elapsed_ms = now_ms() - start;
  return NULL;
}

/* ---- Individual test routines ---- */

static int test_timeout(void) {
  printf("  TEST: read times out after %u ms...\n", TIMEOUT_MS);

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    perror("socketpair"); return -1;
  }

  reader_ctx_t ctx;
  ctx.fd          = sv[0];
  ctx.expect_data = 0;
  ctx.result      = -1;
  ctx.elapsed_ms  = 0;

  pthread_t tid;
  if (pthread_create(&tid, NULL, reader_thread, &ctx) != 0) {
    perror("pthread_create");
    close(sv[0]); close(sv[1]);
    return -1;
  }

  /* Do NOT send any data — let it time out */
  pthread_join(tid, NULL);

  close(sv[0]); close(sv[1]);

  if (ctx.result != 0) {
    printf("    ✗ expected timeout (0), got %d\n", ctx.result);
    return 1;
  }

  if (ctx.elapsed_ms < TIMEOUT_MS) {
    printf("    ✗ timeout too fast: %llu ms < %u ms\n",
           (unsigned long long)ctx.elapsed_ms, TIMEOUT_MS);
    return 1;
  }

  if (ctx.elapsed_ms > TIMEOUT_MS + MARGIN_MS) {
    printf("    ✗ timeout too slow: %llu ms > %u ms\n",
           (unsigned long long)ctx.elapsed_ms,
           TIMEOUT_MS + MARGIN_MS);
    return 1;
  }

  printf("    ✓ timed out after %llu ms (expected ~%u ms)\n",
         (unsigned long long)ctx.elapsed_ms, TIMEOUT_MS);
  return 0;
}

static int test_data_before_timeout(void) {
  printf("  TEST: data arrives before %u ms timeout...\n", TIMEOUT_MS);

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    perror("socketpair"); return -1;
  }

  reader_ctx_t ctx;
  ctx.fd          = sv[0];
  ctx.expect_data = 1;
  ctx.result      = -1;
  ctx.elapsed_ms  = 0;

  pthread_t tid;
  if (pthread_create(&tid, NULL, reader_thread, &ctx) != 0) {
    perror("pthread_create");
    close(sv[0]); close(sv[1]);
    return -1;
  }

  /* Send data after a short delay — well within the timeout */
  do_sleep(SLEEP_AFTER);
  char ping[] = "PING";
  send(sv[1], ping, sizeof(ping), 0);

  pthread_join(tid, NULL);

  close(sv[0]); close(sv[1]);

  if (ctx.result != 1) {
    printf("    ✗ expected data (1), got %d\n", ctx.result);
    return 1;
  }

  if (ctx.elapsed_ms >= TIMEOUT_MS) {
    printf("    ✗ read took too long: %llu ms >= %u ms\n",
           (unsigned long long)ctx.elapsed_ms, TIMEOUT_MS);
    return 1;
  }

  printf("    ✓ data read after %llu ms (well before %u ms timeout)\n",
         (unsigned long long)ctx.elapsed_ms, TIMEOUT_MS);
  return 0;
}

static int test_timeout_precision(void) {
  printf("  TEST: timeout precision (5 iterations)...\n");

  int failures = 0;
  for (int i = 0; i < 5; i++) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
      perror("socketpair"); return -1;
    }

    reader_ctx_t ctx;
    ctx.fd          = sv[0];
    ctx.expect_data = 0;
    ctx.result      = -1;
    ctx.elapsed_ms  = 0;

    pthread_t tid;
    pthread_create(&tid, NULL, reader_thread, &ctx);
    pthread_join(tid, NULL);

    close(sv[0]); close(sv[1]);

    if (ctx.result != 0) {
      printf("    iteration %d: ✗ expected timeout, got %d\n", i, ctx.result);
      failures++;
      continue;
    }

    if (ctx.elapsed_ms < TIMEOUT_MS ||
        ctx.elapsed_ms > TIMEOUT_MS + MARGIN_MS) {
      printf("    iteration %d: ✗ %llu ms out of range [%u, %u]\n",
             i, (unsigned long long)ctx.elapsed_ms,
             TIMEOUT_MS, TIMEOUT_MS + MARGIN_MS);
      failures++;
      continue;
    }

    printf("    iteration %d: %llu ms ✓\n",
           i, (unsigned long long)ctx.elapsed_ms);
  }

  return failures;
}

/* ---- Main ---- */

int main(void) {
  int total = 0, passed = 0;

  printf("--- Idle timeout unit test (%u ms timeout) ---\n", TIMEOUT_MS);

  /* 1. Timeout */
  printf("\n[1/3] Timeout behavior\n");
  int rc = test_timeout();
  total++;
  if (rc == 0) { passed++; printf("  PASS\\n"); }
  else         { printf("  FAIL\\n"); }

  /* 2. Data before timeout */
  printf("\n[2/3] Data delivery before timeout\n");
  rc = test_data_before_timeout();
  total++;
  if (rc == 0) { passed++; printf("  PASS\\n"); }
  else         { printf("  FAIL\\n"); }

  /* 3. Precision */
  printf("\n[3/3] Timeout precision\n");
  rc = test_timeout_precision();
  total++;
  if (rc == 0) { passed++; printf("  PASS\\n"); }
  else         { printf("  FAIL (%d deviations)\\n", rc); }

  printf("\n--- Results: %d/%d passed ---\n", passed, total);

  /* Also run the E2E idle timeout test with 500ms if available */
  return (passed == total) ? 0 : 1;
}
