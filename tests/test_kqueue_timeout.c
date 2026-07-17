/*
 * memDBG - Unit test: kqueue timeout precision.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Self-contained test (no daemon required).  Tests the daemon's
 * wait_for_client() directly via the extracted pal_wait module:
 * socketpair + wait_for_client() with a short timeout.
 *
 * This is the same codepath the daemon uses on macOS, FreeBSD, PS4, PS5.
 *
 * Tests:
 *   1. kevent times out after ~TIMEOUT_MS with no data
 *   2. kevent fires immediately when data is already queued
 *   3. kevent precision across multiple iterations
 *   4. Non-blocking poll (timeout=0) returns instantly
 */

#include "memdbg/pal/pal_wait.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---- Configuration ---- */

#define TIMEOUT_MS  500U
#define MARGIN_MS   250U   /* generous margin for CI/loaded systems */
#define ITERATIONS  5

/* ---- Helpers ---- */

static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL +
         (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* ---- Test 1: timeout with no data ---- */

static int test_timeout(void) {
  printf("  TEST: kevent times out after %u ms...\n", TIMEOUT_MS);

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    perror("socketpair"); return -1;
  }

  uint64_t start = now_ms();
  int rc = wait_for_client(sv[0], (int)TIMEOUT_MS);
  uint64_t elapsed = now_ms() - start;

  close(sv[0]); close(sv[1]);

  if (rc != 0) {
    printf("    ✗ expected timeout (0), got %d\n", rc);
    return 1;
  }

  if (elapsed < TIMEOUT_MS) {
    printf("    ✗ timeout too fast: %llu ms < %u ms\n",
           (unsigned long long)elapsed, TIMEOUT_MS);
    return 1;
  }

  if (elapsed > TIMEOUT_MS + MARGIN_MS) {
    printf("    ✗ timeout too slow: %llu ms > %u ms\n",
           (unsigned long long)elapsed, TIMEOUT_MS + MARGIN_MS);
    return 1;
  }

  printf("    ✓ timed out after %llu ms (expected ~%u ms)\n",
         (unsigned long long)elapsed, TIMEOUT_MS);
  return 0;
}

/* ---- Test 2: data already queued — fires instantly ---- */

static int test_immediate_data(void) {
  printf("  TEST: wait_for_client fires immediately when data is queued...\n");

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    perror("socketpair"); return -1;
  }

  /* Write data before polling */
  char ping = '!';
  send(sv[1], &ping, 1, 0);

  uint64_t start = now_ms();
  int rc = wait_for_client(sv[0], 5000); /* 5s timeout — should return instantly */
  uint64_t elapsed = now_ms() - start;

  close(sv[0]); close(sv[1]);

  if (rc != 1) {
    printf("    ✗ expected data (1), got %d\n", rc);
    return 1;
  }

  if (elapsed > 100) {
    printf("    ✗ slow response: %llu ms (expected << 100 ms)\n",
           (unsigned long long)elapsed);
    return 1;
  }

  printf("    ✓ data detected after %llu ms (instant)\n",
         (unsigned long long)elapsed);
  return 0;
}

/* ---- Test 3: precision across multiple iterations ---- */

static int test_precision(void) {
  printf("  TEST: wait_for_client precision (%d iterations)...\n", ITERATIONS);

  int failures = 0;
  for (int i = 0; i < ITERATIONS; i++) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
      perror("socketpair"); return -1;
    }

    uint64_t start = now_ms();
    int rc = wait_for_client(sv[0], (int)TIMEOUT_MS);
    uint64_t elapsed = now_ms() - start;

    close(sv[0]); close(sv[1]);

    if (rc != 0) {
      printf("    iteration %d: ✗ expected timeout, got %d\n", i, rc);
      failures++; continue;
    }

    if (elapsed < TIMEOUT_MS || elapsed > TIMEOUT_MS + MARGIN_MS) {
      printf("    iteration %d: ✗ %llu ms out of range [%u, %u]\n",
             i, (unsigned long long)elapsed,
             TIMEOUT_MS, TIMEOUT_MS + MARGIN_MS);
      failures++; continue;
    }

    printf("    iteration %d: %llu ms ✓\n",
           i, (unsigned long long)elapsed);
  }
  return failures;
}

/* ---- Test 4: zero-timeout (non-blocking poll) ---- */

static int test_zero_timeout(void) {
  printf("  TEST: wait_for_client with timeout=0 returns instantly...\n");

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    perror("socketpair"); return -1;
  }

  uint64_t start = now_ms();
  int rc = wait_for_client(sv[0], 0); /* purely non-blocking poll */
  uint64_t elapsed = now_ms() - start;

  close(sv[0]); close(sv[1]);

  /* No data queued, so it should time out immediately */
  if (rc != 0) {
    printf("    ✗ expected timeout (0), got %d\n", rc);
    return 1;
  }

  if (elapsed > 10) {
    printf("    ✗ non-blocking poll took %llu ms (expected << 10 ms)\n",
           (unsigned long long)elapsed);
    return 1;
  }

  printf("    ✓ non-blocking poll returned in %llu ms\n",
         (unsigned long long)elapsed);
  return 0;
}

/* ---- Test 5: error handling on invalid fd ---- */

static int test_bad_fd(void) {
  printf("  TEST: wait_for_client with invalid fd returns error...\n");

  /* Use an fd that is definitely invalid */
  int rc = wait_for_client(9999, 100);
  if (rc >= 0) {
    printf("    ✗ expected error, got %d\n", rc);
    return 1;
  }

  printf("    ✓ invalid fd correctly returned -1\n");
  return 0;
}

/* ---- Main ---- */

int main(void) {
  int total = 0, passed = 0;

  printf("--- kqueue timeout precision test (%u ms) ---\n", TIMEOUT_MS);

  /* 1 */
  printf("\n[1/5] Timeout\n");
  int rc = test_timeout();
  total++; if (rc == 0) { passed++; printf("  PASS\n"); }
  else printf("  FAIL\n");

  /* 2 */
  printf("\n[2/5] Immediate data\n");
  rc = test_immediate_data();
  total++; if (rc == 0) { passed++; printf("  PASS\n"); }
  else printf("  FAIL\n");

  /* 3 */
  printf("\n[3/5] Precision\n");
  rc = test_precision();
  total++; if (rc == 0) { passed++; printf("  PASS\n"); }
  else printf("  FAIL (%d deviations)\n", rc);

  /* 4 */
  printf("\n[4/5] Zero timeout (non-blocking)\n");
  rc = test_zero_timeout();
  total++; if (rc == 0) { passed++; printf("  PASS\n"); }
  else printf("  FAIL\n");

  /* 5 */
  printf("\n[5/5] Invalid fd\n");
  rc = test_bad_fd();
  total++; if (rc == 0) { passed++; printf("  PASS\n"); }
  else printf("  FAIL\n");

  printf("\n--- Results: %d/%d passed ---\n", passed, total);
  return (passed == total) ? 0 : 1;
}
