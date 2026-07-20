/*
 * MemDBG - Test the EBADF retry path in pal_memory_read (TOCTOU race recovery).
 *
 * pal_memory_linux.c normally compiles only under __linux__.
 * This test file compiles it on any host by defining mock pal_file_*
 * functions BEFORE the #include, so the Linux code path can be
 * exercised without a real /proc/pid/mem filesystem.
 *
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* ===================================================================
 *  Mock file-I/O state (intercepted by the #include below)
 * =================================================================== */

static int   g_mock_open_count    = 0;
static int   g_mock_close_count   = 0;
static int   g_mock_pread_count   = 0;
static bool  g_mock_first_fail    = true;   /* first pread fails with EBADF */
static int   g_mock_next_fd       = 101;    /* monotonically increasing */
static int   g_mock_open_should_fail = 0;   /* if true, open() returns -1 */

#define pal_file_open        mock_pal_file_open
#define pal_file_close       mock_pal_file_close
#define pal_file_pread_all   mock_pal_file_pread_all
#define pal_file_pwrite_all  mock_pal_file_pwrite_all

static int mock_pal_file_open(const char *path, int flags, mode_t mode) {
  (void)path;
  (void)flags;
  (void)mode;
  ++g_mock_open_count;
  if (g_mock_open_should_fail) {
    g_mock_open_should_fail = 0;
    errno = EACCES;
    return -1;
  }
  return g_mock_next_fd++;
}

static int mock_pal_file_close(int fd) {
  (void)fd;
  ++g_mock_close_count;
  return 0;
}

static ssize_t mock_pal_file_pread_all(int fd, void *buffer, size_t count,
                                       off_t offset) {
  (void)fd;
  (void)offset;
  ++g_mock_pread_count;
  if (g_mock_first_fail) {
    /* Simulate TOCTOU race: the cached fd was closed by another thread. */
    g_mock_first_fail = false;
    errno = EBADF;
    return -1;
  }
  /* Success: fill buffer with a known pattern. */
  memset(buffer, 0xAA, count);
  return (ssize_t)count;
}

static ssize_t mock_pal_file_pwrite_all(int fd, const void *buffer,
                                        size_t count, off_t offset) {
  (void)fd;
  (void)buffer;
  (void)count;
  (void)offset;
  return -1; /* not used by these tests */
}

/* ===================================================================
 *  Include the implementation under test
 * =================================================================== */

#include "../src/pal/pal_memory_linux.c"

/* ===================================================================
 *  Test harness
 * =================================================================== */

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      ++g_passed;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      ++g_failed;                                                              \
      printf("  FAIL  %s\n", name);                                            \
    }                                                                          \
  } while (0)

static void reset_mocks(void) {
  g_mock_open_count      = 0;
  g_mock_close_count     = 0;
  g_mock_pread_count     = 0;
  g_mock_first_fail      = true;
  g_mock_next_fd         = 101;
  g_mock_open_should_fail = 0;
  /* Reset the fd cache by flushing all PIDs. */
  pal_memory_fd_cache_flush(0);
}

/* ---- Test 1: EBADF retry succeeds on second attempt ---- */
static void test_ebadf_retry_success(void) {
  reset_mocks();

  uint8_t buf[16];
  size_t read_out = 0;

  memdbg_status_t st = pal_memory_read(42, 0x1000, buf, sizeof(buf),
                                       &read_out);

  /* The first pread returned EBADF; the retry opened a fresh fd and
   * succeeded.  The caller should see a successful read. */
  TEST("EBADF retry: status is MEMDBG_OK", st == MEMDBG_OK);
  TEST("EBADF retry: read_out == requested length", read_out == 16);
  TEST("EBADF retry: buffer was filled", buf[0] == 0xAA && buf[15] == 0xAA);

  /* Two pread calls: one that fails (EBADF), one that succeeds (retry). */
  TEST("EBADF retry: pread called twice", g_mock_pread_count == 2);

  /* Two opens: one from fd_cache_get (stored in cache), one from the
   * EBADF retry path (opened directly, not cached). */
  TEST("EBADF retry: open called twice", g_mock_open_count == 2);

  /* Two closes: one from fd_cache_flush (closes stale fd=101), one from
   * the EBADF retry cleanup (closes temporary fd=102). */
  TEST("EBADF retry: close called twice", g_mock_close_count == 2);
}

/* ---- Test 2: EBADF retry also fails (persistent error) ----
 *
 * Scenario: cache hit → pread EBADF → retry open fails with EACCES.
 * The caller gets a terminal error (not retried again).
 *
 * We set up the cache manually by calling pal_memory_read once with
 * g_mock_first_fail = false so the cache is populated cleanly (no
 * EBADF on the first call).  Then we set g_mock_first_fail = true
 * and g_mock_open_should_fail = 1 so the next call will:
 *   1. Hit cache  (no open needed)
 *   2. Fail with EBADF on the pread
 *   3. Try to open a fresh fd → g_mock_open_should_fail triggers
 *   4. Return MEMDBG_ERR_IO (the retry open failed, but not EACCES
 *      since we gated on EBADF from the first attempt) */
static void test_ebadf_retry_fails(void) {
  /* --- Phase 1: populate cache (no EBADF) --- */
  reset_mocks();
  g_mock_first_fail = false;
  {
    uint8_t buf[16];
    size_t read_out = 0;
    pal_memory_read(42, 0x1000, buf, sizeof(buf), &read_out);
  }
  /* Cache now has pid=42 → fd=101. */

  /* --- Phase 2: enable EBADF + retry open failure --- */
  g_mock_first_fail = true;
  g_mock_open_should_fail = 1;  /* retry open returns -1/EACCES */
  /* Reset counters so we can verify exactly what happens next. */
  g_mock_open_count  = 0;
  g_mock_close_count = 0;
  g_mock_pread_count = 0;

  uint8_t buf[16];
  size_t read_out = 0;
  errno = 0;
  memdbg_status_t st = pal_memory_read(42, 0x2000, buf, sizeof(buf),
                                       &read_out);

  /* Cache hit → pread EBADF → retry open fails → terminal error. */
  TEST("EBADF retry: open-fail returns error", st != MEMDBG_OK);
  TEST("EBADF retry: read_out is zero on failure", read_out == 0);
  TEST("EBADF retry: pread called once (retry never reached pread)",
       g_mock_pread_count == 1);
  TEST("EBADF retry: one open attempt from retry (cache_get hit zero)",
       g_mock_open_count == 1);
  /* One close from fd_cache_flush, one from retry's close on open
   * failure... actually the retry only closes if it opened successfully.
   * Since open failed, only the cache flush close happens. */
  TEST("EBADF retry: close called once (cache flush)",
       g_mock_close_count == 1);
}

/* ---- Test 3: Normal path (no EBADF) works ---- */
static void test_normal_path(void) {
  reset_mocks();
  /* Disable EBADF simulation. */
  g_mock_first_fail = false;

  uint8_t buf[16];
  size_t read_out = 0;

  memdbg_status_t st = pal_memory_read(7, 0x1000, buf, sizeof(buf), &read_out);

  TEST("normal path: status is MEMDBG_OK", st == MEMDBG_OK);
  TEST("normal path: read_out == length", read_out == 16);
  TEST("normal path: pread called once", g_mock_pread_count == 1);
  TEST("normal path: open called once (from cache_get)",
       g_mock_open_count == 1);
  TEST("normal path: no close (fd stays in cache)",
       g_mock_close_count == 0);
}

/* ---- Test 4: Cache hit reuses cached fd (no open) ---- */
static void test_cache_hit(void) {
  reset_mocks();
  g_mock_first_fail = false;

  uint8_t buf[16];
  size_t read_out = 0;

  /* First call: creates cache entry (1 open). */
  memdbg_status_t st1 = pal_memory_read(99, 0x1000, buf, sizeof(buf),
                                        &read_out);
  const int opens_after_first = g_mock_open_count;

  /* Second call to same PID: should hit the cache (0 opens). */
  memdbg_status_t st2 = pal_memory_read(99, 0x2000, buf, sizeof(buf),
                                        &read_out);

  TEST("cache hit: first call succeeded", st1 == MEMDBG_OK);
  TEST("cache hit: second call succeeded", st2 == MEMDBG_OK);
  TEST("cache hit: no additional open on second call",
       g_mock_open_count == opens_after_first);
  TEST("cache hit: pread called twice total", g_mock_pread_count == 2);
}

/* ---- Test 5: pal_memory_write uses separate fd (not cached) ---- */
static void test_write_path(void) {
  reset_mocks();
  g_mock_first_fail = false;

  const uint8_t data[] = {0x11, 0x22, 0x33};
  size_t written = 0;

  /* pal_memory_write opens its own /proc/pid/mem O_RDWR, reads aren't
   * affected by the mock EBADF since write doesn't use the cache. */
  /* Our mock pwrite_all just returns -1 (not implemented), so this
   * test just verifies it doesn't crash and follows the right path. */
  memdbg_status_t st = pal_memory_write(42, 0x1000, data, sizeof(data),
                                        &written);

  /* The mock pwrite_all returns -1, so write should fail. */
  TEST("write path: fails with I/O error",
       st == MEMDBG_ERR_IO);
  TEST("write path: written is zero on failure", written == 0);
}

int main(void) {
  printf("=== PAL Memory EBADF Retry Tests ===\n");
  printf("(uses mock file I/O, no real /proc/pid/mem required)\n\n");

  test_ebadf_retry_success();
  printf("\n");
  test_ebadf_retry_fails();
  printf("\n");
  test_normal_path();
  printf("\n");
  test_cache_hit();
  printf("\n");
  test_write_path();

  printf("\n=== Results ============================\n");
  printf("Total:  %d\n", g_passed + g_failed);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("========================================\n");
  return g_failed == 0 ? 0 : 1;
}
