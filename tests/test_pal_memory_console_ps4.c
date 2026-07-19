/*
 * MemDBG - Test the PS4 PAL memory backend (mdbg_copyout/copyin only,
 * no PTWALK, DMAP, or PS5-specific regions walk) using mocked PS4 SDK.
 *
 * Compiles pal_memory_console.c on host by defining MEMDBG_PAL_CONSOLE=1
 * and MEMDBG_PAL_PS4=1 and providing stub <ps4/mdbg.h> (via -Itests/include)
 * that #define-s every SDK symbol to a mock_* name.
 *
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* ===================================================================
 *  Mock state
 * =================================================================== */

static int  g_mock_copyout_count        = 0;
static int  g_mock_copyin_count         = 0;

/* Configurable return values (set before each test case) */
static int  g_mock_copyout_ret          = 0;   /* 0 = success */
static int  g_mock_copyout_errno        = 0;
static int  g_mock_copyin_ret           = 0;   /* 0 = success */
static int  g_mock_copyin_errno         = 0;

/* Copyout output buffer (filled by mock) */
static uint8_t g_mock_copyout_data[256];
static size_t  g_mock_copyout_data_len  = 0;

/* ===================================================================
 *  Mock function definitions
 *
 *  The ps4/mdbg.h stub #define-s:
 *    mdbg_copyout  -> mock_mdbg_copyout
 *    mdbg_copyin   -> mock_mdbg_copyin
 * =================================================================== */

int mock_mdbg_copyout(pid_t pid, intptr_t address,
                      void *buffer, size_t length) {
  (void)pid;
  (void)address;
  ++g_mock_copyout_count;
  if (g_mock_copyout_ret != 0) {
    errno = g_mock_copyout_errno;
    return g_mock_copyout_ret;
  }
  size_t cp = length < g_mock_copyout_data_len ? length : g_mock_copyout_data_len;
  if (cp > 0) memcpy(buffer, g_mock_copyout_data, cp);
  return 0;
}

int mock_mdbg_copyin(pid_t pid, const void *buffer,
                     intptr_t address, size_t length) {
  ++g_mock_copyin_count;
  (void)pid;
  (void)buffer;
  (void)address;
  (void)length;
  if (g_mock_copyin_ret != 0) {
    errno = g_mock_copyin_errno;
    return g_mock_copyin_ret;
  }
  return 0;
}

/* ===================================================================
 *  Include the implementation under test
 *
 *  pal_memory_internal.h checks MEMDBG_PAL_PS4 and includes <ps4/mdbg.h>,
 *  which is provided by the tests/include/ps4/mdbg.h stub (via -Itests/include).
 * =================================================================== */

#include "../src/pal/pal_memory_console.c"

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
  g_mock_copyout_count       = 0;
  g_mock_copyin_count        = 0;

  g_mock_copyout_ret         = 0;
  g_mock_copyout_errno       = 0;
  g_mock_copyin_ret          = 0;
  g_mock_copyin_errno        = 0;

  g_mock_copyout_data_len    = 0;

  errno = 0;
}

/* ===================================================================
 *  Test: pal_memory_read
 * =================================================================== */

static void test_read_direct(void) {
  reset_mocks();
  g_mock_copyout_data_len = 8;
  memset(g_mock_copyout_data, 0xAA, 8);

  uint8_t buf[8];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(100, 0x1000, buf, 8, &read_out);

  TEST("PS4 read direct: status OK", st == MEMDBG_OK);
  TEST("PS4 read direct: read_out == 8", read_out == 8);
  TEST("PS4 read direct: copyout called once", g_mock_copyout_count == 1);
  TEST("PS4 read direct: data matches", buf[0] == 0xAA && buf[7] == 0xAA);
}

static void test_read_eacces_no_fallback(void) {
  reset_mocks();
  g_mock_copyout_ret   = -1;
  g_mock_copyout_errno = EACCES;

  uint8_t buf[8];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(100, 0x1000, buf, 8, &read_out);

  /* PS4 has no PTWALK fallback — EACCES from mdbg_copyout returns error */
  TEST("PS4 read EACCES: status is error", st != MEMDBG_OK);
  TEST("PS4 read EACCES: copyout called", g_mock_copyout_count == 1);
  TEST("PS4 read EACCES: read_out == 0", read_out == 0);
}

static void test_read_efault_no_fallback(void) {
  reset_mocks();
  g_mock_copyout_ret   = -1;
  g_mock_copyout_errno = EFAULT;

  uint8_t buf[8];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(100, 0x1000, buf, 8, &read_out);

  TEST("PS4 read EFAULT: status is error", st != MEMDBG_OK);
  TEST("PS4 read EFAULT: copyout called", g_mock_copyout_count == 1);
}

static void test_read_invalid_pid(void) {
  reset_mocks();
  uint8_t buf[8];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(1, 0x1000, buf, 8, &read_out);
  TEST("PS4 read pid==1: permission denied", st == MEMDBG_ERR_PERMISSION);
  TEST("PS4 read pid==1: copyout not called", g_mock_copyout_count == 0);
}

static void test_read_zero_length(void) {
  reset_mocks();
  uint8_t buf[8];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(100, 0x1000, buf, 0, &read_out);
  TEST("PS4 read length==0: OK (no-op)", st == MEMDBG_OK);
}

/* ===================================================================
 *  Test: pal_memory_write
 * =================================================================== */

static void test_write_direct(void) {
  reset_mocks();
  g_mock_copyin_ret = 0;  /* success */

  const uint8_t data[] = {0x11, 0x22, 0x33, 0x44};
  size_t written = 0;
  memdbg_status_t st = pal_memory_write(100, 0x1000, data, 4, &written);

  TEST("PS4 write direct: status OK", st == MEMDBG_OK);
  TEST("PS4 write direct: written == 4", written == 4);
  TEST("PS4 write direct: copyin called", g_mock_copyin_count == 1);
}

static void test_write_eacces_no_fallback(void) {
  reset_mocks();
  g_mock_copyin_ret   = -1;
  g_mock_copyin_errno = EACCES;

  const uint8_t data[] = {0x11, 0x22};
  size_t written = 0;
  memdbg_status_t st = pal_memory_write(100, 0x1000, data, 2, &written);

  /* PS4 has no PTWALK or DMAP fallback — EACCES returns error */
  TEST("PS4 write EACCES: status is error", st != MEMDBG_OK);
  TEST("PS4 write EACCES: copyin called", g_mock_copyin_count == 1);
  TEST("PS4 write EACCES: written == 0", written == 0);
}

static void test_write_invalid_pid(void) {
  reset_mocks();
  const uint8_t data[] = {0x11, 0x22};
  size_t written = 0;
  memdbg_status_t st = pal_memory_write(0, 0x1000, data, 2, &written);
  TEST("PS4 write pid==0: error", st != MEMDBG_OK);
  TEST("PS4 write pid==0: copyin not called", g_mock_copyin_count == 0);
}

static void test_write_zero_length(void) {
  reset_mocks();
  const uint8_t data[] = {0x11};
  size_t written = 0;
  memdbg_status_t st = pal_memory_write(100, 0x1000, data, 0, &written);
  TEST("PS4 write length==0: OK (no-op)", st == MEMDBG_OK);
}

/* ===================================================================
 *  Test: pal_memory_batch_item
 * =================================================================== */

static void test_batch_read_direct(void) {
  reset_mocks();
  g_mock_copyout_data_len = 4;
  memset(g_mock_copyout_data, 0xCC, 4);

  pal_memory_batch_t *b = pal_memory_batch_begin(100);
  TEST("PS4 batch begin: non-NULL", b != NULL);

  uint8_t buf[4];
  size_t r = pal_memory_batch_item(b, 0x1000, buf, 4);
  pal_memory_batch_end(b);

  TEST("PS4 batch read: returned 4 bytes", r == 4);
  TEST("PS4 batch read: copyout called", g_mock_copyout_count == 1);
}

/* ===================================================================
 *  Test: pal_memory_batch_write_item
 * =================================================================== */

static void test_batch_write_direct(void) {
  reset_mocks();
  g_mock_copyin_ret = 0;

  pal_memory_batch_write_t *b = pal_memory_batch_write_begin(100);
  TEST("PS4 batch write begin: non-NULL", b != NULL);

  const uint8_t data[] = {0xDD, 0xEE};
  size_t r = pal_memory_batch_write_item(b, 0x1000, data, 2);
  pal_memory_batch_write_end(b);

  TEST("PS4 batch write: returned 2 bytes", r == 2);
  TEST("PS4 batch write: copyin called", g_mock_copyin_count == 1);
}

/* ===================================================================
 *  Test: Unsupported operations (PS4 returns ERR_UNSUPPORTED)
 * =================================================================== */

static void test_protect_unsupported(void) {
  reset_mocks();
  uint32_t old_prot = 0;
  memdbg_status_t st = pal_memory_protect(100, 0x1000, 4096, 7, &old_prot);
  TEST("PS4 protect: unsupported", st == MEMDBG_ERR_UNSUPPORTED);
}

static void test_alloc_unsupported(void) {
  reset_mocks();
  uint64_t addr = 0;
  memdbg_status_t st = pal_memory_alloc(100, 0, 4096, 7, 0, &addr);
  TEST("PS4 alloc: unsupported", st == MEMDBG_ERR_UNSUPPORTED);
  TEST("PS4 alloc: addr == 0", addr == 0);
}

static void test_free_unsupported(void) {
  reset_mocks();
  memdbg_status_t st = pal_memory_free(100, 0x1000, 4096);
  TEST("PS4 free: unsupported", st == MEMDBG_ERR_UNSUPPORTED);
}

/* ===================================================================
 *  Main
 * =================================================================== */

int main(void) {
  printf("=== PS4 PAL Memory Console Tests ===\n");
  printf("(uses mocks for ps4/mdbg.h — no PTWALK, DMAP, or PS5-specific paths)\\n\\n");

  printf("--- pal_memory_read ---\n");
  test_read_direct();
  test_read_eacces_no_fallback();
  test_read_efault_no_fallback();
  test_read_invalid_pid();
  test_read_zero_length();
  printf("\n");

  printf("--- pal_memory_write ---\n");
  test_write_direct();
  test_write_eacces_no_fallback();
  test_write_invalid_pid();
  test_write_zero_length();
  printf("\n");

  printf("--- pal_memory_batch_item ---\n");
  test_batch_read_direct();
  printf("\n");

  printf("--- pal_memory_batch_write_item ---\n");
  test_batch_write_direct();
  printf("\n");

  printf("--- PS4 unsupported operations ---\n");
  test_protect_unsupported();
  test_alloc_unsupported();
  test_free_unsupported();
  printf("\n");

  printf("=== Results ============================\n");
  printf("Total:  %d\n", g_passed + g_failed);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("========================================\n");
  return g_failed == 0 ? 0 : 1;
}
