/*
 * MemDBG - Test the PS5 PAL memory fallback chain (mdbg_copyout/copyin,
 * PTWALK, DMAP, PS5 regions) using mocked PS5 SDK functions.
 *
 * Compiles pal_memory_console.c on host by defining MEMDBG_PAL_CONSOLE=1
 * and MEMDBG_PAL_PS5=1 and providing stub <ps5/kernel.h> and <ps5/mdbg.h>
 * headers that #define every SDK symbol to a mock_* name.
 *
 * The mock functions track call counts and return configurable errors so
 * each fallback level can be exercised independently.
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
 *  Mock state (read/written by the mock functions below, inspected by
 *  the test assertions)
 * =================================================================== */

static int  g_mock_copyout_count        = 0;
static int  g_mock_copyin_count         = 0;  /* tracks mdbg_copyin calls */
static int  g_mock_ptw_read_count       = 0;
static int  g_mock_ptw_write_count      = 0;
static int  g_mock_ptw_aux_count        = 0;
static int  g_mock_ptw_avail_count      = 0;
static int  g_mock_ext_begin_count      = 0;
static int  g_mock_ext_end_count        = 0;
static int  g_mock_protect_count        = 0;
static int  g_mock_fw_version_count     = 0;
static int  g_mock_mprotect_count       = 0;
static int  g_mock_process_maps_count   = 0;

/* Configurable return values (set before each test case) */
static int  g_mock_copyout_ret          = 0;   /* 0 = success */
static int  g_mock_copyout_errno        = 0;
static int  g_mock_copyin_ret           = 0;   /* used by mock_mdbg_copyin */
static int  g_mock_copyin_errno         = 0;
static int  g_mock_ptw_available        = 1;   /* ptw_is_available() */
static int  g_mock_ptw_aux_contains     = 0;   /* ptw_aux_contains() */
static int  g_mock_ptw_read_ret         = 0;   /* 0 = success */
static int  g_mock_ptw_write_ret        = 0;   /* 0 = success */
static uint32_t g_mock_fw_version       = 0x08400000U; /* >= 8.40 → DMAP */
static int  g_mock_vmem_prot            = 7;   /* RWX */
static int  g_mock_vmem_prot_errno      = 0;
static int  g_mock_set_vmem_ret         = 0;
static int  g_mock_set_vmem_errno       = 0;
static int  g_mock_mprotect_ret         = 0;
static int  g_mock_process_maps_ret     = 0;   /* 0 = MEMDBG_OK */
static int  g_mock_ext_begin_ret        = 0;   /* 0 = success */

/* Copyout output buffer (filled by mock) */
static uint8_t g_mock_copyout_data[256];
static size_t  g_mock_copyout_data_len  = 0;

/* ===================================================================
 *  Mock function definitions (must be defined before the #include of
 *  the production source because the stub <ps5/kernel.h> #define-s
 *  redirect to these identifiers).
 *
 *  The ps5/kernel.h stub is found via -Itests/include and #define-s:
 *    mdbg_copyout              → mock_mdbg_copyout
 *    mdbg_copyin               → mock_mdbg_copyin
 *    kernel_get_fw_version     → mock_kernel_get_fw_version
 *    kernel_get_vmem_protection → mock_kernel_get_vmem_protection
 *    kernel_set_vmem_protection → mock_kernel_set_vmem_protection
 *    kernel_mprotect            → mock_kernel_mprotect
 *    memdbg_kernel_external_begin → mock_memdbg_kernel_external_begin
 *    memdbg_kernel_external_end → mock_memdbg_kernel_external_end
 *    kernel_get_proc            → mock_kernel_get_proc
 *    kernel_setlong             → mock_kernel_setlong
 *    kernel_getlong             → mock_kernel_getlong
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

uint32_t mock_kernel_get_fw_version(void) {
  ++g_mock_fw_version_count;
  return g_mock_fw_version;
}

int mock_kernel_get_vmem_protection(pid_t pid, intptr_t address,
                                    size_t length) {
  (void)pid;
  (void)address;
  (void)length;
  ++g_mock_protect_count;
  if (g_mock_vmem_prot_errno != 0) {
    errno = g_mock_vmem_prot_errno;
    return -1;
  }
  return g_mock_vmem_prot;
}

int mock_kernel_set_vmem_protection(pid_t pid, intptr_t address,
                                    size_t length, int protection) {
  (void)pid;
  (void)address;
  (void)length;
  (void)protection;
  ++g_mock_protect_count;
  if (g_mock_set_vmem_ret != 0) {
    errno = g_mock_set_vmem_errno;
    return -1;
  }
  return 0;
}

int mock_kernel_mprotect(pid_t pid, intptr_t address,
                         size_t length, int prot) {
  (void)pid;
  (void)address;
  (void)length;
  (void)prot;
  ++g_mock_mprotect_count;
  return g_mock_mprotect_ret;
}

int mock_memdbg_kernel_external_begin(void) {
  ++g_mock_ext_begin_count;
  return g_mock_ext_begin_ret;
}

void mock_memdbg_kernel_external_end(void) {
  ++g_mock_ext_end_count;
}

intptr_t mock_kernel_get_proc(pid_t pid) {
  (void)pid;
  return (intptr_t)0xDEADBEEF;
}

int mock_kernel_setlong(intptr_t addr, uint64_t val) {
  (void)addr;
  (void)val;
  return 0;
}

uint64_t mock_kernel_getlong(intptr_t addr) {
  (void)addr;
  return 0;
}

/* ---- ptw_* mocks ---- */
/* These #define-s must come before the #include because
 * pal_memory_console.c calls ptw_* functions after #include-ing
 * the pt_walker.h header. */
#define ptw_is_available mock_ptw_is_available
#define ptw_aux_contains mock_ptw_aux_contains
#define ptw_read         mock_ptw_read
#define ptw_write        mock_ptw_write

static int mock_ptw_is_available(void) {
  ++g_mock_ptw_avail_count;
  return g_mock_ptw_available;
}

static int mock_ptw_aux_contains(uint32_t pid, uint64_t addr, uint64_t len) {
  (void)pid;
  (void)addr;
  (void)len;
  ++g_mock_ptw_aux_count;
  return g_mock_ptw_aux_contains;
}

static int mock_ptw_read(uint32_t pid, uint64_t addr,
                         uint64_t length, void *dst) {
  (void)pid;
  (void)addr;
  (void)length;
  ++g_mock_ptw_read_count;
  if (g_mock_ptw_read_ret != 0) return g_mock_ptw_read_ret;
  if (dst != NULL && length > 0)
    memset(dst, 0xBB, (size_t)(length < 256 ? length : 256));
  return 0;
}

static int mock_ptw_write(uint32_t pid, uint64_t addr,
                          uint64_t length, const void *src) {
  (void)pid;
  (void)addr;
  (void)length;
  (void)src;
  ++g_mock_ptw_write_count;
  return g_mock_ptw_write_ret;
}

/* ---- pal_process_maps mocks — #define before include, body after ---- */
/* The #define renames the extern declarations in pal_process.h to
 * mock_* names. The actual definitions live after the #include where
 * the types (pal_map_list_t, memdbg_status_t) are available. */
#define pal_process_maps      mock_pal_process_maps
#define pal_process_maps_free mock_pal_process_maps_free

/* ===================================================================
 *  Include the implementation under test
 * =================================================================== */

#include "../src/pal/pal_memory_console.c"

/* ===================================================================
 *  Mock definitions that depend on types from included headers
 * =================================================================== */

memdbg_status_t mock_pal_process_maps(int pid, pal_map_list_t *out) {
  (void)pid;
  ++g_mock_process_maps_count;
  if (g_mock_process_maps_ret != 0) {
    errno = EIO;
    return MEMDBG_ERR_IO;
  }
  /* Return a single writable region covering the entire address space. */
  pal_map_list_t *list = (pal_map_list_t *)out;
  list->count = 1U;
  list->capacity = 1U;
  list->entries = (pal_map_entry_t *)calloc(1, sizeof(pal_map_entry_t));
  if (list->entries != NULL) {
    list->entries[0].start      = 0x1000ULL;
    list->entries[0].end        = 0x7FFFFFFFFFFFULL;
    list->entries[0].protection = 7U; /* RWX */
  }
  return MEMDBG_OK;
}

void mock_pal_process_maps_free(pal_map_list_t *list) {
  if (list != NULL) {
    free(list->entries);
    list->entries = NULL;
    list->count = 0U;
  }
}

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
  g_mock_ptw_read_count      = 0;
  g_mock_ptw_write_count     = 0;
  g_mock_ptw_aux_count       = 0;
  g_mock_ptw_avail_count     = 0;
  g_mock_ext_begin_count     = 0;
  g_mock_ext_end_count       = 0;
  g_mock_protect_count       = 0;
  g_mock_fw_version_count    = 0;
  g_mock_mprotect_count      = 0;
  g_mock_process_maps_count  = 0;

  g_mock_copyout_ret         = 0;
  g_mock_copyout_errno       = 0;
  g_mock_copyin_ret          = 0;
  g_mock_copyin_errno        = 0;
  g_mock_ptw_available       = 1;
  g_mock_ptw_aux_contains    = 0;
  g_mock_ptw_read_ret        = 0;
  g_mock_ptw_write_ret       = 0;
  g_mock_fw_version          = 0x08400000U;
  g_mock_vmem_prot           = 7;
  g_mock_vmem_prot_errno     = 0;
  g_mock_set_vmem_ret        = 0;
  g_mock_set_vmem_errno      = 0;
  g_mock_mprotect_ret        = 0;
  g_mock_process_maps_ret    = 0;
  g_mock_ext_begin_ret       = 0;

  g_mock_copyout_data_len    = 0;

  /* Reset atomic s_fw_needs_dmap to -1 so console_fw_needs_dmap() re-evaluates */
  atomic_store_explicit(&s_fw_needs_dmap, -1, memory_order_relaxed);

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

  TEST("read direct: status OK", st == MEMDBG_OK);
  TEST("read direct: read_out == 8", read_out == 8);
  TEST("read direct: copyout called once", g_mock_copyout_count == 1);
  TEST("read direct: ptw_read not called", g_mock_ptw_read_count == 0);
  TEST("read direct: data matches", buf[0] == 0xAA && buf[7] == 0xAA);
}

static void test_read_ptw_aux_hit(void) {
  reset_mocks();
  g_mock_ptw_aux_contains = 1;

  uint8_t buf[8];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(100, 0x1000, buf, 8, &read_out);

  TEST("read PTWALK aux: status OK", st == MEMDBG_OK);
  TEST("read PTWALK aux: read_out == 8", read_out == 8);
  TEST("read PTWALK aux: ptw_aux_contains called", g_mock_ptw_aux_count == 1);
  TEST("read PTWALK aux: ptw_read called", g_mock_ptw_read_count == 1);
  TEST("read PTWALK aux: copyout NOT called (bypassed)", g_mock_copyout_count == 0);
  TEST("read PTWALK aux: ptw_data matches", buf[0] == 0xBB && buf[7] == 0xBB);
}

static void test_read_eacces_fallback(void) {
  reset_mocks();
  g_mock_copyout_ret   = -1;
  g_mock_copyout_errno = EACCES;
  g_mock_ptw_read_ret  = 0;  /* PTWALK succeeds */

  uint8_t buf[8];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(100, 0x1000, buf, 8, &read_out);

  TEST("read EACCES fallback: status OK", st == MEMDBG_OK);
  TEST("read EACCES fallback: read_out == 8", read_out == 8);
  TEST("read EACCES fallback: copyout called once", g_mock_copyout_count == 1);
  TEST("read EACCES fallback: ptw_read called (fallback)", g_mock_ptw_read_count == 1);
}

static void test_read_eacces_both_fail(void) {
  reset_mocks();
  g_mock_copyout_ret   = -1;
  g_mock_copyout_errno = EACCES;
  g_mock_ptw_read_ret  = -1;  /* PTWALK also fails */

  uint8_t buf[8];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(100, 0x1000, buf, 8, &read_out);

  TEST("read EACCES both fail: status is error", st != MEMDBG_OK);
  TEST("read EACCES both fail: copyout called", g_mock_copyout_count == 1);
  TEST("read EACCES both fail: ptw_read called (attempted)", g_mock_ptw_read_count == 1);
  TEST("read EACCES both fail: read_out == 0", read_out == 0);
}

static void test_read_efault_no_fallback(void) {
  reset_mocks();
  g_mock_copyout_ret   = -1;
  g_mock_copyout_errno = EFAULT;
  g_mock_ptw_read_ret  = 0;   /* even if PTWALK would succeed, EFAULT skips it */

  uint8_t buf[8];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(100, 0x1000, buf, 8, &read_out);

  TEST("read EFAULT: no fallback attempted", st != MEMDBG_OK);
  TEST("read EFAULT: copyout called once", g_mock_copyout_count == 1);
  TEST("read EFAULT: ptw_read NOT called (skip logic)", g_mock_ptw_read_count == 0);
}

static void test_read_invalid_pid(void) {
  reset_mocks();
  uint8_t buf[8];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(1, 0x1000, buf, 8, &read_out);
  TEST("read pid==1: permission denied", st == MEMDBG_ERR_PERMISSION);
  TEST("read pid==1: copyout not called", g_mock_copyout_count == 0);
}

static void test_read_zero_length(void) {
  reset_mocks();
  uint8_t buf[8];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(100, 0x1000, buf, 0, &read_out);
  TEST("read length==0: OK (no-op)", st == MEMDBG_OK);
}

/* ===================================================================
 *  Test: pal_memory_write
 * =================================================================== */

static void test_write_dmap_success(void) {
  reset_mocks();
  g_mock_fw_version   = 0x08400000U;  /* >= 8.40 -> DMAP */
  g_mock_ptw_write_ret = 0;

  const uint8_t data[] = {0x11, 0x22, 0x33, 0x44};
  size_t written = 0;
  memdbg_status_t st = pal_memory_write(100, 0x1000, data, 4, &written);

  TEST("write DMAP success: status OK", st == MEMDBG_OK);
  TEST("write DMAP success: written == 4", written == 4);
  TEST("write DMAP success: ptw_write called", g_mock_ptw_write_count == 1);
  /* Cache coherency: console_mdbg_copyin_raw called after ptw_write.
   * This internally calls mdbg_copyin (mocked). */
  TEST("write DMAP success: copyin called (icache flush)", g_mock_copyin_count == 1);
}

static void test_write_no_dmap_fallback(void) {
  reset_mocks();
  g_mock_fw_version   = 0x08000000U;  /* < 8.40 -> no DMAP */
  g_mock_copyin_ret   = 0;            /* console_mdbg_copyin succeeds */

  const uint8_t data[] = {0x11, 0x22};
  size_t written = 0;
  memdbg_status_t st = pal_memory_write(100, 0x1000, data, 2, &written);

  TEST("write no-DMAP: status OK", st == MEMDBG_OK);
  TEST("write no-DMAP: written == 2", written == 2);
  TEST("write no-DMAP: copyin called (not DMAP)", g_mock_copyin_count >= 1);
  TEST("write no-DMAP: ptw_write not called", g_mock_ptw_write_count == 0);
}

static void test_write_dmap_ptw_fails_fallback(void) {
  reset_mocks();
  g_mock_fw_version   = 0x08400000U;  /* >= 8.40 */
  g_mock_ptw_write_ret = -1;          /* ptw_write fails -> falls through */
  g_mock_copyin_ret   = 0;            /* console_mdbg_copyin succeeds */

  const uint8_t data[] = {0x11, 0x22};
  size_t written = 0;
  memdbg_status_t st = pal_memory_write(100, 0x1000, data, 2, &written);

  TEST("write DMAP fail fallback: status OK (copyin worked)", st == MEMDBG_OK);
  TEST("write DMAP fail fallback: ptw_write called", g_mock_ptw_write_count == 1);
  TEST("write DMAP fail fallback: copyin called (fallback)", g_mock_copyin_count >= 1);
}

/* ===================================================================
 *  Test: pal_memory_batch_item
 * =================================================================== */

static void test_batch_read_direct(void) {
  reset_mocks();
  g_mock_copyout_data_len = 4;
  memset(g_mock_copyout_data, 0xCC, 4);

  pal_memory_batch_t *b = pal_memory_batch_begin(100);
  TEST("batch read begin: handle non-NULL", b != NULL);

  uint8_t buf[4];
  size_t r = pal_memory_batch_item(b, 0x1000, buf, 4);
  pal_memory_batch_end(b);

  TEST("batch read direct: returned 4 bytes", r == 4);
  TEST("batch read direct: copyout called", g_mock_copyout_count == 1);
  TEST("batch read direct: ptw aux checked once", g_mock_ptw_aux_count == 1);
}

static void test_batch_read_ptw_aux(void) {
  reset_mocks();
  g_mock_ptw_aux_contains = 1;  /* PTWALK aux region */

  pal_memory_batch_t *b = pal_memory_batch_begin(100);
  TEST("batch read aux begin: non-NULL", b != NULL);

  uint8_t buf[4];
  size_t r = pal_memory_batch_item(b, 0x1000, buf, 4);
  pal_memory_batch_end(b);

  TEST("batch read aux: returned 4 bytes", r == 4);
  TEST("batch read aux: ptw aux checked", g_mock_ptw_aux_count >= 1);
  TEST("batch read aux: ptw_read called", g_mock_ptw_read_count == 1);
  TEST("batch read aux: copyout NOT called", g_mock_copyout_count == 0);
}

/* ===================================================================
 *  Test: pal_memory_batch_write_item
 * =================================================================== */

static void test_batch_write_dmap(void) {
  reset_mocks();
  g_mock_fw_version   = 0x08400000U;
  g_mock_ptw_write_ret = 0;

  pal_memory_batch_write_t *b = pal_memory_batch_write_begin(100);
  TEST("batch write begin: non-NULL", b != NULL);

  const uint8_t data[] = {0xDD, 0xEE};
  size_t r = pal_memory_batch_write_item(b, 0x1000, data, 2);
  pal_memory_batch_write_end(b);

  TEST("batch write DMAP: returned 2 bytes", r == 2);
  TEST("batch write DMAP: ptw_write called", g_mock_ptw_write_count == 1);
  /* Cache coherency: console_mdbg_copyin_raw called after ptw_write.
   * This internally calls mdbg_copyin (mocked). */
  TEST("batch write DMAP: copyin called (icache flush)", g_mock_copyin_count == 1);
}

static void test_batch_write_no_dmap(void) {
  reset_mocks();
  g_mock_fw_version   = 0x08000000U;  /* < 8.40 */
  g_mock_copyin_ret   = 0;

  pal_memory_batch_write_t *b = pal_memory_batch_write_begin(100);
  TEST("batch write no-DMAP begin: non-NULL", b != NULL);

  const uint8_t data[] = {0xDD, 0xEE};
  size_t r = pal_memory_batch_write_item(b, 0x1000, data, 2);
  pal_memory_batch_write_end(b);

  TEST("batch write no-DMAP: returned 2 bytes", r == 2);
  TEST("batch write no-DMAP: copyin called", g_mock_copyin_count >= 1);
  TEST("batch write no-DMAP: ptw_write NOT called", g_mock_ptw_write_count == 0);
}

/* ===================================================================
 *  Test: console_fw_needs_dmap
 * =================================================================== */

static void test_fw_below_dmap(void) {
  reset_mocks();
  g_mock_fw_version = 0x08000000U;  /* FW 8.00 */
  /* s_fw_needs_dmap was reset to -1 by reset_mocks */
  int needs = console_fw_needs_dmap();
  TEST("FW 8.00: does NOT need DMAP", needs == 0);
  TEST("FW 8.00: fw version queried", g_mock_fw_version_count == 1);
}

static void test_fw_at_dmap(void) {
  reset_mocks();
  g_mock_fw_version = 0x08400000U;  /* FW 8.40 */
  int needs = console_fw_needs_dmap();
  TEST("FW 8.40: needs DMAP", needs == 1);
  TEST("FW 8.40: fw version queried", g_mock_fw_version_count == 1);
}

static void test_fw_cached(void) {
  reset_mocks();
  g_mock_fw_version = 0x08400000U;
  /* First call: computes and caches */
  int first = console_fw_needs_dmap();
  g_mock_fw_version_count = 0;
  /* Second call: should use cache */
  int second = console_fw_needs_dmap();
  TEST("FW cached: first call correct", first == 1);
  TEST("FW cached: second call correct", second == 1);
  TEST("FW cached: fw version NOT re-queried", g_mock_fw_version_count == 0);
}

/* ===================================================================
 *  Test: Invalid PID edge cases
 * =================================================================== */

static void test_batch_begin_invalid_pid(void) {
  reset_mocks();
  pal_memory_batch_t *b = pal_memory_batch_begin(0);
  TEST("batch begin pid=0: NULL", b == NULL);

  pal_memory_batch_write_t *bw = pal_memory_batch_write_begin(0);
  TEST("batch write begin pid=0: NULL", bw == NULL);

  uint8_t buf[4];
  size_t read_out = 0;
  memdbg_status_t st = pal_memory_read(0, 0x1000, buf, 4, &read_out);
  TEST("read pid=0: error", st != MEMDBG_OK);
}

/* ===================================================================
 *  Main
 * =================================================================== */

int main(void) {
  printf("=== PAL Memory Console Fallback Tests ===\n");
  printf("(uses mocks for ps5/kernel.h, ps5/mdbg.h, pt_walker.h)\n\n");

  printf("--- pal_memory_read ---\n");
  test_read_direct();
  test_read_ptw_aux_hit();
  test_read_eacces_fallback();
  test_read_eacces_both_fail();
  test_read_efault_no_fallback();
  test_read_invalid_pid();
  test_read_zero_length();
  printf("\n");

  printf("--- pal_memory_write ---\n");
  test_write_dmap_success();
  test_write_no_dmap_fallback();
  test_write_dmap_ptw_fails_fallback();
  printf("\n");

  printf("--- pal_memory_batch_item ---\n");
  test_batch_read_direct();
  test_batch_read_ptw_aux();
  printf("\n");

  printf("--- pal_memory_batch_write_item ---\n");
  test_batch_write_dmap();
  test_batch_write_no_dmap();
  printf("\n");

  printf("--- console_fw_needs_dmap ---\n");
  test_fw_below_dmap();
  test_fw_at_dmap();
  test_fw_cached();
  printf("\n");

  printf("--- edge cases ---\n");
  test_batch_begin_invalid_pid();
  printf("\n");

  printf("=== Results ============================\n");
  printf("Total:  %d\n", g_passed + g_failed);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("========================================\n");
  return g_failed == 0 ? 0 : 1;
}
