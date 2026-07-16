/*
 * MemDBG - Memory primitive regression tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/pal/pal_memory.h"

#include <stdio.h>
#include <string.h>

static int g_passed = 0;
static int g_failed = 0;
static memdbg_status_t g_write_statuses[4];
static size_t g_write_status_count = 0U;
static size_t g_write_calls = 0U;

#define TEST(name, expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s\n", name);                                            \
    }                                                                          \
  } while (0)

memdbg_status_t pal_memory_read(int pid, uint64_t address, void *buffer,
                                size_t length, size_t *read_out) {
  (void)pid;
  (void)address;
  if (buffer != NULL) memset(buffer, 0, length);
  if (read_out != NULL) *read_out = length;
  return MEMDBG_OK;
}

memdbg_status_t pal_memory_write(int pid, uint64_t address,
                                 const void *buffer, size_t length,
                                 size_t *written_out) {
  (void)pid;
  (void)address;
  (void)buffer;
  const size_t index = g_write_calls++;
  const memdbg_status_t status =
      index < g_write_status_count ? g_write_statuses[index] : MEMDBG_OK;
  if (written_out != NULL)
    *written_out = status == MEMDBG_OK ? length : 0U;
  return status;
}

pal_memory_batch_t *pal_memory_batch_begin(int pid) {
  (void)pid;
  return NULL;
}

size_t pal_memory_batch_item(pal_memory_batch_t *batch, uint64_t address,
                             void *buffer, size_t length) {
  (void)batch;
  (void)address;
  (void)buffer;
  (void)length;
  return 0U;
}

void pal_memory_batch_end(pal_memory_batch_t *batch) { (void)batch; }

pal_memory_batch_write_t *pal_memory_batch_write_begin(int pid) {
  (void)pid;
  return NULL;
}

size_t pal_memory_batch_write_item(pal_memory_batch_write_t *batch,
                                   uint64_t address, const void *buffer,
                                   size_t length) {
  (void)batch;
  (void)address;
  (void)buffer;
  (void)length;
  return 0U;
}

void pal_memory_batch_write_end(pal_memory_batch_write_t *batch) {
  (void)batch;
}

static void reset_writes(void) {
  memset(g_write_statuses, 0, sizeof(g_write_statuses));
  g_write_status_count = 0U;
  g_write_calls = 0U;
}

static void test_single_write_status(void) {
  const uint8_t data[] = {0xaaU, 0xbbU};
  size_t written = 99U;

  reset_writes();
  g_write_statuses[0] = MEMDBG_ERR_PERMISSION;
  g_write_status_count = 1U;

  const memdbg_status_t status =
      memdbg_memory_write(42, 0x1000U, data, sizeof(data), &written);
  TEST("single write preserves permission status",
       status == MEMDBG_ERR_PERMISSION);
  TEST("failed write reports zero bytes", written == 0U);
  TEST("single write uses PAL primitive", g_write_calls == 1U);
}

static void test_batch_fallback_uses_write_primitive(void) {
  const memdbg_batch_write_item_t items[] = {
      {.address = 0x1000U, .length = 1U},
      {.address = 0x2000U, .length = 1U},
  };
  const uint8_t data[] = {0x11U, 0x22U};
  memdbg_batch_write_result_entry_t results[2];

  reset_writes();
  g_write_statuses[0] = MEMDBG_OK;
  g_write_statuses[1] = MEMDBG_ERR_PERMISSION;
  g_write_status_count = 2U;
  memset(results, 0, sizeof(results));

  const memdbg_status_t status =
      memdbg_memory_batch_write(42, items, data, 2U, results);
  TEST("batch fallback returns first exact failure",
       status == MEMDBG_ERR_PERMISSION);
  TEST("batch fallback uses shared PAL write primitive", g_write_calls == 2U);
  TEST("batch success item records bytes",
       results[0].status == (uint32_t)MEMDBG_OK &&
           results[0].written == 1U);
  TEST("batch failure item preserves permission",
       results[1].status == (uint32_t)MEMDBG_ERR_PERMISSION &&
           results[1].written == 0U);
}

int main(void) {
  printf("=== Memory Primitive Tests ===\n");
  test_single_write_status();
  test_batch_fallback_uses_write_primitive();
  printf("\nPassed: %d\nFailed: %d\n", g_passed, g_failed);
  return g_failed == 0 ? 0 : 1;
}
