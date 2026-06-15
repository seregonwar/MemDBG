/*
 * memDBG - Memory debugger payload for jailbroken consoles.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This module is a thin wrapper around the PAL memory API.
 * Platform-specific implementations live in src/pal/pal_memory.c.
 * This file handles only: telemetry counters, batch read orchestration.
 */

#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/pal/pal_memory.h"

#include <stdatomic.h>
#include <string.h>

/* ---- Telemetry ---- */

static atomic_ullong g_total_bytes_read    = 0;
static atomic_ullong g_total_bytes_written = 0;
static atomic_ullong g_total_read_calls    = 0;
static atomic_ullong g_total_write_calls   = 0;

void memdbg_memory_telemetry(memdbg_telemetry_response_t *out) {
  if (out == NULL) return;
  out->total_bytes_read    = atomic_load_explicit(&g_total_bytes_read,    memory_order_relaxed);
  out->total_bytes_written = atomic_load_explicit(&g_total_bytes_written, memory_order_relaxed);
  out->total_read_calls    = atomic_load_explicit(&g_total_read_calls,    memory_order_relaxed);
  out->total_write_calls   = atomic_load_explicit(&g_total_write_calls,   memory_order_relaxed);
}

static void bump_read(uint64_t bytes) {
  atomic_fetch_add_explicit(&g_total_bytes_read, bytes, memory_order_relaxed);
  atomic_fetch_add_explicit(&g_total_read_calls, 1ULL,  memory_order_relaxed);
}

static void bump_write(uint64_t bytes) {
  atomic_fetch_add_explicit(&g_total_bytes_written, bytes, memory_order_relaxed);
  atomic_fetch_add_explicit(&g_total_write_calls,  1ULL,   memory_order_relaxed);
}

/* ---- Single read ---- */

memdbg_status_t memdbg_memory_read(int pid, uint64_t address, void *buffer,
                                   size_t length, size_t *read_out) {
  if (pid <= 0 || (buffer == NULL && length != 0U)) return MEMDBG_ERR_PARAM;
  if (read_out != NULL) *read_out = 0U;
  if (length == 0U) return MEMDBG_OK;

  memdbg_status_t st = pal_memory_read(pid, address, buffer, length, read_out);
  if (st == MEMDBG_OK && read_out != NULL) bump_read((uint64_t)*read_out);
  return st;
}

/* ---- Single write ---- */

memdbg_status_t memdbg_memory_write(int pid, uint64_t address,
                                    const void *buffer, size_t length,
                                    size_t *written_out) {
  if (pid <= 0 || (buffer == NULL && length != 0U)) return MEMDBG_ERR_PARAM;
  if (written_out != NULL) *written_out = 0U;
  if (length == 0U) return MEMDBG_OK;

  memdbg_status_t st = pal_memory_write(pid, address, buffer, length, written_out);
  if (st == MEMDBG_OK && written_out != NULL) bump_write((uint64_t)*written_out);
  return st;
}

/* ---- Batch read ---- */

memdbg_status_t memdbg_memory_batch_read(
    int pid, const memdbg_batch_read_item_t *items, uint32_t count,
    memdbg_batch_read_result_entry_t *results, uint8_t *data_out,
    uint32_t data_capacity, uint32_t *data_used) {
  if (pid <= 0 || items == NULL || results == NULL || data_out == NULL ||
      count == 0U || count > MEMDBG_BATCH_READ_MAX_ITEMS)
    return MEMDBG_ERR_PARAM;
  if (data_used != NULL) *data_used = 0U;

  pal_memory_batch_t *batch = pal_memory_batch_begin(pid);
  if (batch == NULL) return MEMDBG_ERR_UNSUPPORTED;

  uint32_t offset = 0U;
  memdbg_status_t overall = MEMDBG_OK;

  for (uint32_t i = 0U; i < count; ++i) {
    results[i].address = items[i].address;
    results[i].length  = 0U;
    results[i].status  = (uint32_t)MEMDBG_ERR_IO;

    uint32_t len = items[i].length;
    if (len == 0U) { results[i].status = (uint32_t)MEMDBG_OK; continue; }
    if (offset + len > data_capacity) {
      results[i].status = (uint32_t)MEMDBG_ERR_OVERFLOW;
      overall = MEMDBG_ERR_OVERFLOW;
      continue;
    }

    size_t n = pal_memory_batch_item(batch, items[i].address, data_out + offset, len);
    if (n == 0U) continue;

    bump_read((uint64_t)n);
    results[i].length = (uint32_t)n;
    results[i].status = (uint32_t)MEMDBG_OK;
    offset += (uint32_t)n;
  }

  pal_memory_batch_end(batch);
  if (data_used != NULL) *data_used = offset;
  return overall;
}
