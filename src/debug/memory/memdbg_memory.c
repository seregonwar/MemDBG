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

#include "memdbg/core/memdbg_log.h"
#include "memdbg/pal/pal_memory.h"

#include <stdatomic.h>

// Telemetry

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

// Single read

memdbg_status_t memdbg_memory_read(int pid, uint64_t address, void *buffer,
                                   size_t length, size_t *read_out) {
  size_t bytes_read = 0U;
  memdbg_status_t st;

  if (pid <= 0 || (buffer == NULL && length != 0U)) return MEMDBG_ERR_PARAM;
  if (read_out != NULL) *read_out = 0U;
  if (length == 0U) return MEMDBG_OK;

  st = pal_memory_read(pid, address, buffer, length, &bytes_read);

  if (read_out != NULL) *read_out = bytes_read;
  if (st == MEMDBG_OK) bump_read((uint64_t)bytes_read);
  return st;
}

// Single write

memdbg_status_t memdbg_memory_write(int pid, uint64_t address,
                                    const void *buffer, size_t length,
                                    size_t *written_out) {
  size_t bytes_written = 0U;
  memdbg_status_t st;

  if (pid <= 0 || (buffer == NULL && length != 0U)) return MEMDBG_ERR_PARAM;
  if (written_out != NULL) *written_out = 0U;
  if (length == 0U) return MEMDBG_OK;

  st = pal_memory_write(pid, address, buffer, length, &bytes_written);

  if (written_out != NULL) *written_out = bytes_written;
  if (st == MEMDBG_OK) bump_write((uint64_t)bytes_written);
  return st;
}

// Batch read

memdbg_status_t memdbg_memory_batch_read(
    int pid, const memdbg_batch_read_item_t *items, uint32_t count,
    memdbg_batch_read_result_entry_t *results, uint8_t *data_out,
    uint32_t data_capacity, uint32_t *data_used) {
  if (pid <= 0 || items == NULL || results == NULL || data_out == NULL ||
      count == 0U || count > MEMDBG_BATCH_READ_MAX_ITEMS)
    return MEMDBG_ERR_PARAM;
  if (data_used != NULL) *data_used = 0U;

  pal_memory_batch_t *batch = pal_memory_batch_begin(pid);
  if (batch == NULL) {
    return MEMDBG_ERR_UNSUPPORTED;
  }

  uint32_t offset = 0U;
  memdbg_status_t overall = MEMDBG_OK;

  for (uint32_t i = 0U; i < count; ++i) {
    results[i].address = items[i].address;
    results[i].length  = 0U;
    results[i].status  = (uint32_t)MEMDBG_ERR_IO;

    uint32_t len = items[i].length;
    if (len == 0U) { results[i].status = (uint32_t)MEMDBG_OK; continue; }
    /* Validate len against a sane per-item limit before the offset arithmetic to
     * avoid 32-bit wrap when len is near UINT32_MAX. Each item is capped at the
     * well below-4 GiB range MEMDBG_BATCH_READ_MAX_ITEM_BYTES. */
    if (len > MEMDBG_BATCH_READ_MAX_ITEM_BYTES) {
      results[i].status = (uint32_t)MEMDBG_ERR_PARAM;
      overall = MEMDBG_ERR_PARAM;
      continue;
    }
    /* Compute in size_t (>= 32 bit, 64 bit on the supported payloads) so the
     * addition cannot overflow before the capacity comparison. */
    if ((size_t)offset + (size_t)len > (size_t)data_capacity) {
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

// Batch write

memdbg_status_t memdbg_memory_batch_write(
    int pid, const memdbg_batch_write_item_t *items, const uint8_t *data,
    uint32_t count, memdbg_batch_write_result_entry_t *results) {
  if (pid <= 0 || items == NULL || data == NULL || results == NULL ||
      count == 0U || count > MEMDBG_BATCH_WRITE_MAX_ITEMS)
    return MEMDBG_ERR_PARAM;

  pal_memory_batch_write_t *batch = pal_memory_batch_write_begin(pid);
  if (batch == NULL) {
    /* Fallback: individual writes per item */
    memdbg_status_t overall = MEMDBG_OK;
    size_t data_off = 0U;
    for (uint32_t i = 0U; i < count; ++i) {
      results[i].address = items[i].address;
      results[i].written = 0U;
      results[i].status  = (uint32_t)MEMDBG_ERR_IO;
      uint32_t len = items[i].length;
      if (len == 0U) { results[i].status = (uint32_t)MEMDBG_OK; continue; }
      size_t written = 0U;
      memdbg_status_t st = pal_memory_write(pid, items[i].address,
          data + data_off, len, &written);
      results[i].status  = (uint32_t)st;
      results[i].written = (uint32_t)written;
      if (st == MEMDBG_OK) bump_write((uint64_t)written);
      if (st != MEMDBG_OK && overall == MEMDBG_OK) overall = st;
      data_off += len;
    }
    return overall;
  }

  /* Batch path: single open fd for all items */
  memdbg_status_t overall = MEMDBG_OK;
  size_t data_off = 0U;
  for (uint32_t i = 0U; i < count; ++i) {
    results[i].address = items[i].address;
    results[i].written = 0U;
    results[i].status  = (uint32_t)MEMDBG_ERR_IO;
    uint32_t len = items[i].length;
    if (len == 0U) { results[i].status = (uint32_t)MEMDBG_OK; continue; }
    size_t n = pal_memory_batch_write_item(batch, items[i].address,
                                           data + data_off, len);
    bump_write((uint64_t)n);
    results[i].written = (uint32_t)n;
    results[i].status  = (n == (size_t)len) ? (uint32_t)MEMDBG_OK : (uint32_t)MEMDBG_ERR_IO;
    if (n != (size_t)len && overall == MEMDBG_OK) overall = MEMDBG_ERR_IO;
    data_off += len;
  }

  pal_memory_batch_write_end(batch);
  return overall;
}
