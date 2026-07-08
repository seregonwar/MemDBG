/*
 * memDBG - Memory read/write/batch protocol handlers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from src/core/daemon/memdbg.c.
 */

#include "daemon_internal.h"

#include "memdbg/core/memdbg.h"
#include "memdbg/debug/memdbg_memory.h"
#include <stdlib.h>
#include <string.h>

/* ---- MEMORY_READ / MEMORY_WRITE ---- */

memdbg_status_t handle_memory_read(int fd, const memdbg_packet_header_t *req,
                                   const memdbg_config_t *cfg, const void *body,
                                   uint32_t body_len) {
  if (body_len != sizeof(memdbg_memory_request_t)) return MEMDBG_ERR_PROTOCOL;
  const memdbg_memory_request_t *read_req = (const memdbg_memory_request_t *)body;
  if (read_req->length > cfg->max_read_bytes) return MEMDBG_ERR_OVERFLOW;

  /* malloc(0) is implementation-defined and may return NULL;
     guard the read call so a zero-length request never dereferences NULL. */
  unsigned char *buffer = NULL;
  size_t read_len = 0U;
  memdbg_status_t status;

  if (read_req->length == 0U) {
    status = MEMDBG_OK;
  } else {
    buffer = (unsigned char *)malloc(read_req->length);
    if (buffer == NULL) return MEMDBG_ERR_NOMEM;
    status = memdbg_memory_read(read_req->pid, read_req->address,
        buffer, read_req->length, &read_len);
  }
  if (status == MEMDBG_OK) {
    if (send_framed_response(fd, req, MEMDBG_OK, buffer, (uint32_t)read_len) != 0)
      status = MEMDBG_ERR_NET;
  }
  free(buffer);
  return status;
}

memdbg_status_t handle_memory_write(int fd, const memdbg_packet_header_t *req,
                                    const memdbg_config_t *cfg, const void *body,
                                    uint32_t body_len) {
  if (body_len < sizeof(memdbg_memory_request_t)) return MEMDBG_ERR_PROTOCOL;
  const memdbg_memory_request_t *write_req = (const memdbg_memory_request_t *)body;
  if (write_req->length > cfg->max_read_bytes ||
      body_len != sizeof(*write_req) + write_req->length)
    return MEMDBG_ERR_PROTOCOL;

  const unsigned char *data = (const unsigned char *)body + sizeof(memdbg_memory_request_t);
  size_t written = 0U;
  memdbg_status_t status = memdbg_memory_write(write_req->pid, write_req->address,
      data, write_req->length, &written);
  if (status != MEMDBG_OK) return status;

  uint32_t written32 = (uint32_t)written;
  return send_response(fd, req, MEMDBG_OK, &written32, sizeof(written32)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- BATCH_READ ---- */

memdbg_status_t handle_batch_read(int fd, const memdbg_packet_header_t *req,
                                  const memdbg_config_t *cfg, const void *body,
                                  uint32_t body_len) {
  memdbg_batch_read_result_entry_t *results;
  uint8_t *data_out;
  uint32_t data_used = 0U;
  memdbg_status_t status;

  if (body_len < sizeof(memdbg_batch_read_request_t)) return MEMDBG_ERR_PROTOCOL;

  const memdbg_batch_read_request_t *batch_req = (const memdbg_batch_read_request_t *)body;
  uint32_t count = batch_req->count;
  if (count == 0U || count > MEMDBG_BATCH_READ_MAX_ITEMS) return MEMDBG_ERR_PARAM;

  size_t items_size = count * sizeof(memdbg_batch_read_item_t);
  size_t results_size = count * sizeof(memdbg_batch_read_result_entry_t);
  if (body_len < sizeof(*batch_req) + items_size) return MEMDBG_ERR_PROTOCOL;

  const memdbg_batch_read_item_t *items =
      (const memdbg_batch_read_item_t *)((const uint8_t *)body + sizeof(*batch_req));

  uint64_t total_data = 0U;
  for (uint32_t i = 0U; i < count; ++i)
    total_data += items[i].length;

  if (total_data > cfg->max_packet_bytes) return MEMDBG_ERR_OVERFLOW;
  if (total_data > UINT32_MAX) return MEMDBG_ERR_OVERFLOW;

  results = (memdbg_batch_read_result_entry_t *)calloc(count, sizeof(*results));
  if (results == NULL) return MEMDBG_ERR_NOMEM;

  data_out = (uint8_t *)malloc(total_data == 0U ? 1U : (size_t)total_data);
  if (data_out == NULL) {
    free(results);
    return MEMDBG_ERR_NOMEM;
  }

  status = memdbg_memory_batch_read(batch_req->pid, items, count,
      results, data_out, (uint32_t)total_data, &data_used);

  if (status == MEMDBG_OK || status == MEMDBG_ERR_OVERFLOW) {
    unsigned char *framed_data = NULL;
    uint32_t framed_len = 0U;
    memdbg_status_t frame_status =
        build_framed_payload(data_out, data_used, &framed_data, &framed_len);
    if (frame_status != MEMDBG_OK) {
      free(data_out);
      free(results);
      return frame_status;
    }

    size_t payload_len = results_size + framed_len;
    unsigned char *payload = (unsigned char *)malloc(payload_len);
    if (payload == NULL) {
      free(framed_data);
      free(data_out);
      free(results);
      return MEMDBG_ERR_NOMEM;
    }

    memcpy(payload, results, results_size);
    memcpy(payload + results_size, framed_data, framed_len);
    int rc = send_response(fd, req, MEMDBG_OK, payload, (uint32_t)payload_len);
    free(payload);
    free(framed_data);
    free(data_out);
    free(results);
    return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  free(data_out);
  free(results);
  return status;
}

/* ---- BATCH_WRITE ---- */

memdbg_status_t handle_batch_write(int fd, const memdbg_packet_header_t *req,
                                   const memdbg_config_t *cfg, const void *body,
                                   uint32_t body_len) {
  if (body_len < sizeof(memdbg_batch_write_request_t)) return MEMDBG_ERR_PROTOCOL;

  const memdbg_batch_write_request_t *batch_req = (const memdbg_batch_write_request_t *)body;
  uint32_t count = batch_req->count;
  if (count == 0U || count > MEMDBG_BATCH_WRITE_MAX_ITEMS) return MEMDBG_ERR_PARAM;

  size_t results_size = count * sizeof(memdbg_batch_write_result_entry_t);

  unsigned char *results_buf = (unsigned char *)calloc(1U, results_size);
  if (results_buf == NULL) return MEMDBG_ERR_NOMEM;

  memdbg_batch_write_result_entry_t *results =
      (memdbg_batch_write_result_entry_t *)results_buf;

  const uint8_t *cursor = (const uint8_t *)body + sizeof(*batch_req);
  const uint8_t *end    = (const uint8_t *)body + body_len;

  memdbg_batch_write_item_t items[MEMDBG_BATCH_WRITE_MAX_ITEMS];
  const uint8_t *data_ptrs[MEMDBG_BATCH_WRITE_MAX_ITEMS];
  uint32_t valid = 0U;
  memdbg_status_t overall = MEMDBG_OK;

  for (uint32_t i = 0U; i < count; ++i) {
    results[i].address = 0U;
    results[i].written = 0U;
    results[i].status  = (uint32_t)MEMDBG_ERR_IO;

    if ((size_t)(end - cursor) < sizeof(memdbg_batch_write_item_t)) {
      results[i].status = (uint32_t)MEMDBG_ERR_PROTOCOL;
      overall = MEMDBG_ERR_PROTOCOL;
      goto _send;
    }

    const memdbg_batch_write_item_t *item = (const memdbg_batch_write_item_t *)cursor;
    cursor += sizeof(*item);

    results[i].address = item->address;
    uint32_t dlen = item->length;

    if (dlen == 0U) {
      results[i].status  = (uint32_t)MEMDBG_OK;
      results[i].written = 0U;
      continue;
    }

    if ((size_t)(end - cursor) < dlen) {
      results[i].status = (uint32_t)MEMDBG_ERR_PROTOCOL;
      overall = MEMDBG_ERR_PROTOCOL;
      goto _send;
    }

    if (dlen > cfg->max_read_bytes) {
      results[i].status = (uint32_t)MEMDBG_ERR_OVERFLOW;
      overall = MEMDBG_ERR_OVERFLOW;
      cursor += dlen;
      continue;
    }

    items[valid].address = item->address;
    items[valid].length  = dlen;
    data_ptrs[valid]     = cursor;
    valid++;
    cursor += dlen;
  }

  if (overall != MEMDBG_ERR_PROTOCOL && valid > 0U) {
    size_t total_data = 0U;
    for (uint32_t i = 0U; i < valid; ++i)
      total_data += items[i].length;

    if (total_data > cfg->max_packet_bytes) {
      for (uint32_t i = 0U; i < count; ++i) {
        if (results[i].status == (uint32_t)MEMDBG_ERR_IO) {
          results[i].status = (uint32_t)MEMDBG_ERR_OVERFLOW;
        }
      }
      overall = MEMDBG_ERR_OVERFLOW;
    } else {
      uint8_t *flat_data = (uint8_t *)malloc(total_data);
    if (flat_data != NULL) {
      size_t off = 0U;
      for (uint32_t i = 0U; i < valid; ++i) {
        memcpy(flat_data + off, data_ptrs[i], items[i].length);
        off += items[i].length;
      }

      memdbg_batch_write_result_entry_t batch_results[MEMDBG_BATCH_WRITE_MAX_ITEMS];
      (void)memdbg_memory_batch_write(batch_req->pid, items,
          flat_data, valid, batch_results);
      free(flat_data);

      uint32_t vr = 0U;
      for (uint32_t i = 0U; i < count && vr < valid; ++i) {
        if (results[i].status == (uint32_t)MEMDBG_ERR_IO) {
          results[i].status  = batch_results[vr].status;
          results[i].written = batch_results[vr].written;
          ++vr;
        }
      }
    } else {
      for (uint32_t i = 0U; i < count; ++i) {
        if (results[i].status == (uint32_t)MEMDBG_ERR_IO) {
          results[i].status = (uint32_t)MEMDBG_ERR_NOMEM;
        }
      }
      overall = MEMDBG_ERR_NOMEM;
    }
    }
  }

_send: {
    memdbg_status_t header_status =
        overall == MEMDBG_ERR_PROTOCOL ? MEMDBG_ERR_PROTOCOL : MEMDBG_OK;
    int rc = send_response(fd, req, header_status, results_buf,
                           (uint32_t)results_size);
    free(results_buf);
    return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }
}
