/*
 * memDBG - Memory debugger payload for jailbroken consoles.
 * Copyright (C) 2026 SeregonWar
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/core/memdbg.h"

#include "memdbg/core/memdbg_instance.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/debug/memdbg_process.h"
#include "memdbg/pal/pal_memory.h"
#include "memdbg/pal/pal_network.h"
#include "memdbg/pal/pal_notification.h"
#include "memdbg/privilege/privilege.h"
#include "memdbg/scanner/memdbg_scan.h"
#include "memdbg/telemetry/discovery.h"
#include "memdbg/telemetry/udp_log.h"
#include "memdbg/pal/lz4.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

/* ---- Thread pool config ---- */

#define MEMDBG_THREAD_POOL_SIZE 4

/* ---- Globals ---- */

static atomic_bool g_stop_requested = ATOMIC_VAR_INIT(false);
static atomic_uint g_active_connections = 0;
static time_t      g_start_time = 0;

/* ---- Config ---- */

void memdbg_config_defaults(memdbg_config_t *cfg) {
  if (cfg == NULL) return;
  memset(cfg, 0, sizeof(*cfg));
  (void)snprintf(cfg->bind_host, sizeof(cfg->bind_host), "0.0.0.0");
  (void)snprintf(cfg->udp_log_host, sizeof(cfg->udp_log_host), "%s",
                 MEMDBG_DEFAULT_UDP_LOG_HOST);
  (void)snprintf(cfg->data_root, sizeof(cfg->data_root), "%s",
                 MEMDBG_DEFAULT_DATA_ROOT);
  cfg->debug_port      = MEMDBG_DEFAULT_DEBUG_PORT;
  cfg->udp_log_port    = MEMDBG_DEFAULT_UDP_LOG_PORT;
  cfg->discovery_port  = MEMDBG_DEFAULT_DISCOVERY_PORT;
  cfg->enable_udp_log  = true;
  cfg->replace_existing = true;
  cfg->max_packet_bytes = MEMDBG_PROTOCOL_MAX_PACKET;
  cfg->max_read_bytes   = MEMDBG_PROTOCOL_MAX_READ;
  cfg->max_scan_results = 200000U;
}

const char *memdbg_strerror(memdbg_status_t status) {
  switch (status) {
  case MEMDBG_OK:             return "ok";
  case MEMDBG_ERR_PARAM:      return "invalid parameter";
  case MEMDBG_ERR_NOMEM:      return "out of memory";
  case MEMDBG_ERR_IO:         return "i/o error";
  case MEMDBG_ERR_NET:        return "network error";
  case MEMDBG_ERR_PROTOCOL:   return "protocol error";
  case MEMDBG_ERR_UNSUPPORTED: return "unsupported";
  case MEMDBG_ERR_NOT_FOUND:  return "not found";
  case MEMDBG_ERR_PERMISSION: return "permission denied";
  case MEMDBG_ERR_OVERFLOW:   return "overflow";
  case MEMDBG_ERR_STATE:      return "invalid state";
  default:                    return "unknown error";
  }
}

void memdbg_daemon_request_stop(void) {
  atomic_store_explicit(&g_stop_requested, true, memory_order_relaxed);
}

bool memdbg_daemon_should_stop(void) {
  return atomic_load_explicit(&g_stop_requested, memory_order_relaxed);
}

/* ---- Helpers ---- */

static uint16_t memdbg_platform_id(void) {
#if defined(PLATFORM_PS4) || defined(PS4)
  return (uint16_t)MEMDBG_PLATFORM_PS4;
#elif defined(PLATFORM_PS5) || defined(PS5)
  return (uint16_t)MEMDBG_PLATFORM_PS5;
#else
  return (uint16_t)MEMDBG_PLATFORM_HOST;
#endif
}

static uint32_t memdbg_capabilities(const memdbg_config_t *cfg) {
  uint32_t caps = MEMDBG_CAP_PROCESS_LIST | MEMDBG_CAP_PROCESS_MAPS |
                  MEMDBG_CAP_MEMORY_READ | MEMDBG_CAP_MEMORY_WRITE |
                  MEMDBG_CAP_SCAN_EXACT | MEMDBG_CAP_SCAN_PROCESS_EXACT |
                  MEMDBG_CAP_SCAN_TELEMETRY | MEMDBG_CAP_PROCESS_INFO |
                  MEMDBG_CAP_SCAN_AOB | MEMDBG_CAP_SCAN_POINTER |
                  MEMDBG_CAP_FOREGROUND_APP | MEMDBG_CAP_PROCESS_CONTROL |
                  MEMDBG_CAP_BATCH_READ | MEMDBG_CAP_BATCH_WRITE |
                  MEMDBG_CAP_PERF_TELEMETRY | MEMDBG_CAP_LZ4 |
                  MEMDBG_CAP_SCAN_UNKNOWN | MEMDBG_CAP_SCAN_PROCESS_AOB |
                  MEMDBG_CAP_DISCOVERY;
  if (cfg != NULL && cfg->enable_udp_log)
    caps |= MEMDBG_CAP_UDP_LOG;
  return caps;
}

#define MEMDBG_LZ4_THRESHOLD 4096U

/* Forward declaration */
static int send_response(socket_t fd, const memdbg_packet_header_t *req,
                         memdbg_status_t status, const void *payload,
                         uint32_t payload_len);

/* ---- Framed payload compression ----
   Prefix byte: 0x00 = raw data follows (strip prefix on client)
                0x01 = LZ4: 4-byte uncomp_len LE + compressed data
   Always emits a prefix for consistency — client always strips/decompresses. */

static memdbg_status_t build_framed_payload(const void *data, uint32_t data_len,
                                            unsigned char **out,
                                            uint32_t *out_len) {
  unsigned char *raw;

  if (out == NULL || out_len == NULL || (data == NULL && data_len != 0U)) {
    return MEMDBG_ERR_PARAM;
  }
  *out = NULL;
  *out_len = 0U;

  if (data == NULL || data_len == 0U) {
    raw = (unsigned char *)malloc(1U);
    if (raw == NULL) return MEMDBG_ERR_NOMEM;
    raw[0] = 0x00U;
    *out = raw;
    *out_len = 1U;
    return MEMDBG_OK;
  }

  /* Small payloads: raw with 0x00 prefix */
  if (data_len < MEMDBG_LZ4_THRESHOLD) {
    raw = (unsigned char *)malloc(data_len + 1U);
    if (raw == NULL) return MEMDBG_ERR_NOMEM;
    raw[0] = 0x00U;
    memcpy(raw + 1, data, data_len);
    *out = raw;
    *out_len = data_len + 1U;
    return MEMDBG_OK;
  }

  /* Large payloads: try LZ4 compression */
  int bound = lz4_compress_bound((int)data_len);
  unsigned char *compressed = (unsigned char *)malloc((size_t)bound + 5U);
  if (compressed == NULL) goto _send_raw;

  int csize = lz4_compress_default((const char *)data, (char *)(compressed + 5),
                                   (int)data_len, bound);
  if (csize <= 0 || (uint32_t)csize >= data_len - (data_len / 8U)) {
    free(compressed);
    goto _send_raw;
  }

  /* Compressed: prefix 0x01 + 4-byte uncompressed_size LE + compressed data */
  compressed[0] = 0x01U;
  compressed[1] = (unsigned char)(data_len & 0xFFU);
  compressed[2] = (unsigned char)((data_len >> 8U) & 0xFFU);
  compressed[3] = (unsigned char)((data_len >> 16U) & 0xFFU);
  compressed[4] = (unsigned char)((data_len >> 24U) & 0xFFU);
  *out = compressed;
  *out_len = (uint32_t)csize + 5U;
  return MEMDBG_OK;

_send_raw:
  {
    raw = (unsigned char *)malloc(data_len + 1U);
    if (raw == NULL) return MEMDBG_ERR_NOMEM;
    raw[0] = 0x00U;
    memcpy(raw + 1, data, data_len);
    *out = raw;
    *out_len = data_len + 1U;
    return MEMDBG_OK;
  }
}

static int send_framed_response(socket_t fd, const memdbg_packet_header_t *req,
                                memdbg_status_t status, const void *data,
                                uint32_t data_len) {
  unsigned char *payload = NULL;
  uint32_t payload_len = 0U;
  memdbg_status_t frame_status =
      build_framed_payload(data, data_len, &payload, &payload_len);
  int rc;

  if (frame_status != MEMDBG_OK) {
    return send_response(fd, req, frame_status, NULL, 0U);
  }

  rc = send_response(fd, req, status, payload, payload_len);
  free(payload);
  return rc;
}

/* ---- Send response (implementation) ---- */

static int send_response(socket_t fd, const memdbg_packet_header_t *req,
                         memdbg_status_t status, const void *payload,
                         uint32_t payload_len) {
  memdbg_response_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic      = MEMDBG_PACKET_MAGIC;
  hdr.version    = MEMDBG_PROTOCOL_VERSION;
  hdr.command    = req != NULL ? req->command : 0U;
  hdr.request_id = req != NULL ? req->request_id : 0U;
  hdr.status     = (int32_t)status;
  hdr.length     = payload_len;

  if (pal_socket_write_all(fd, &hdr, sizeof(hdr)) < 0) return -1;
  if (payload_len != 0U && pal_socket_write_all(fd, payload, payload_len) < 0) return -1;
  return 0;
}

/* ---- HELLO ---- */

static memdbg_status_t handle_hello(const memdbg_config_t *cfg,
                                    memdbg_hello_response_t *out) {
  if (cfg == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));
  out->protocol_version = MEMDBG_PROTOCOL_VERSION;
  out->platform_id      = memdbg_platform_id();
  out->capabilities     = memdbg_capabilities(cfg);
  out->debug_port       = cfg->debug_port;
  out->udp_log_port     = cfg->enable_udp_log ? cfg->udp_log_port : 0U;
  (void)snprintf(out->version, sizeof(out->version), "%s", MEMDBG_VERSION_STRING);
  (void)snprintf(out->name, sizeof(out->name), "MemDBG");
  return MEMDBG_OK;
}

/* ---- PROCESS_LIST ---- */

static memdbg_status_t handle_process_list(socket_t fd, const memdbg_packet_header_t *req) {
  memdbg_process_list_t list;
  memdbg_status_t status = memdbg_process_list(&list);
  if (status != MEMDBG_OK) return status;

  size_t payload_len = sizeof(uint32_t) + list.count * sizeof(memdbg_process_entry_t);
  if (payload_len > UINT32_MAX) { memdbg_process_list_free(&list); return MEMDBG_ERR_OVERFLOW; }

  unsigned char *payload = (unsigned char *)malloc(payload_len);
  if (payload == NULL) { memdbg_process_list_free(&list); return MEMDBG_ERR_NOMEM; }

  uint32_t count = (uint32_t)list.count;
  memcpy(payload, &count, sizeof(count));
  if (list.count != 0U)
    memcpy(payload + sizeof(count), list.entries, list.count * sizeof(memdbg_process_entry_t));

  int rc = send_response(fd, req, MEMDBG_OK, payload, (uint32_t)payload_len);
  free(payload);
  memdbg_process_list_free(&list);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- PROCESS_MAPS ---- */

static memdbg_status_t handle_process_maps(socket_t fd, const memdbg_packet_header_t *req,
                                           const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_process_maps_request_t)) return MEMDBG_ERR_PROTOCOL;
  const memdbg_process_maps_request_t *maps_req = (const memdbg_process_maps_request_t *)body;
  memdbg_map_list_t maps;
  memdbg_status_t status = memdbg_process_maps_cached(maps_req->pid, &maps);
  if (status != MEMDBG_OK) return status;

  size_t payload_len = sizeof(uint32_t) + maps.count * sizeof(memdbg_map_entry_t);
  if (payload_len > UINT32_MAX) { memdbg_process_maps_free(&maps); return MEMDBG_ERR_OVERFLOW; }

  unsigned char *payload = (unsigned char *)malloc(payload_len);
  if (payload == NULL) { memdbg_process_maps_free(&maps); return MEMDBG_ERR_NOMEM; }

  uint32_t count = (uint32_t)maps.count;
  memcpy(payload, &count, sizeof(count));
  if (maps.count != 0U)
    memcpy(payload + sizeof(count), maps.entries, maps.count * sizeof(memdbg_map_entry_t));

  int rc = send_response(fd, req, MEMDBG_OK, payload, (uint32_t)payload_len);
  free(payload);
  memdbg_process_maps_free(&maps);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- PROCESS_INFO ---- */

static memdbg_status_t handle_process_info(socket_t fd, const memdbg_packet_header_t *req,
                                           const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_process_info_request_t)) return MEMDBG_ERR_PROTOCOL;
  const memdbg_process_info_request_t *info_req = (const memdbg_process_info_request_t *)body;
  memdbg_process_info_response_t info;
  memdbg_status_t status = memdbg_process_info(info_req->pid, &info);
  if (status != MEMDBG_OK) return status;
  return send_response(fd, req, MEMDBG_OK, &info, sizeof(info)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- MEMORY_READ / MEMORY_WRITE ---- */

static memdbg_status_t handle_memory_read(socket_t fd, const memdbg_packet_header_t *req,
                                          const memdbg_config_t *cfg, const void *body,
                                          uint32_t body_len) {
  if (body_len != sizeof(memdbg_memory_request_t)) return MEMDBG_ERR_PROTOCOL;
  const memdbg_memory_request_t *read_req = (const memdbg_memory_request_t *)body;
  if (read_req->length > cfg->max_read_bytes) return MEMDBG_ERR_OVERFLOW;

  unsigned char *buffer = (unsigned char *)malloc(read_req->length);
  if (buffer == NULL && read_req->length != 0U) return MEMDBG_ERR_NOMEM;

  size_t read_len = 0U;
  memdbg_status_t status = memdbg_memory_read(read_req->pid, read_req->address,
      buffer, read_req->length, &read_len);
  if (status == MEMDBG_OK) {
    if (send_framed_response(fd, req, MEMDBG_OK, buffer, (uint32_t)read_len) != 0)
      status = MEMDBG_ERR_NET;
  }
  free(buffer);
  return status;
}

static memdbg_status_t handle_memory_write(socket_t fd, const memdbg_packet_header_t *req,
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

static memdbg_status_t handle_batch_read(socket_t fd, const memdbg_packet_header_t *req,
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

  /* Calculate total data needed. */
  uint64_t total_data = 0U;
  for (uint32_t i = 0U; i < count; ++i)
    total_data += items[i].length;

  if (total_data > cfg->max_read_bytes * 2U) return MEMDBG_ERR_OVERFLOW;
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

/* ---- BATCH_WRITE ----
 *
 * Wire format: batch_req (pid + count) followed by count repetitions of
 *   { memdbg_batch_write_item_t, item->length raw bytes }.
 *
 * Uses memdbg_memory_batch_write for OS-level batching: a single fd to
 * /proc/pid/mem on Linux (vs N× open/seek/write/close with individual
 * writes), individual ptrace calls on FreeBSD, etc. */

static memdbg_status_t handle_batch_write(socket_t fd, const memdbg_packet_header_t *req,
                                          const memdbg_config_t *cfg, const void *body,
                                          uint32_t body_len) {
  if (body_len < sizeof(memdbg_batch_write_request_t)) return MEMDBG_ERR_PROTOCOL;

  const memdbg_batch_write_request_t *batch_req = (const memdbg_batch_write_request_t *)body;
  uint32_t count = batch_req->count;
  if (count == 0U || count > MEMDBG_BATCH_WRITE_MAX_ITEMS) return MEMDBG_ERR_PARAM;

  size_t results_size = count * sizeof(memdbg_batch_write_result_entry_t);

  /* Allocate and zero-initialize results buffer.  Zeroing ensures that
     unprocessed entries (after an early protocol-error goto) are safely
     reported as address=0, written=0, status=ERR_IO. */
  unsigned char *results_buf = (unsigned char *)calloc(1U, results_size);
  if (results_buf == NULL) return MEMDBG_ERR_NOMEM;

  memdbg_batch_write_result_entry_t *results =
      (memdbg_batch_write_result_entry_t *)results_buf;

  /* Phase 1: parse wire format, validating and collecting item descriptors
     + data pointers.  The wire interleaves item headers with their data,
     so we need to collect them before calling the batch API. */
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

    /* Collect for batch write */
    items[valid].address = item->address;
    items[valid].length  = dlen;
    data_ptrs[valid]     = cursor;
    valid++;
    cursor += dlen;
  }

  /* Phase 2: build flat data buffer from scattered wire data,
     then execute all writes in one PAL batch session. */
  if (overall != MEMDBG_ERR_PROTOCOL && valid > 0U) {
    /* Compute total data size */
    size_t total_data = 0U;
    for (uint32_t i = 0U; i < valid; ++i)
      total_data += items[i].length;

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

      /* Map batch results back to wire-ordered results array.
         Only items with pre-batch status ERR_IO were passed to the batch;
         dlen==0 items (status OK) and overflow items (status OVERFLOW)
         are skipped, keeping their pre-batch values. */
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
      overall = MEMDBG_OK;
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

/* ---- Scan result sender ---- */

static memdbg_status_t send_scan_result(socket_t fd, const memdbg_packet_header_t *req,
                                        memdbg_scan_result_t *result) {
  size_t payload_len = sizeof(memdbg_scan_response_prefix_t) +
                       result->count * sizeof(memdbg_scan_result_entry_t);
  if (payload_len > UINT32_MAX) return MEMDBG_ERR_OVERFLOW;

  unsigned char *payload = (unsigned char *)malloc(payload_len);
  if (payload == NULL) return MEMDBG_ERR_NOMEM;

  memdbg_scan_response_prefix_t prefix;
  memset(&prefix, 0, sizeof(prefix));
  prefix.count           = (uint32_t)result->count;
  prefix.truncated       = result->truncated ? 1U : 0U;
  prefix.bytes_scanned   = result->bytes_scanned;
  prefix.elapsed_ns      = result->elapsed_ns;
  prefix.read_calls      = result->read_calls;
  prefix.regions_scanned = result->regions_scanned;
  prefix.read_errors     = result->read_errors;

  memcpy(payload, &prefix, sizeof(prefix));
  if (result->count != 0U)
    memcpy(payload + sizeof(prefix), result->entries,
           result->count * sizeof(memdbg_scan_result_entry_t));

  int rc = send_response(fd, req, MEMDBG_OK, payload, (uint32_t)payload_len);
  free(payload);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Scan handlers ---- */

static memdbg_status_t handle_scan_exact_v2(socket_t fd, const memdbg_packet_header_t *req,
                                            const memdbg_config_t *cfg, const void *body,
                                            uint32_t body_len) {
  if (body_len != sizeof(memdbg_scan_exact_request_t)) return MEMDBG_ERR_PROTOCOL;
  memdbg_scan_exact_request_t scan_req;
  memcpy(&scan_req, body, sizeof(scan_req));
  if (scan_req.max_results == 0U || scan_req.max_results > cfg->max_scan_results)
    scan_req.max_results = cfg->max_scan_results;
  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_exact(&scan_req, &result);
  if (status == MEMDBG_OK) status = send_scan_result(fd, req, &result);
  memdbg_scan_result_free(&result);
  return status;
}

static memdbg_status_t handle_scan_process_exact(socket_t fd, const memdbg_packet_header_t *req,
                                                 const memdbg_config_t *cfg, const void *body,
                                                 uint32_t body_len) {
  if (body_len != sizeof(memdbg_scan_process_exact_request_t)) return MEMDBG_ERR_PROTOCOL;
  memdbg_scan_process_exact_request_t scan_req;
  memcpy(&scan_req, body, sizeof(scan_req));
  if (scan_req.max_results == 0U || scan_req.max_results > cfg->max_scan_results)
    scan_req.max_results = cfg->max_scan_results;
  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_process_exact(&scan_req, &result);
  if (status == MEMDBG_OK) status = send_scan_result(fd, req, &result);
  memdbg_scan_result_free(&result);
  return status;
}

static memdbg_status_t handle_scan_aob(socket_t fd, const memdbg_packet_header_t *req,
                                       const memdbg_config_t *cfg, const void *body,
                                       uint32_t body_len) {
  if (body_len < sizeof(memdbg_scan_aob_request_t)) return MEMDBG_ERR_PROTOCOL;
  const memdbg_scan_aob_request_t *aob_req = (const memdbg_scan_aob_request_t *)body;
  uint32_t pat_len = aob_req->pattern_length;
  if (pat_len == 0U || pat_len > 256U) return MEMDBG_ERR_PARAM;
  uint32_t expected = sizeof(*aob_req) + pat_len + pat_len;
  if (body_len < expected) return MEMDBG_ERR_PROTOCOL;
  const uint8_t *pattern = (const uint8_t *)body + sizeof(*aob_req);
  const uint8_t *mask    = pattern + pat_len;
  memdbg_scan_aob_request_t req_copy = *aob_req;
  if (req_copy.max_results == 0U || req_copy.max_results > cfg->max_scan_results)
    req_copy.max_results = cfg->max_scan_results;
  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_aob(&req_copy, pattern, mask, &result);
  if (status == MEMDBG_OK) status = send_scan_result(fd, req, &result);
  memdbg_scan_result_free(&result);
  return status;
}

static memdbg_status_t handle_scan_process_aob(socket_t fd, const memdbg_packet_header_t *req,
                                               const memdbg_config_t *cfg, const void *body,
                                               uint32_t body_len) {
  if (body_len < sizeof(memdbg_scan_process_aob_request_t)) return MEMDBG_ERR_PROTOCOL;
  const memdbg_scan_process_aob_request_t *scan_req =
      (const memdbg_scan_process_aob_request_t *)body;
  uint32_t pat_len = scan_req->pattern_length;
  if (pat_len == 0U || pat_len > 256U) return MEMDBG_ERR_PARAM;
  uint32_t expected = sizeof(*scan_req) + pat_len + pat_len;
  if (body_len < expected) return MEMDBG_ERR_PROTOCOL;
  const uint8_t *pattern = (const uint8_t *)body + sizeof(*scan_req);
  const uint8_t *mask    = pattern + pat_len;
  memdbg_scan_process_aob_request_t req_copy = *scan_req;
  if (req_copy.max_results == 0U || req_copy.max_results > cfg->max_scan_results)
    req_copy.max_results = cfg->max_scan_results;
  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_process_aob(&req_copy, pattern, mask,
      &result);
  if (status == MEMDBG_OK) status = send_scan_result(fd, req, &result);
  memdbg_scan_result_free(&result);
  return status;
}

static memdbg_status_t handle_scan_unknown(socket_t fd, const memdbg_packet_header_t *req,
                                           const memdbg_config_t *cfg, const void *body,
                                           uint32_t body_len) {
  if (body_len != sizeof(memdbg_scan_process_exact_request_t)) return MEMDBG_ERR_PROTOCOL;
  memdbg_scan_process_exact_request_t scan_req;
  memcpy(&scan_req, body, sizeof(scan_req));
  if (scan_req.max_results == 0U || scan_req.max_results > cfg->max_scan_results)
    scan_req.max_results = cfg->max_scan_results;
  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_unknown(&scan_req, &result);
  if (status == MEMDBG_OK) status = send_scan_result(fd, req, &result);
  memdbg_scan_result_free(&result);
  return status;
}

static memdbg_status_t handle_scan_pointer(socket_t fd, const memdbg_packet_header_t *req,
                                           const memdbg_config_t *cfg, const void *body,
                                           uint32_t body_len) {
  if (body_len != sizeof(memdbg_scan_pointer_request_t)) return MEMDBG_ERR_PROTOCOL;
  memdbg_scan_pointer_request_t scan_req;
  memcpy(&scan_req, body, sizeof(scan_req));
  if (scan_req.max_results == 0U || scan_req.max_results > cfg->max_scan_results)
    scan_req.max_results = cfg->max_scan_results;
  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_pointer(&scan_req, &result);
  if (status == MEMDBG_OK) status = send_scan_result(fd, req, &result);
  memdbg_scan_result_free(&result);
  return status;
}

/* ---- FOREGROUND_APP ---- */

static memdbg_status_t handle_foreground_app(socket_t fd, const memdbg_packet_header_t *req,
                                             const void *body, uint32_t body_len) {
  (void)body; (void)body_len;
  memdbg_foreground_app_response_t app;
  memset(&app, 0, sizeof(app));
  memdbg_process_list_t list;
  memdbg_status_t status = memdbg_process_list(&list);
  if (status != MEMDBG_OK) return status;
  for (size_t i = 0U; i < list.count; ++i) {
    if (list.entries[i].pid > 0) {
      app.pid = list.entries[i].pid;
      memdbg_process_info_response_t info;
      if (memdbg_process_info(list.entries[i].pid, &info) == MEMDBG_OK) {
        memcpy(app.title_id, info.title_id, sizeof(app.title_id));
        memcpy(app.content_id, info.content_id, sizeof(app.content_id));
        memcpy(app.name, info.name, sizeof(app.name));
      }
      break;
    }
  }
  memdbg_process_list_free(&list);
  return send_response(fd, req, MEMDBG_OK, &app, sizeof(app)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- PROCESS_STOP / PROCESS_CONTINUE ---- */

static memdbg_status_t handle_process_control(socket_t fd, const memdbg_packet_header_t *req,
                                              const void *body, uint32_t body_len,
                                              uint32_t expected_action) {
  if (body_len != sizeof(memdbg_process_control_request_t)) return MEMDBG_ERR_PROTOCOL;
  const memdbg_process_control_request_t *ctrl = (const memdbg_process_control_request_t *)body;
  if (ctrl->action != expected_action) return MEMDBG_ERR_PARAM;
  int sig = (expected_action == 1U) ? SIGSTOP : SIGCONT;
  if (kill((pid_t)ctrl->pid, sig) != 0)
    return errno == EPERM ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_NOT_FOUND;
  return send_response(fd, req, MEMDBG_OK, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- TELEMETRY ---- */

static memdbg_status_t handle_telemetry(socket_t fd, const memdbg_packet_header_t *req) {
  memdbg_telemetry_response_t telemetry;
  memset(&telemetry, 0, sizeof(telemetry));

  memdbg_memory_telemetry(&telemetry);

  time_t now = time(NULL);
  telemetry.uptime_seconds     = (uint64_t)(now - g_start_time);
  telemetry.active_connections = atomic_load_explicit(&g_active_connections, memory_order_relaxed);
  telemetry.thread_pool_size   = MEMDBG_THREAD_POOL_SIZE;

  uint32_t hits = 0U, misses = 0U;
  memdbg_process_cache_stats(&hits, &misses);
  telemetry.scan_cache_hits   = hits;
  telemetry.scan_cache_misses = misses;

  return send_response(fd, req, MEMDBG_OK, &telemetry, sizeof(telemetry)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Dispatch ---- */

static memdbg_status_t dispatch_packet(socket_t fd, const memdbg_config_t *cfg,
                                       const memdbg_packet_header_t *req, const void *body) {
  switch ((memdbg_command_t)req->command) {
  case MEMDBG_CMD_HELLO: {
    memdbg_hello_response_t hello;
    memdbg_status_t status = handle_hello(cfg, &hello);
    if (status != MEMDBG_OK) return status;
    return send_response(fd, req, MEMDBG_OK, &hello, sizeof(hello)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }
  case MEMDBG_CMD_PING:
    return send_response(fd, req, MEMDBG_OK, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  case MEMDBG_CMD_PROCESS_LIST:       return handle_process_list(fd, req);
  case MEMDBG_CMD_PROCESS_MAPS:       return handle_process_maps(fd, req, body, req->length);
  case MEMDBG_CMD_PROCESS_INFO:       return handle_process_info(fd, req, body, req->length);
  case MEMDBG_CMD_MEMORY_READ:        return handle_memory_read(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_MEMORY_WRITE:       return handle_memory_write(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_BATCH_READ:         return handle_batch_read(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_BATCH_WRITE:        return handle_batch_write(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_EXACT:         return handle_scan_exact_v2(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_PROCESS_EXACT: return handle_scan_process_exact(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_AOB:           return handle_scan_aob(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_PROCESS_AOB:
    return handle_scan_process_aob(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_POINTER:       return handle_scan_pointer(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_UNKNOWN:       return handle_scan_unknown(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_FOREGROUND_APP:     return handle_foreground_app(fd, req, body, req->length);
  case MEMDBG_CMD_PROCESS_STOP:       return handle_process_control(fd, req, body, req->length, 1U);
  case MEMDBG_CMD_PROCESS_CONTINUE:   return handle_process_control(fd, req, body, req->length, 2U);
  case MEMDBG_CMD_TELEMETRY:          return handle_telemetry(fd, req);
  case MEMDBG_CMD_SHUTDOWN:
    memdbg_daemon_request_stop();
    return send_response(fd, req, MEMDBG_OK, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  default:
    return MEMDBG_ERR_PROTOCOL;
  }
}

/* ---- Single client handler (runs in thread pool worker) ---- */

static void handle_client(socket_t fd, const memdbg_config_t *cfg) {
  atomic_fetch_add_explicit(&g_active_connections, 1U, memory_order_relaxed);
  (void)pal_socket_set_nonblocking(fd, false);
  (void)pal_socket_configure(fd);

  while (!memdbg_daemon_should_stop()) {
    memdbg_packet_header_t req;
    if (pal_socket_read_exact(fd, &req, sizeof(req)) < 0) break;

    if (req.magic != MEMDBG_PACKET_MAGIC || req.version != MEMDBG_PROTOCOL_VERSION ||
        req.length > cfg->max_packet_bytes) {
      (void)send_response(fd, &req, MEMDBG_ERR_PROTOCOL, NULL, 0U);
      break;
    }

    void *body = NULL;
    if (req.length != 0U) {
      body = malloc(req.length);
      if (body == NULL) {
        (void)send_response(fd, &req, MEMDBG_ERR_NOMEM, NULL, 0U);
        break;
      }
      if (pal_socket_read_exact(fd, body, req.length) < 0) { free(body); break; }
    }

    memdbg_status_t status = dispatch_packet(fd, cfg, &req, body);
    free(body);
    if (status != MEMDBG_OK)
      (void)send_response(fd, &req, status, NULL, 0U);
  }

  (void)pal_socket_close(fd);
  atomic_fetch_sub_explicit(&g_active_connections, 1U, memory_order_relaxed);
}

/* ---- Thread pool worker (multi-accept pattern) ---- */

typedef struct {
  socket_t            listen_fd;
  const memdbg_config_t *cfg;
} worker_args_t;

static int wait_for_client(socket_t listen_fd) {
  fd_set rfds;
  struct timeval tv;
  int rc;

  FD_ZERO(&rfds);
  FD_SET(listen_fd, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = 250000;

  do {
    rc = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
  } while (rc < 0 && errno == EINTR);

  if (rc <= 0) return rc;
  return FD_ISSET(listen_fd, &rfds) ? 1 : 0;
}

static void *worker_thread(void *arg) {
  worker_args_t *args = (worker_args_t *)arg;
  socket_t listen_fd  = args->listen_fd;
  memdbg_config_t cfg = *args->cfg;

  while (!memdbg_daemon_should_stop()) {
    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)sizeof(ss);
    int ready = wait_for_client(listen_fd);

    if (ready == 0) continue;
    if (ready < 0) {
      if (memdbg_daemon_should_stop()) break;
      memdbg_log_write(MEMDBG_LOG_WARN, "listener wait failed: %s",
                       pal_socket_last_error());
      break;
    }

    socket_t client_fd = accept(listen_fd, (struct sockaddr *)&ss, &slen);

    if (client_fd < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
      if (memdbg_daemon_should_stop()) break;
      memdbg_log_write(MEMDBG_LOG_WARN, "accept failed: %s", pal_socket_last_error());
      continue;
    }

    handle_client(client_fd, &cfg);
  }

  return NULL;
}

/* ---- Signal handlers ---- */

static void signal_handler(int signum) {
  (void)signum;
  memdbg_daemon_request_stop();
}

static void install_signal_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  (void)sigemptyset(&sa.sa_mask);
  (void)sigaction(SIGINT,  &sa, NULL);
  (void)sigaction(SIGTERM, &sa, NULL);
#ifdef SIGHUP
  (void)sigaction(SIGHUP, &sa, NULL);
#endif
#ifdef SIGPIPE
  sa.sa_handler = SIG_IGN;
  (void)sigaction(SIGPIPE, &sa, NULL);
#endif
}

static void daemon_sleep_ms(uint32_t ms) {
  struct timespec ts;
  ts.tv_sec = (time_t)(ms / 1000U);
  ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
  }
}

static memdbg_status_t open_debug_listener(const memdbg_config_t *cfg,
                                           socket_t *listen_fd) {
  int saved_errno;
  memdbg_status_t replace_status;

  if (cfg == NULL || listen_fd == NULL) return MEMDBG_ERR_PARAM;

  if (cfg->replace_existing) {
    replace_status = memdbg_instance_stop_previous(cfg);
    if (replace_status == MEMDBG_OK) {
      daemon_sleep_ms(200U);
    }
  }

  if (pal_tcp_listen(cfg->bind_host, cfg->debug_port, 16, listen_fd) == 0) {
    return MEMDBG_OK;
  }

  saved_errno = errno;
  if (!cfg->replace_existing || saved_errno != EADDRINUSE) {
    errno = saved_errno;
    return MEMDBG_ERR_NET;
  }

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "debug port %u is still busy; retrying previous payload stop",
                   cfg->debug_port);
  (void)memdbg_instance_stop_previous(cfg);

  for (uint32_t i = 0U; i < 25U; ++i) {
    daemon_sleep_ms(100U);
    if (pal_tcp_listen(cfg->bind_host, cfg->debug_port, 16, listen_fd) == 0) {
      memdbg_log_write(MEMDBG_LOG_INFO,
                       "debug listener rebound after replacing previous payload");
      return MEMDBG_OK;
    }
    saved_errno = errno;
    if (saved_errno != EADDRINUSE) break;
  }

  errno = saved_errno;
  return MEMDBG_ERR_NET;
}

/* ---- Daemon entry point ---- */

int memdbg_daemon_run(const memdbg_config_t *cfg_in) {
  memdbg_config_t cfg;
  socket_t listen_fd = PAL_INVALID_SOCKET;
  int worker_count = 0;

  if (cfg_in == NULL) memdbg_config_defaults(&cfg);
  else                cfg = *cfg_in;

  atomic_store_explicit(&g_stop_requested, false, memory_order_relaxed);
  g_start_time = time(NULL);

  if (pal_network_init() != 0) return MEMDBG_ERR_NET;

  if (memdbg_log_init(cfg.data_root) != 0) {
    (void)pal_network_fini();
    return MEMDBG_ERR_IO;
  }
  int notification_ready = (pal_notification_init() == 0);

  install_signal_handlers();

  if (cfg.enable_udp_log) {
    memdbg_udp_log_config_t ucfg;
    memdbg_udp_log_config_defaults(&ucfg);
    (void)snprintf(ucfg.host, sizeof(ucfg.host), "%s", cfg.udp_log_host);
    ucfg.port = cfg.udp_log_port;
    ucfg.broadcast = strcmp(cfg.udp_log_host, "255.255.255.255") == 0;
    memdbg_status_t ustatus = memdbg_udp_log_start(&ucfg);
    if (ustatus != MEMDBG_OK)
      memdbg_log_write(MEMDBG_LOG_WARN, "UDP log disabled: %s", memdbg_strerror(ustatus));
  }

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "MemDBG %s starting debug=%s:%u udp_log=%s:%u pool=%d",
                   MEMDBG_VERSION_STRING, cfg.bind_host, cfg.debug_port,
                   cfg.enable_udp_log ? cfg.udp_log_host : "off",
                   cfg.enable_udp_log ? cfg.udp_log_port : 0U,
                   MEMDBG_THREAD_POOL_SIZE);

  if (memdbg_privilege_supported() &&
      memdbg_privilege_jailbreak_self() != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "privilege: payload escalation failed; memory actions may fail with permission/i-o status");
  }

  if (open_debug_listener(&cfg, &listen_fd) != MEMDBG_OK) {
    memdbg_log_write(MEMDBG_LOG_ERROR, "debug listener failed: %s", pal_socket_last_error());
    if (notification_ready) pal_notification_shutdown();
    memdbg_udp_log_stop();
    memdbg_log_close();
    pal_network_fini();
    return MEMDBG_ERR_NET;
  }

  if (memdbg_instance_write_pid_file(&cfg) != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN, "instance: failed to write pid file");
  }

  /* Start UDP discovery listener so frontends can auto-detect the payload. */
  {
    memdbg_status_t dstatus = memdbg_discovery_start(&cfg);
    if (dstatus != MEMDBG_OK)
      memdbg_log_write(MEMDBG_LOG_WARN, "discovery: %s",
                       memdbg_strerror(dstatus));
  }

  if (notification_ready)
    pal_notification_send("MemDBG by seregonwar started");

  /* Pre-create thread pool workers. They wait with a short select timeout so
     SHUTDOWN and signals can stop the daemon without waiting on blocking accept(). */
  worker_args_t wargs;
  wargs.listen_fd = listen_fd;
  wargs.cfg       = &cfg;

  pthread_t workers[MEMDBG_THREAD_POOL_SIZE];
  for (int i = 0; i < MEMDBG_THREAD_POOL_SIZE; ++i) {
    if (pthread_create(&workers[i], NULL, worker_thread, &wargs) != 0) {
      memdbg_log_write(MEMDBG_LOG_ERROR, "failed to create worker thread %d", i);
      memdbg_daemon_request_stop();
      break;
    }
    worker_count++;
  }

  /* Wait for workers to exit (happens on shutdown). */
  for (int i = 0; i < worker_count; ++i)
    (void)pthread_join(workers[i], NULL);

  (void)pal_socket_close(listen_fd);
  memdbg_discovery_stop();
  pal_memory_fd_cache_flush(0);  /* close all cached /proc/pid/mem fds */
  memdbg_instance_remove_pid_file(&cfg);
  memdbg_process_maps_cache_flush(0);

  memdbg_log_write(MEMDBG_LOG_INFO, "MemDBG stopped");
  if (notification_ready) pal_notification_shutdown();
  memdbg_udp_log_stop();
  memdbg_log_close();
  pal_network_fini();
  return MEMDBG_OK;
}
