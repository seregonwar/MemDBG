/*
 * memDBG - Protocol response helpers (framed payload, send, buffer pool).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from memdbg.c.
 */

#include "memdbg/daemon/response.h"
#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/pal/lz4.h"
#include "memdbg/pal/pal_network.h"
#include "daemon_internal.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define MEMDBG_LZ4_THRESHOLD 4096U

/* ---- Framed payload compression ---- */

memdbg_status_t build_framed_payload(const void *data, uint32_t data_len,
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

  if (data_len < MEMDBG_LZ4_THRESHOLD) {
    raw = (unsigned char *)malloc(data_len + 1U);
    if (raw == NULL) return MEMDBG_ERR_NOMEM;
    raw[0] = 0x00U;
    memcpy(raw + 1, data, data_len);
    *out = raw;
    *out_len = data_len + 1U;
    return MEMDBG_OK;
  }

  int bound = lz4_compress_bound((int)data_len);
  unsigned char *compressed = (unsigned char *)malloc((size_t)bound + 5U);
  if (compressed == NULL) goto _send_raw;

  int csize = lz4_compress_default((const char *)data, (char *)(compressed + 5),
                                   (int)data_len, bound);
  if (csize <= 0 || (uint32_t)csize >= data_len - (data_len / 8U)) {
    free(compressed);
    goto _send_raw;
  }

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

int send_framed_response(int fd, const memdbg_packet_header_t *req,
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

/* ---- Send response ---- */

int send_response(int fd, const memdbg_packet_header_t *req,
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

  if (payload_len == 0U || payload == NULL) {
    if (pal_socket_write_all(fd, &hdr, sizeof(hdr)) < 0) return -1;
  } else {
    if (pal_socket_writev_all(fd, &hdr, sizeof(hdr),
                              payload, payload_len) < 0) return -1;
  }
  return 0;
}

/* ---- Zero-copy response buffer pool ---- */

typedef struct {
  unsigned char *buf;
  size_t         capacity;
} response_pool_slot_t;

static response_pool_slot_t g_resp_pool[MEMDBG_RESP_POOL_COUNT];
static atomic_uint          g_resp_pool_next = 0;

void resp_pool_init(void) {
  for (int i = 0; i < MEMDBG_RESP_POOL_COUNT; ++i) {
    g_resp_pool[i].buf = (unsigned char *)malloc(MEMDBG_RESP_POOL_SIZE);
    g_resp_pool[i].capacity = g_resp_pool[i].buf ? MEMDBG_RESP_POOL_SIZE : 0U;
  }
}

void resp_pool_fini(void) {
  for (int i = 0; i < MEMDBG_RESP_POOL_COUNT; ++i) {
    free(g_resp_pool[i].buf);
    g_resp_pool[i].buf = NULL;
    g_resp_pool[i].capacity = 0U;
  }
}

unsigned char *resp_pool_acquire(size_t needed, size_t *out_size) {
  unsigned int slot = atomic_fetch_add(&g_resp_pool_next, 1U) %
                      (unsigned int)MEMDBG_RESP_POOL_COUNT;
  if (g_resp_pool[slot].capacity >= needed) {
    *out_size = g_resp_pool[slot].capacity;
    return g_resp_pool[slot].buf;
  }
  *out_size = 0U;
  return NULL;
}
