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

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define MEMDBG_LZ4_THRESHOLD 4096U
#define MEMDBG_RESPONSE_COALESCE_MAX 8192U
#define MEMDBG_RESPONSE_HEAP_COALESCE_MAX (1024U * 1024U)

#if defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__) || \
    defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#define MEMDBG_RESPONSE_CONSOLE 1
#else
#define MEMDBG_RESPONSE_CONSOLE 0
#endif

static int send_raw_framed(int fd, const memdbg_response_header_t *hdr,
                           const void *data, uint32_t data_len) {
  const unsigned char raw_marker = 0U;
#if MEMDBG_RESPONSE_CONSOLE
  /* Retail PS4/PS5 TCP stacks can impose a delayed-ACK-sized bubble between
   * a tiny header write and the immediately following body. Coalesce common
   * memory reads into one write; fall back to bounded split writes if memory
   * pressure prevents the temporary allocation. */
  if (data_len <= MEMDBG_RESPONSE_HEAP_COALESCE_MAX) {
    size_t frame_len = sizeof(*hdr) + 1U + (size_t)data_len;
    unsigned char *frame = (unsigned char *)malloc(frame_len);
    if (frame != NULL) {
      memcpy(frame, hdr, sizeof(*hdr));
      frame[sizeof(*hdr)] = raw_marker;
      if (data_len != 0U) memcpy(frame + sizeof(*hdr) + 1U, data, data_len);
      int rc = pal_socket_write_all(fd, frame, frame_len) < 0 ? -1 : 0;
      free(frame);
      return rc;
    }
  }
  {
    unsigned char prefix[sizeof(*hdr) + 1U];
    memcpy(prefix, hdr, sizeof(*hdr));
    prefix[sizeof(*hdr)] = raw_marker;
    if (pal_socket_write_all(fd, prefix, sizeof(prefix)) < 0) return -1;
    return data_len == 0U || pal_socket_write_all(fd, data, data_len) >= 0
        ? 0 : -1;
  }
#else
  return pal_socket_writev3_all(fd, hdr, sizeof(*hdr),
                                &raw_marker, sizeof(raw_marker),
                                data, data_len) < 0 ? -1 : 0;
#endif
}

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

  if (data_len > (uint32_t)INT_MAX) goto _send_raw;
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
  if (data == NULL && data_len != 0U)
    return send_response(fd, req, MEMDBG_ERR_PARAM, NULL, 0U);

  if (data_len < MEMDBG_LZ4_THRESHOLD || data_len > (uint32_t)INT_MAX) {
    memdbg_response_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = MEMDBG_PACKET_MAGIC;
    hdr.version = MEMDBG_PROTOCOL_VERSION;
    hdr.command = req != NULL ? req->command : 0U;
    hdr.request_id = req != NULL ? req->request_id : 0U;
    hdr.status = (int32_t)status;
    hdr.length = data_len + 1U;
    return send_raw_framed(fd, &hdr, data, data_len);
  }

  int bound = lz4_compress_bound((int)data_len);
  unsigned char *compressed = (unsigned char *)malloc((size_t)bound + 5U);
  if (compressed != NULL) {
    int csize = lz4_compress_default((const char *)data,
                                     (char *)(compressed + 5),
                                     (int)data_len, bound);
    if (csize > 0 && (uint32_t)csize < data_len - (data_len / 8U)) {
      compressed[0] = 0x01U;
      compressed[1] = (unsigned char)(data_len & 0xFFU);
      compressed[2] = (unsigned char)((data_len >> 8U) & 0xFFU);
      compressed[3] = (unsigned char)((data_len >> 16U) & 0xFFU);
      compressed[4] = (unsigned char)((data_len >> 24U) & 0xFFU);
      int rc = send_response(fd, req, status, compressed,
                             (uint32_t)csize + 5U);
      free(compressed);
      return rc;
    }
    free(compressed);
  }

  /* Compression was not worthwhile: avoid allocating and copying a raw frame. */
  memdbg_response_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = MEMDBG_PACKET_MAGIC;
  hdr.version = MEMDBG_PROTOCOL_VERSION;
  hdr.command = req != NULL ? req->command : 0U;
  hdr.request_id = req != NULL ? req->request_id : 0U;
  hdr.status = (int32_t)status;
  hdr.length = data_len + 1U;
  return send_raw_framed(fd, &hdr, data, data_len);
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
  } else if (payload_len <= MEMDBG_RESPONSE_COALESCE_MAX) {
    unsigned char frame[sizeof(hdr) + MEMDBG_RESPONSE_COALESCE_MAX];
    memcpy(frame, &hdr, sizeof(hdr));
    memcpy(frame + sizeof(hdr), payload, payload_len);
    if (pal_socket_write_all(fd, frame, sizeof(hdr) + payload_len) < 0)
      return -1;
  } else if (payload_len <= MEMDBG_RESPONSE_HEAP_COALESCE_MAX) {
    size_t frame_len = sizeof(hdr) + (size_t)payload_len;
    unsigned char *frame = (unsigned char *)malloc(frame_len);
    if (frame != NULL) {
      memcpy(frame, &hdr, sizeof(hdr));
      memcpy(frame + sizeof(hdr), payload, payload_len);
      int rc = pal_socket_write_all(fd, frame, frame_len) < 0 ? -1 : 0;
      free(frame);
      return rc;
    }
#if MEMDBG_RESPONSE_CONSOLE
    if (pal_socket_write_all(fd, &hdr, sizeof(hdr)) < 0 ||
        pal_socket_write_all(fd, payload, payload_len) < 0)
      return -1;
#else
    if (pal_socket_writev_all(fd, &hdr, sizeof(hdr),
                              payload, payload_len) < 0) return -1;
#endif
  } else {
#if MEMDBG_RESPONSE_CONSOLE
    /* writev is not consistently safe across PS4/PS5 retail payload libc
       variants. Two bounded writes are preferable to terminating the daemon. */
    if (pal_socket_write_all(fd, &hdr, sizeof(hdr)) < 0 ||
        pal_socket_write_all(fd, payload, payload_len) < 0)
      return -1;
#else
    if (pal_socket_writev_all(fd, &hdr, sizeof(hdr),
                              payload, payload_len) < 0) return -1;
#endif
  }
  return 0;
}
