/*
 * memDBG - ps5debug compat: FlashScan bridge (server-resident scanning).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Maps legacy ps5debug quickscan commands (0xBDAACC08-0xE) to the
 * MemDBG FlashScan engine.  Uses socketpair(2) to capture the native
 * handler output, then forwards it with a bitswapped status prefix.
 *
 * Limitations (by design — the legacy client can't participate in
 * interactive fd reads inside the native handler):
 *   - START with SNAP_SEGMENTS flag     → error (handler reads segments from fd)
 *   - COUNT in non-resident mode        → empty results (handler reads chunks from fd)
 *   - START snapshot path, COUNT resident/snapshot path → fully supported
 */

#include "internal.h"

#include "memdbg/scanner/flashscan.h"

#include <sys/socket.h>

/* ---- Socketpair helpers ---- */

static int flashscan_spawn_pair(socket_t *writer, socket_t *reader) {
  int sp[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) return -1;
  *writer = sp[0];
  *reader = sp[1];
  return 0;
}

/* Read all remaining bytes from a socketpair reader into a malloc'd buffer.
 * Max 64 MiB to prevent runaway allocation.  Returns buffer + length, or
 * NULL / 0 on error.  Caller must free the buffer. */
static uint8_t *flashscan_read_remaining(socket_t reader, uint32_t *out_len) {
  uint8_t *buf = NULL;
  uint32_t cap = 0U, len = 0U;
  uint8_t  chunk[65536U];
  ssize_t  n;

  *out_len = 0U;
  for (;;) {
    n = recv(reader, chunk, sizeof(chunk), 0);
    if (n <= 0) break;
    if (len + (uint32_t)n > (64U << 20)) { free(buf); return NULL; }
    if (len + (uint32_t)n > cap) {
      uint32_t new_cap = cap != 0U ? cap * 2U : 65536U;
      if (new_cap < len + (uint32_t)n) new_cap = len + (uint32_t)n + 65536U;
      uint8_t *nb = (uint8_t *)realloc(buf, new_cap);
      if (nb == NULL) { free(buf); return NULL; }
      buf = nb; cap = new_cap;
    }
    memcpy(buf + len, chunk, (size_t)n);
    len += (uint32_t)n;
  }
  *out_len = len;
  return buf;
}

/* Read a native int32 status from the socketpair reader.
 * Returns 0 on success, -1 on read error. */
static int flashscan_read_native_status(socket_t reader, int32_t *status) {
  if (pal_socket_read_exact(reader, status, 4) < 0)
    return -1;
  return 0;
}

/* Send the legacy response: bitswapped status + optional payload.
 * The caller owns payload and must free it after this returns. */
static memdbg_status_t flashscan_send_legacy(socket_t fd, uint32_t legacy_status,
                                             const uint8_t *payload, uint32_t plen) {
  int rc = legacy_send_status(fd, legacy_status);
  if (rc != 0) return MEMDBG_ERR_NET;
  if (plen > 0U && payload != NULL) {
    rc = legacy_send_blob(fd, payload, plen);
    if (rc != 0) return MEMDBG_ERR_NET;
  }
  return MEMDBG_OK;
}

/*
 * Common socketpair dispatch pattern (see per-handler implementations below).
 *
 * NOTE: The socketpair approach cannot support FlashScan paths that read
 * interactively from the fd (SNAP_SEGMENTS, non-resident COUNT).
 * Those are explicitly rejected or documented as limitations.
 */

/* ---- CAPS ---- */

memdbg_status_t legacy_handle_quickscan_caps(socket_t fd) {
  socket_t writer = PAL_INVALID_SOCKET;
  socket_t reader = PAL_INVALID_SOCKET;
  int32_t nstatus = -1;
  uint8_t *payload = NULL;
  uint32_t plen = 0U;

  if (flashscan_spawn_pair(&writer, &reader) < 0)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  (void)flashscan_handle_caps(writer);
  (void)pal_socket_close(writer);

  if (flashscan_read_native_status(reader, &nstatus) < 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (nstatus != 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  payload = flashscan_read_remaining(reader, &plen);
  (void)pal_socket_close(reader);

  {
    memdbg_status_t ret = flashscan_send_legacy(fd, LEGACY_CMD_SUCCESS,
                                                payload, plen);
    free(payload);
    return ret;
  }
}

/* ---- CONFIG ---- */

memdbg_status_t legacy_handle_quickscan_config(socket_t fd,
                                               const void *body,
                                               uint32_t body_len) {
  if (body == NULL || body_len < sizeof(memdbg_quickscan_config_request_t))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  const memdbg_quickscan_config_request_t *lr =
      (const memdbg_quickscan_config_request_t *)body;

  uint32_t path_len = lr->spill_path_len;
  const uint8_t *extra = NULL;
  if (path_len > 0U) {
    uint32_t off = (uint32_t)sizeof(*lr);
    if (off + path_len <= body_len)
      extra = (const uint8_t *)body + off;
    else
      path_len = 0U;
  }

  socket_t writer = PAL_INVALID_SOCKET;
  socket_t reader = PAL_INVALID_SOCKET;
  int32_t nstatus = -1;

  if (flashscan_spawn_pair(&writer, &reader) < 0)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  (void)flashscan_handle_config(writer, lr, extra, path_len);
  (void)pal_socket_close(writer);

  if (flashscan_read_native_status(reader, &nstatus) < 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  (void)pal_socket_close(reader);

  if (nstatus != 0)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0
             ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- REGIONS ---- */

memdbg_status_t legacy_handle_quickscan_regions(socket_t fd,
                                                const void *body,
                                                uint32_t body_len) {
  if (body == NULL || body_len < sizeof(memdbg_quickscan_regions_request_t))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  const memdbg_quickscan_regions_request_t *lr =
      (const memdbg_quickscan_regions_request_t *)body;

  socket_t writer = PAL_INVALID_SOCKET;
  socket_t reader = PAL_INVALID_SOCKET;
  int32_t nstatus = -1;
  uint8_t *payload = NULL;
  uint32_t plen = 0U;

  if (flashscan_spawn_pair(&writer, &reader) < 0)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  (void)flashscan_handle_regions(writer, lr);
  (void)pal_socket_close(writer);

  if (flashscan_read_native_status(reader, &nstatus) < 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (nstatus != 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  payload = flashscan_read_remaining(reader, &plen);
  (void)pal_socket_close(reader);

  {
    memdbg_status_t ret = flashscan_send_legacy(fd, LEGACY_CMD_SUCCESS,
                                                payload, plen);
    free(payload);
    return ret;
  }
}

/* ---- START ---- */

memdbg_status_t legacy_handle_quickscan_start(socket_t fd,
                                              const void *body,
                                              uint32_t body_len) {
  if (body == NULL || body_len < sizeof(memdbg_quickscan_start_request_t))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  const memdbg_quickscan_start_request_t *lr =
      (const memdbg_quickscan_start_request_t *)body;

  /* Reject SNAP_SEGMENTS — the handler reads segments interactively from fd. */
  if (lr->request_flags & MEMDBG_QS_FL_SNAP_SEGMENTS)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  uint32_t data_off = (uint32_t)sizeof(*lr);
  uint32_t data_len = lr->value_length;
  int is_between    = (lr->compare_type == 4);

  const uint8_t *cmp_data = NULL;
  const uint8_t *qs_mask  = NULL;

  if (data_len > 0U) {
    uint32_t need = data_off + data_len * (is_between ? 2U : 1U);
    if (need <= body_len)
      cmp_data = (const uint8_t *)body + data_off;
  }

  /* AOB mask follows compare data (value_type == 10) */
  if (lr->value_type == 10U && cmp_data != NULL) {
    uint32_t moff = data_off + data_len * (is_between ? 2U : 1U);
    if (moff + data_len <= body_len)
      qs_mask = (const uint8_t *)body + moff;
  }

  socket_t writer = PAL_INVALID_SOCKET;
  socket_t reader = PAL_INVALID_SOCKET;
  int32_t nstatus = -1;
  uint8_t *payload = NULL;
  uint32_t plen = 0U;

  if (flashscan_spawn_pair(&writer, &reader) < 0)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  (void)flashscan_handle_start(writer, lr, cmp_data, qs_mask, 0U);
  (void)pal_socket_close(writer);

  if (flashscan_read_native_status(reader, &nstatus) < 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (nstatus != 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  payload = flashscan_read_remaining(reader, &plen);
  (void)pal_socket_close(reader);

  {
    memdbg_status_t ret = flashscan_send_legacy(fd, LEGACY_CMD_SUCCESS,
                                                payload, plen);
    free(payload);
    return ret;
  }
}

/* ---- COUNT ---- */

memdbg_status_t legacy_handle_quickscan_count(socket_t fd,
                                              const void *body,
                                              uint32_t body_len) {
  if (body == NULL || body_len < sizeof(memdbg_quickscan_count_request_t))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  const memdbg_quickscan_count_request_t *lr =
      (const memdbg_quickscan_count_request_t *)body;

  uint32_t d_off = (uint32_t)sizeof(*lr);
  uint32_t d_len = lr->value_length;

  const uint8_t *cmp_d = NULL;
  const uint8_t *qc_mask = NULL;

  if (d_len > 0U && d_off + d_len <= body_len)
    cmp_d = (const uint8_t *)body + d_off;

  if (lr->value_type == 10U && cmp_d != NULL) {
    uint32_t mo = d_off + d_len;
    if (mo + d_len <= body_len)
      qc_mask = (const uint8_t *)body + mo;
  }

  socket_t writer = PAL_INVALID_SOCKET;
  socket_t reader = PAL_INVALID_SOCKET;
  int32_t nstatus = -1;
  uint8_t *payload = NULL;
  uint32_t plen = 0U;

  if (flashscan_spawn_pair(&writer, &reader) < 0)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  (void)flashscan_handle_count(writer, lr, cmp_d, qc_mask, 0U);
  (void)pal_socket_close(writer);

  if (flashscan_read_native_status(reader, &nstatus) < 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (nstatus != 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  payload = flashscan_read_remaining(reader, &plen);
  (void)pal_socket_close(reader);

  {
    memdbg_status_t ret = flashscan_send_legacy(fd, LEGACY_CMD_SUCCESS,
                                                payload, plen);
    free(payload);
    return ret;
  }
}

/* ---- FETCH ---- */

memdbg_status_t legacy_handle_quickscan_fetch(socket_t fd,
                                              const void *body,
                                              uint32_t body_len) {
  if (body == NULL || body_len < sizeof(memdbg_quickscan_fetch_request_t))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  const memdbg_quickscan_fetch_request_t *lr =
      (const memdbg_quickscan_fetch_request_t *)body;

  socket_t writer = PAL_INVALID_SOCKET;
  socket_t reader = PAL_INVALID_SOCKET;
  int32_t nstatus = -1;
  uint8_t *payload = NULL;
  uint32_t plen = 0U;

  if (flashscan_spawn_pair(&writer, &reader) < 0)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  (void)flashscan_handle_fetch(writer, lr, 0U);
  (void)pal_socket_close(writer);

  if (flashscan_read_native_status(reader, &nstatus) < 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (nstatus != 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  payload = flashscan_read_remaining(reader, &plen);
  (void)pal_socket_close(reader);

  {
    memdbg_status_t ret = flashscan_send_legacy(fd, LEGACY_CMD_SUCCESS,
                                                payload, plen);
    free(payload);
    return ret;
  }
}

/* ---- END ---- */

memdbg_status_t legacy_handle_quickscan_end(socket_t fd) {
  socket_t writer = PAL_INVALID_SOCKET;
  socket_t reader = PAL_INVALID_SOCKET;
  int32_t nstatus = -1;

  if (flashscan_spawn_pair(&writer, &reader) < 0)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  (void)flashscan_handle_end(writer, 0U);
  (void)pal_socket_close(writer);

  if (flashscan_read_native_status(reader, &nstatus) < 0) {
    (void)pal_socket_close(reader);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  (void)pal_socket_close(reader);

  if (nstatus != 0)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;

  return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0
             ? MEMDBG_OK : MEMDBG_ERR_NET;
}
