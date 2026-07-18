/*
 * memDBG - ps5debug compat: kernel bridge.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "internal.h"
#include "memdbg/pal/pal_kernel.h"

memdbg_status_t legacy_handle_kern_base(socket_t fd) {
  if (!pal_kernel_supported())
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  uint64_t text_base = 0U, data_base = 0U;
  memdbg_status_t st = pal_kernel_base(&text_base, &data_base);
  if (st != MEMDBG_OK) return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  (void)text_base;
  return (legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 &&
          legacy_send_blob(fd, &data_base, sizeof(data_base)) == 0)
             ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_kern_read(socket_t fd, const memdbg_config_t *cfg, const void *body, uint32_t body_len) {
  if (!pal_kernel_supported()) return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  if (!legacy_has_body(body, body_len, sizeof(legacy_kernel_memory_request_t))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  const legacy_kernel_memory_request_t *req = (const legacy_kernel_memory_request_t *)body;
  if (req->length == 0U || !legacy_rw_allowed(cfg, req->length)) return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  uint8_t *buf = (uint8_t *)malloc(req->length);
  if (buf == NULL) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  memdbg_status_t st = pal_kernel_read(req->address, buf, req->length);
  if (st != MEMDBG_OK) { free(buf); return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }
  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0) { free(buf); return MEMDBG_ERR_NET; }
  int rc = legacy_send_blob(fd, buf, req->length); free(buf);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_kern_write(socket_t fd, const memdbg_config_t *cfg, const void *body, uint32_t body_len) {
  if (!pal_kernel_supported()) return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  if (!legacy_has_body(body, body_len, sizeof(legacy_kernel_memory_request_t))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  const legacy_kernel_memory_request_t *req = (const legacy_kernel_memory_request_t *)body;
  if (req->length == 0U || !legacy_rw_allowed(cfg, req->length)) return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  uint8_t *buffer = (uint8_t *)malloc(req->length);
  if (buffer == NULL) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0) { free(buffer); return MEMDBG_ERR_NET; }
  if (pal_socket_read_exact(fd, buffer, req->length) < 0) { free(buffer); return MEMDBG_ERR_NET; }
  memdbg_status_t st = pal_kernel_write(req->address, buffer, req->length);
  free(buffer);
  return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}
