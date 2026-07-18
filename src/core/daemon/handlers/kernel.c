/*
 * memDBG - Kernel and console protocol handlers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from src/core/daemon/memdbg.c.
 */

#include "daemon_internal.h"

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/pal/pal_kernel.h"
#include "memdbg/pal/pal_notification.h"
#include <stdlib.h>
#include <string.h>

#if defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
#include <ps4/klog.h>
#elif defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#include <ps5/klog.h>
#include <sys/reboot.h>
#ifndef RB_AUTOBOOT
#define RB_AUTOBOOT 0
#endif
extern int reboot(int);
#define MEMDBG_DAEMON_HAS_REBOOT 1
#endif

/* ---- Console text helper ---- */

static memdbg_status_t copy_console_text(const void *body, uint32_t body_len,
                                         char **text_out) {
  if (text_out == NULL) return MEMDBG_ERR_PARAM;
  *text_out = NULL;
  if (body_len < sizeof(memdbg_console_text_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_console_text_request_t *tr =
      (const memdbg_console_text_request_t *)body;
  if (tr->length > 4096U)
    return MEMDBG_ERR_PARAM;
  if (body_len != sizeof(*tr) + tr->length)
    return MEMDBG_ERR_PROTOCOL;
  char *text = (char *)malloc((size_t)tr->length + 1U);
  if (text == NULL) return MEMDBG_ERR_NOMEM;
  memcpy(text, (const uint8_t *)body + sizeof(*tr), tr->length);
  text[tr->length] = '\0';
  *text_out = text;
  return MEMDBG_OK;
}

/* ---- CONSOLE ---- */

memdbg_status_t handle_console_notify(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len) {
  char *text = NULL;
  memdbg_status_t st = copy_console_text(body, body_len, &text);
  if (st == MEMDBG_OK) {
    pal_notification_send(text);
    free(text);
  }
  return send_response(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK
                                                   : MEMDBG_ERR_NET;
}

memdbg_status_t handle_console_print(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len) {
  char *text = NULL;
  memdbg_status_t st = copy_console_text(body, body_len, &text);
  if (st == MEMDBG_OK) {
#if defined(PLATFORM_PS4) || defined(PLATFORM_PS5) || defined(PS4) ||          \
    defined(PS5) || defined(__ORBIS__) || defined(__PROSPERO__)
    (void)klog_puts(text);
#else
    memdbg_log_write(MEMDBG_LOG_INFO, "console: %s", text);
#endif
    free(text);
  }
  return send_response(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK
                                                   : MEMDBG_ERR_NET;
}

memdbg_status_t handle_console_reboot(int fd,
    const memdbg_packet_header_t *req) {
#if defined(MEMDBG_DAEMON_HAS_REBOOT)
  memdbg_status_t st = reboot(RB_AUTOBOOT) == 0 ? MEMDBG_OK : MEMDBG_ERR_IO;
#else
  memdbg_status_t st = MEMDBG_ERR_UNSUPPORTED;
#endif
  return send_response(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK
                                                   : MEMDBG_ERR_NET;
}

/* ---- KERNEL ---- */

memdbg_status_t handle_kernel_base(int fd,
    const memdbg_packet_header_t *req) {
  memdbg_kernel_base_response_t resp;
  memset(&resp, 0, sizeof(resp));
  uint64_t text_base = 0U;
  uint64_t data_base = 0U;
  memdbg_status_t st = pal_kernel_base(&text_base, &data_base);
  resp.text_base = text_base;
  resp.data_base = data_base;
  return send_response(fd, req, st, st == MEMDBG_OK ? &resp : NULL,
                       st == MEMDBG_OK ? (uint32_t)sizeof(resp) : 0U) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}

memdbg_status_t handle_kernel_read(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_kernel_memory_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_kernel_memory_request_t *kr =
      (const memdbg_kernel_memory_request_t *)body;
  if (kr->address == 0U || kr->length > MEMDBG_PROTOCOL_MAX_READ)
    return MEMDBG_ERR_PARAM;

  /* Validate address against known kernel ranges to avoid page faults. */
  uint64_t text_base = 0U, data_base = 0U;
  if (pal_kernel_base(&text_base, &data_base) == MEMDBG_OK) {
    static const uint64_t kKernelMaxRange = 64ULL * 1024ULL * 1024ULL;
    uint64_t end = kr->address + (uint64_t)kr->length;
    bool in_text = (kr->address >= text_base && end <= text_base + kKernelMaxRange);
    bool in_data = (kr->address >= data_base && end <= data_base + kKernelMaxRange);
    if (!in_text && !in_data)
      return MEMDBG_ERR_PARAM;
  }

  uint8_t *buffer = (uint8_t *)malloc(kr->length == 0U ? 1U : kr->length);
  if (buffer == NULL) return MEMDBG_ERR_NOMEM;
  memdbg_status_t st = pal_kernel_read(kr->address, buffer, kr->length);
  int rc = send_response(fd, req, st, st == MEMDBG_OK ? buffer : NULL,
                         st == MEMDBG_OK ? kr->length : 0U);
  free(buffer);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t handle_kernel_write(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len) {
  if (body_len < sizeof(memdbg_kernel_memory_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_kernel_memory_request_t *kw =
      (const memdbg_kernel_memory_request_t *)body;
  if (kw->address == 0U || kw->length > MEMDBG_PROTOCOL_MAX_READ)
    return MEMDBG_ERR_PARAM;
  if (body_len != sizeof(*kw) + kw->length)
    return MEMDBG_ERR_PROTOCOL;

  /* Same bounds validation as handle_kernel_read. */
  uint64_t text_base = 0U, data_base = 0U;
  if (pal_kernel_base(&text_base, &data_base) == MEMDBG_OK) {
    static const uint64_t kKernelMaxRange = 64ULL * 1024ULL * 1024ULL;
    uint64_t end = kw->address + (uint64_t)kw->length;
    bool in_text = (kw->address >= text_base && end <= text_base + kKernelMaxRange);
    bool in_data = (kw->address >= data_base && end <= data_base + kKernelMaxRange);
    if (!in_text && !in_data)
      return MEMDBG_ERR_PARAM;
  }

  const uint8_t *data = (const uint8_t *)body + sizeof(*kw);
  memdbg_status_t st = pal_kernel_write(kw->address, data, kw->length);
  return send_response(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK
                                                   : MEMDBG_ERR_NET;
}
