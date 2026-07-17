/*
 * memDBG - Tracer protocol handlers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from include/memdbg/core/memdbg_protocol_tracer_handlers.h.
 * Originally static inline; now compiled once as regular functions to
 * reduce compilation duplication across translation units.
 */

#include "memdbg/core/memdbg_protocol_tracer_handlers.h"

#include "memdbg/debug/memdbg_debugger.h"

#include <stdlib.h>
#include <string.h>

memdbg_status_t handle_tracer_attach(
    int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_fn)(int, const memdbg_packet_header_t *,
                   memdbg_status_t, const void *, uint32_t)) {
  (void)fd;
  if (body_len != sizeof(memdbg_tracer_attach_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_tracer_attach_request_t *r =
      (const memdbg_tracer_attach_request_t *)body;
  /* Ensure no debugger is attached; detach is idempotent and atomic.
   * Avoids the TOCTOU between is_attached() and detach(). */
  memdbg_status_t detach_st = memdbg_debugger_detach();
  if (detach_st != MEMDBG_OK)
    return send_fn(fd, req, detach_st, NULL, 0U) == 0 ? MEMDBG_OK
                                                      : MEMDBG_ERR_NET;
  memdbg_status_t st = memdbg_tracer_daemon_start(r->pid, NULL);
  return send_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t handle_tracer_detach(
    int fd,
    const memdbg_packet_header_t *req,
    int (*send_fn)(int, const memdbg_packet_header_t *,
                   memdbg_status_t, const void *, uint32_t)) {
  memdbg_tracer_daemon_stop();
  return send_fn(fd, req, MEMDBG_OK, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t handle_tracer_poll(
    int fd,
    const memdbg_packet_header_t *req,
    int (*send_fn)(int, const memdbg_packet_header_t *,
                   memdbg_status_t, const void *, uint32_t)) {
  memdbg_tracer_event_t *events =
      (memdbg_tracer_event_t *)malloc(
          256 * sizeof(memdbg_tracer_event_t));
  if (events == NULL) return MEMDBG_ERR_NOMEM;

  uint32_t count = memdbg_tracer_daemon_poll_events(events, 256);

  const uint32_t prefix_size =
      (uint32_t)sizeof(memdbg_tracer_poll_response_prefix_t);
  const uint32_t payload_size =
      prefix_size + count * (uint32_t)sizeof(memdbg_tracer_event_t);

  uint8_t *buf = (uint8_t *)malloc(payload_size);
  if (buf == NULL) {
    free(events);
    return MEMDBG_ERR_NOMEM;
  }

  memdbg_tracer_poll_response_prefix_t *pfx =
      (memdbg_tracer_poll_response_prefix_t *)buf;
  pfx->count = count;
  pfx->reserved = 0;
  if (count > 0)
    memcpy(buf + prefix_size, events,
           count * sizeof(memdbg_tracer_event_t));

  free(events);
  memdbg_status_t st =
      send_fn(fd, req, MEMDBG_OK, buf, payload_size) == 0
          ? MEMDBG_OK
          : MEMDBG_ERR_NET;
  free(buf);
  return st;
}

memdbg_status_t handle_tracer_status(
    int fd,
    const memdbg_packet_header_t *req,
    int (*send_fn)(int, const memdbg_packet_header_t *,
                   memdbg_status_t, const void *, uint32_t)) {
  memdbg_tracer_status_response_t st;
  memdbg_tracer_daemon_status(&st);
  return send_fn(fd, req, MEMDBG_OK, &st, sizeof(st)) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}
