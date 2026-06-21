/*
 * memDBG - Tracer protocol handlers (shared between daemon and tests).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Static-inline handler functions for MEMDBG_CMD_TRACER_* commands.
 * Included by both src/core/daemon/memdbg.c and test files so the
 * protocol logic stays in sync.
 */

#ifndef MEMDBG_CORE_MEMDBG_PROTOCOL_TRACER_HANDLERS_H
#define MEMDBG_CORE_MEMDBG_PROTOCOL_TRACER_HANDLERS_H

#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/tracer/memdbg_tracer_daemon.h"

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- TRACER_ATTACH ---- */

static inline memdbg_status_t handle_tracer_attach(
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
  /* Only one subsystem may own ptrace for a target.  Release an existing
   * debugger session first instead of leaving the tracer to fail with
   * EALREADY. */
  if (memdbg_debugger_is_attached()) {
    memdbg_status_t detach_st = memdbg_debugger_detach();
    if (detach_st != MEMDBG_OK)
      return send_fn(fd, req, detach_st, NULL, 0U) == 0 ? MEMDBG_OK
                                                        : MEMDBG_ERR_NET;
  }
  /* Default dump path is empty — daemon will auto-name it. */
  memdbg_status_t st = memdbg_tracer_daemon_start(r->pid, NULL);
  return send_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- TRACER_DETACH ---- */

static inline memdbg_status_t handle_tracer_detach(
    int fd,
    const memdbg_packet_header_t *req,
    int (*send_fn)(int, const memdbg_packet_header_t *,
                   memdbg_status_t, const void *, uint32_t)) {
  memdbg_tracer_daemon_stop();
  return send_fn(fd, req, MEMDBG_OK, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- TRACER_POLL ---- */

static inline memdbg_status_t handle_tracer_poll(
    int fd,
    const memdbg_packet_header_t *req,
    int (*send_fn)(int, const memdbg_packet_header_t *,
                   memdbg_status_t, const void *, uint32_t)) {
  memdbg_tracer_event_t events[256];
  uint32_t count = memdbg_tracer_daemon_poll_events(events, 256);

  /* Build response: prefix + event records. */
  uint8_t buf[sizeof(memdbg_tracer_poll_response_prefix_t) +
              256 * sizeof(memdbg_tracer_event_t)];
  memdbg_tracer_poll_response_prefix_t *pfx =
      (memdbg_tracer_poll_response_prefix_t *)buf;
  pfx->count = count;
  pfx->reserved = 0;
  if (count > 0)
    memcpy(buf + sizeof(*pfx), events, count * sizeof(memdbg_tracer_event_t));

  return send_fn(fd, req, MEMDBG_OK, buf,
                 sizeof(*pfx) + count * sizeof(memdbg_tracer_event_t)) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}

/* ---- TRACER_STATUS ---- */

static inline memdbg_status_t handle_tracer_status(
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

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_PROTOCOL_TRACER_HANDLERS_H */
