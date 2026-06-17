/*
 * memDBG - Debugger protocol handlers (shared between payload and tests).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This header contains the handle_debug_* functions that are used by both
 * src/core/memdbg.c (production) and tests/test_debugger_protocol.c (testing).
 * Include this header in both files to prevent handler drift.
 *
 * The handlers are declared as 'static inline' so each translation unit gets
 * its own copy (no linker conflicts) while keeping them visible to the test.
 */

#ifndef MEMDBG_CORE_MEMDBG_PROTOCOL_DEBUG_HANDLERS_H
#define MEMDBG_CORE_MEMDBG_PROTOCOL_DEBUG_HANDLERS_H

#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/debug/memdbg_debugger.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Debugger attach / detach ---- */

static inline memdbg_status_t handle_debug_attach(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_attach_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_attach_request_t *ar =
      (const memdbg_debug_attach_request_t *)body;
  memdbg_status_t st = memdbg_debugger_attach(ar->pid);
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static inline memdbg_status_t handle_debug_detach(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  memdbg_status_t st = memdbg_debugger_detach();
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static inline memdbg_status_t handle_debug_stop(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  memdbg_status_t st = memdbg_debugger_stop();
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static inline memdbg_status_t handle_debug_continue(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  memdbg_status_t st = memdbg_debugger_continue();
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static inline memdbg_status_t handle_debug_step(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_thread_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_thread_request_t *tr =
      (const memdbg_debug_thread_request_t *)body;
  memdbg_status_t st = memdbg_debugger_step(tr->lwp);
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Thread list ---- */

static inline memdbg_status_t handle_debug_get_threads(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  int32_t lwps[MEMDBG_DEBUGGER_MAX_THREADS];
  char names[MEMDBG_DEBUGGER_MAX_THREADS][24];
  uint32_t count = 0;
  memdbg_status_t st = memdbg_debugger_get_threads(lwps, names, &count,
                                                   MEMDBG_DEBUGGER_MAX_THREADS);
  if (st != MEMDBG_OK)
    return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;

  uint32_t payload_len = (uint32_t)(sizeof(memdbg_debug_threads_response_prefix_t) +
                         count * sizeof(memdbg_debug_thread_entry_t));
  uint8_t *payload = (uint8_t *)malloc(payload_len);
  if (payload == NULL) return MEMDBG_ERR_NOMEM;

  memdbg_debug_threads_response_prefix_t *prefix =
      (memdbg_debug_threads_response_prefix_t *)payload;
  prefix->count = count;
  prefix->reserved = 0;

  memdbg_debug_thread_entry_t *entries =
      (memdbg_debug_thread_entry_t *)(payload + sizeof(*prefix));
  for (uint32_t i = 0; i < count; ++i) {
    entries[i].lwp = lwps[i];
    memcpy(entries[i].name, names[i], sizeof(entries[i].name));
  }

  int rc = send_response_fn(fd, req, MEMDBG_OK, payload, payload_len);
  free(payload);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- General-purpose registers ---- */

static inline memdbg_status_t handle_debug_get_regs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_thread_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_thread_request_t *tr =
      (const memdbg_debug_thread_request_t *)body;
  memdbg_debug_regs_t regs;
  memset(&regs, 0, sizeof(regs));
  memdbg_status_t st = memdbg_debugger_get_regs(tr->lwp, &regs);
  return send_response_fn(fd, req, st, &regs, sizeof(regs)) == 0 ? MEMDBG_OK
                                                                   : MEMDBG_ERR_NET;
}

static inline memdbg_status_t handle_debug_set_regs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_thread_request_t) + sizeof(memdbg_debug_regs_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_thread_request_t *tr =
      (const memdbg_debug_thread_request_t *)body;
  const memdbg_debug_regs_t *regs =
      (const memdbg_debug_regs_t *)((const uint8_t *)body + sizeof(*tr));
  memdbg_status_t st = memdbg_debugger_set_regs(tr->lwp, regs);
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Debug registers ---- */

static inline memdbg_status_t handle_debug_get_dbregs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_thread_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_thread_request_t *tr =
      (const memdbg_debug_thread_request_t *)body;
  memdbg_debug_dbregs_t dbregs;
  memset(&dbregs, 0, sizeof(dbregs));
  memdbg_status_t st = memdbg_debugger_get_dbregs(tr->lwp, &dbregs);
  return send_response_fn(fd, req, st, &dbregs, sizeof(dbregs)) == 0 ? MEMDBG_OK
                                                                      : MEMDBG_ERR_NET;
}

static inline memdbg_status_t handle_debug_set_dbregs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_thread_request_t) + sizeof(memdbg_debug_dbregs_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_thread_request_t *tr =
      (const memdbg_debug_thread_request_t *)body;
  const memdbg_debug_dbregs_t *dbregs =
      (const memdbg_debug_dbregs_t *)((const uint8_t *)body + sizeof(*tr));
  memdbg_status_t st = memdbg_debugger_set_dbregs(tr->lwp, dbregs);
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Breakpoints ---- */

static inline memdbg_status_t handle_debug_set_breakpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_breakpoint_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_breakpoint_request_t *bp =
      (const memdbg_debug_breakpoint_request_t *)body;
  memdbg_status_t st = memdbg_debugger_set_breakpoint(bp->address, bp->kind);
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static inline memdbg_status_t handle_debug_set_breakpoint_cond(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_breakpoint_cond_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_breakpoint_cond_request_t *bp =
      (const memdbg_debug_breakpoint_cond_request_t *)body;
  memdbg_status_t st = memdbg_debugger_set_breakpoint_cond(
      bp->address, bp->kind, bp->cond_reg, bp->cond_op, bp->cond_value);
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static inline memdbg_status_t handle_debug_clear_breakpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_breakpoint_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_breakpoint_request_t *bp =
      (const memdbg_debug_breakpoint_request_t *)body;
  memdbg_status_t st = memdbg_debugger_clear_breakpoint(bp->address);
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Watchpoints ---- */

static inline memdbg_status_t handle_debug_set_watchpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_watchpoint_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_watchpoint_request_t *wp =
      (const memdbg_debug_watchpoint_request_t *)body;
  memdbg_status_t st = memdbg_debugger_set_watchpoint(wp->address, wp->length,
                                                      wp->type);
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static inline memdbg_status_t handle_debug_clear_watchpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_watchpoint_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_watchpoint_request_t *wp =
      (const memdbg_debug_watchpoint_request_t *)body;
  memdbg_status_t st = memdbg_debugger_clear_watchpoint(wp->address);
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Thread control ---- */

static inline memdbg_status_t handle_debug_thread_control(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len, bool suspend,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  if (body_len != sizeof(memdbg_debug_thread_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_debug_thread_request_t *tr =
      (const memdbg_debug_thread_request_t *)body;
  memdbg_status_t st = suspend
                           ? memdbg_debugger_suspend_thread(tr->lwp)
                           : memdbg_debugger_resume_thread(tr->lwp);
  return send_response_fn(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Poll events ---- */

static inline memdbg_status_t handle_debug_poll_events(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  memdbg_status_t st = memdbg_debugger_poll_events();
  memdbg_debug_poll_response_t resp;
  memset(&resp, 0, sizeof(resp));
  resp.stopped = memdbg_debugger_is_stopped() ? 1 : 0;
  resp.stop_lwp = memdbg_debugger_is_stopped() ? memdbg_debugger_get_stop_lwp() : 0;
  return send_response_fn(fd, req, st, &resp, sizeof(resp)) == 0 ? MEMDBG_OK
                                                                   : MEMDBG_ERR_NET;
}

/* ---- Breakpoint / watchpoint list queries ---- */

static inline memdbg_status_t handle_debug_get_breakpoints(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  uint32_t count = 0;
  const memdbg_breakpoint_t *bps = memdbg_debugger_breakpoints(&count);

  uint32_t active = 0;
  for (uint32_t i = 0; i < count; ++i) {
    if (bps[i].active) ++active;
  }

  uint32_t payload_len = (uint32_t)(sizeof(memdbg_debug_breakpoint_list_prefix_t) +
                         active * sizeof(memdbg_debug_breakpoint_list_entry_t));
  uint8_t *payload = (uint8_t *)malloc(payload_len);
  if (payload == NULL) return MEMDBG_ERR_NOMEM;

  memdbg_debug_breakpoint_list_prefix_t *prefix =
      (memdbg_debug_breakpoint_list_prefix_t *)payload;
  prefix->count = active;
  prefix->reserved = 0;

  memdbg_debug_breakpoint_list_entry_t *entries =
      (memdbg_debug_breakpoint_list_entry_t *)(payload + sizeof(*prefix));
  uint32_t w = 0;
  for (uint32_t i = 0; i < count && w < active; ++i) {
    if (!bps[i].active) continue;
    entries[w].address = bps[i].address;
    entries[w].kind = bps[i].kind;
    entries[w].flags = 0;
    if (bps[i].installed) entries[w].flags |= 1U;
    if (bps[i].active)    entries[w].flags |= 2U;
    entries[w].cond_reg   = bps[i].cond_reg;
    entries[w].cond_op    = bps[i].cond_op;
    entries[w].cond_value = bps[i].cond_value;
    ++w;
  }

  int rc = send_response_fn(fd, req, MEMDBG_OK, payload, payload_len);
  free(payload);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static inline memdbg_status_t handle_debug_get_watchpoints(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  uint32_t count = 0;
  const memdbg_watchpoint_t *wps = memdbg_debugger_watchpoints(&count);

  uint32_t active = 0;
  for (uint32_t i = 0; i < count; ++i) {
    if (wps[i].installed) ++active;
  }

  uint32_t payload_len =
      (uint32_t)(sizeof(memdbg_debug_watchpoint_list_prefix_t) +
                 active * sizeof(memdbg_debug_watchpoint_list_entry_t));
  uint8_t *payload = (uint8_t *)malloc(payload_len);
  if (payload == NULL) return MEMDBG_ERR_NOMEM;

  memdbg_debug_watchpoint_list_prefix_t *prefix =
      (memdbg_debug_watchpoint_list_prefix_t *)payload;
  prefix->count = active;
  prefix->reserved = 0;

  memdbg_debug_watchpoint_list_entry_t *entries =
      (memdbg_debug_watchpoint_list_entry_t *)(payload + sizeof(*prefix));
  uint32_t w = 0;
  for (uint32_t i = 0; i < count && w < active; ++i) {
    if (!wps[i].installed) continue;
    entries[w].address = wps[i].address;
    entries[w].length  = wps[i].length;
    entries[w].type    = wps[i].type;
    entries[w].slot    = wps[i].slot;
    entries[w].flags   = 1U;
    ++w;
  }

  int rc = send_response_fn(fd, req, MEMDBG_OK, payload, payload_len);
  free(payload);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Batch clear ---- */

static inline memdbg_status_t handle_debug_clear_all_breakpoints(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  uint32_t cleared = 0;
  memdbg_status_t st = memdbg_debugger_clear_all_breakpoints(&cleared);
  memdbg_debug_clear_all_response_t resp;
  resp.cleared = cleared;
  resp.reserved = 0;
  return send_response_fn(fd, req, st, &resp, sizeof(resp)) == 0 ? MEMDBG_OK
                                                                   : MEMDBG_ERR_NET;
}

static inline memdbg_status_t handle_debug_clear_all_watchpoints(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t)) {
  uint32_t cleared = 0;
  memdbg_status_t st = memdbg_debugger_clear_all_watchpoints(&cleared);
  memdbg_debug_clear_all_response_t resp;
  resp.cleared = cleared;
  resp.reserved = 0;
  return send_response_fn(fd, req, st, &resp, sizeof(resp)) == 0 ? MEMDBG_OK
                                                                   : MEMDBG_ERR_NET;
}

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_PROTOCOL_DEBUG_HANDLERS_H */
