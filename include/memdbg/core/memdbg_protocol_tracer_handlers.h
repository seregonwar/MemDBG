/*
 * memDBG - Tracer protocol handlers (shared between daemon and tests).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Declarations for the handle_tracer_* functions.
 * Implementations live in src/core/daemon/handlers_tracer.c.
 * Include this header to get the declarations without pulling in
 * function bodies (formerly static inline, now compiled once).
 */

#ifndef MEMDBG_CORE_MEMDBG_PROTOCOL_TRACER_HANDLERS_H
#define MEMDBG_CORE_MEMDBG_PROTOCOL_TRACER_HANDLERS_H

#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/tracer/memdbg_tracer_daemon.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- TRACER_ATTACH ---- */

memdbg_status_t handle_tracer_attach(
    int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_fn)(int, const memdbg_packet_header_t *,
                   memdbg_status_t, const void *, uint32_t));

/* ---- TRACER_DETACH ---- */

memdbg_status_t handle_tracer_detach(
    int fd,
    const memdbg_packet_header_t *req,
    int (*send_fn)(int, const memdbg_packet_header_t *,
                   memdbg_status_t, const void *, uint32_t));

/* ---- TRACER_POLL ---- */

memdbg_status_t handle_tracer_poll(
    int fd,
    const memdbg_packet_header_t *req,
    int (*send_fn)(int, const memdbg_packet_header_t *,
                   memdbg_status_t, const void *, uint32_t));

/* ---- TRACER_STATUS ---- */

memdbg_status_t handle_tracer_status(
    int fd,
    const memdbg_packet_header_t *req,
    int (*send_fn)(int, const memdbg_packet_header_t *,
                   memdbg_status_t, const void *, uint32_t));

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_PROTOCOL_TRACER_HANDLERS_H */
