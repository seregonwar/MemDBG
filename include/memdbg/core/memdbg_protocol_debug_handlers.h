/*
 * memDBG - Debugger protocol handlers (shared between daemon and tests).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Declarations for the handle_debug_* functions.
 * Implementations live in src/core/daemon/handlers_debug.c.
 * Include this header to get the declarations without pulling in
 * function bodies (formerly static inline, now compiled once).
 */

#ifndef MEMDBG_CORE_MEMDBG_PROTOCOL_DEBUG_HANDLERS_H
#define MEMDBG_CORE_MEMDBG_PROTOCOL_DEBUG_HANDLERS_H

#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/pal/pal_debug.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Debugger attach / detach ---- */

memdbg_status_t handle_debug_attach(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_detach(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_stop(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_continue(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_step(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

/* ---- Thread list ---- */

memdbg_status_t handle_debug_get_threads(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

/* ---- General-purpose registers ---- */

memdbg_status_t handle_debug_get_regs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_set_regs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

/* ---- Debug registers ---- */

memdbg_status_t handle_debug_get_dbregs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_set_dbregs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

/* ---- FPU/YMM registers ---- */

memdbg_status_t handle_debug_get_fpregs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_set_fpregs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

/* ---- FS/GS base ---- */

memdbg_status_t handle_debug_get_fsgsbase(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_set_fsgsbase(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

/* ---- Breakpoints ---- */

memdbg_status_t handle_debug_set_breakpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_set_breakpoint_cond(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_clear_breakpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

/* ---- Watchpoints ---- */

memdbg_status_t handle_debug_set_watchpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_clear_watchpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

/* ---- Thread control ---- */

memdbg_status_t handle_debug_thread_control(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len, bool suspend,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

/* ---- Poll events ---- */

memdbg_status_t handle_debug_poll_events(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

/* ---- Breakpoint / watchpoint list queries ---- */

memdbg_status_t handle_debug_get_breakpoints(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_get_watchpoints(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

/* ---- Batch clear ---- */

memdbg_status_t handle_debug_clear_all_breakpoints(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

memdbg_status_t handle_debug_clear_all_watchpoints(int fd,
    const memdbg_packet_header_t *req,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t));

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_PROTOCOL_DEBUG_HANDLERS_H */
