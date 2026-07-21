/*
 * memDBG - Process protocol handlers (shared between daemon and tests).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Declaration for handle_process_call.
 * Implementation lives in src/core/daemon/handlers_process.c.
 * Include this header to get the declaration without pulling in
 * the function body (formerly static inline, now compiled once).
 */

#ifndef MEMDBG_CORE_MEMDBG_PROTOCOL_PROCESS_HANDLERS_H
#define MEMDBG_CORE_MEMDBG_PROTOCOL_PROCESS_HANDLERS_H

#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/debug/debugger.h"
#include "memdbg/pal/pal_memory.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Remote function call (ptrace trampoline) ---- */

memdbg_status_t handle_process_call(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    int (*send_response_fn)(int, const memdbg_packet_header_t *,
                            memdbg_status_t, const void *, uint32_t),
    void (*sleep_ms_fn)(uint32_t));

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_PROTOCOL_PROCESS_HANDLERS_H */
