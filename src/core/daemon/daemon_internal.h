/*
 * memDBG - Daemon internal header (shared across daemon source files).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This header declares shared infrastructure and all extracted protocol
 * handlers so that dispatch.c and the handler source files can reference
 * them without pulling in the full memdbg.c.
 */

#ifndef MEMDBG_DAEMON_INTERNAL_H
#define MEMDBG_DAEMON_INTERNAL_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Shared constants ---- */

#include "memdbg/pal/pal_wait.h"

/* Dynamic thread model: connections are served by on-demand threads.
 * The acceptor thread spawns a handler per connection up to max_connections.
 * RESP_POOL_COUNT is sized to match the default connection cap to avoid
 * contention on the pre-allocated response buffer ring. */
#define MEMDBG_DEFAULT_MAX_CONNECTIONS   64
#define MEMDBG_DEFAULT_IDLE_TIMEOUT_MS   30000
#define MEMDBG_RESP_POOL_COUNT           64
#define MEMDBG_RESP_POOL_SIZE            (256U * 1024U)

/* ---- Common type aliases ---- */

typedef int (*memdbg_send_response_fn)(int fd,
    const memdbg_packet_header_t *req, memdbg_status_t status,
    const void *payload, uint32_t payload_len);

/* ---- Shared infrastructure (defined in response.c) ---- */

int send_response(int fd, const memdbg_packet_header_t *req,
                  memdbg_status_t status, const void *payload,
                  uint32_t payload_len);

int send_framed_response(int fd, const memdbg_packet_header_t *req,
                         memdbg_status_t status, const void *data,
                         uint32_t data_len);

memdbg_status_t build_framed_payload(const void *data, uint32_t data_len,
                                     unsigned char **out, uint32_t *out_len);

/* ---- Zero-copy buffer pool (defined in response.c) ---- */
void            resp_pool_init(void);
void            resp_pool_fini(void);
unsigned char  *resp_pool_acquire(size_t needed, size_t *out_size);

/* ---- Acceptor / listener (defined in acceptor.c) ---- */

memdbg_status_t open_debug_listener(const memdbg_config_t *cfg,
                                    socket_t *listen_fd);

int acceptor_start(const memdbg_config_t *cfg, socket_t listen_fd,
                   pthread_t *out_tid);

/* daemon_sleep_ms is now memdbg_sleep_ms (include pal_time.h) */

uint64_t monotonic_seconds(void);

/* ---- Legacy wire compatibility service (defined in legacy/server.c) ---- */

memdbg_status_t memdbg_legacy_start(const memdbg_config_t *cfg);
void            memdbg_legacy_stop(void);

/* ---- Shared globals (defined in memdbg.c) ---- */

extern atomic_uint g_active_connections;
extern uint64_t    g_start_ticks;

/* ---- Dispatch (defined in dispatch.c) ---- */

memdbg_status_t dispatch_packet(int fd, const memdbg_config_t *cfg,
                                const memdbg_packet_header_t *req,
                                const void *body);

/* ---- Hello / Telemetry handlers (defined in dispatch.c) ---- */

memdbg_status_t handle_hello(const memdbg_config_t *cfg,
                             memdbg_hello_response_t *out);

memdbg_status_t handle_telemetry(int fd, const memdbg_packet_header_t *req);

/* ---- Process handlers (defined in handlers/process.c) ---- */

memdbg_status_t handle_process_list(int fd, const memdbg_packet_header_t *req);

memdbg_status_t handle_process_maps(int fd, const memdbg_packet_header_t *req,
                                    const void *body, uint32_t body_len);

memdbg_status_t handle_process_info(int fd, const memdbg_packet_header_t *req,
                                    const void *body, uint32_t body_len);

memdbg_status_t handle_batch_process_info(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len);

memdbg_status_t handle_foreground_app(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len);

memdbg_status_t handle_process_control(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len,
    uint32_t expected_action);

/* ---- Memory handlers (defined in handlers/memory.c) ---- */

memdbg_status_t handle_memory_read(int fd, const memdbg_packet_header_t *req,
    const memdbg_config_t *cfg, const void *body, uint32_t body_len);

memdbg_status_t handle_memory_write(int fd, const memdbg_packet_header_t *req,
    const memdbg_config_t *cfg, const void *body, uint32_t body_len);

memdbg_status_t handle_batch_read(int fd, const memdbg_packet_header_t *req,
    const memdbg_config_t *cfg, const void *body, uint32_t body_len);

memdbg_status_t handle_batch_write(int fd, const memdbg_packet_header_t *req,
    const memdbg_config_t *cfg, const void *body, uint32_t body_len);

/* ---- Scan handlers (defined in handlers/scan.c) ---- */

memdbg_status_t handle_scan_exact_v2(int fd, const memdbg_packet_header_t *req,
    const memdbg_config_t *cfg, const void *body, uint32_t body_len);

memdbg_status_t handle_scan_process_exact(int fd,
    const memdbg_packet_header_t *req,
    const memdbg_config_t *cfg, const void *body, uint32_t body_len);

memdbg_status_t handle_scan_aob(int fd, const memdbg_packet_header_t *req,
    const memdbg_config_t *cfg, const void *body, uint32_t body_len);

memdbg_status_t handle_scan_process_aob(int fd,
    const memdbg_packet_header_t *req,
    const memdbg_config_t *cfg, const void *body, uint32_t body_len);

memdbg_status_t handle_scan_unknown(int fd, const memdbg_packet_header_t *req,
    const memdbg_config_t *cfg, const void *body, uint32_t body_len);
memdbg_status_t handle_scan_unknown_v2(int fd,
    const memdbg_packet_header_t *req, const memdbg_config_t *cfg,
    const void *body, uint32_t body_len);

memdbg_status_t handle_scan_pointer(int fd, const memdbg_packet_header_t *req,
    const memdbg_config_t *cfg, const void *body, uint32_t body_len);

/* ---- Kernel / Console handlers (defined in handlers/kernel.c) ---- */

memdbg_status_t handle_kernel_base(int fd, const memdbg_packet_header_t *req);

memdbg_status_t handle_kernel_read(int fd, const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len);

memdbg_status_t handle_kernel_write(int fd, const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len);

memdbg_status_t handle_console_notify(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len);

memdbg_status_t handle_console_print(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len);

memdbg_status_t handle_console_reboot(int fd,
    const memdbg_packet_header_t *req);

/* ---- Debug handler declarations (defined in handlers/debug.c) ---- */

memdbg_status_t handle_debug_attach(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_detach(int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_stop(int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_continue(int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_step(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_get_threads(int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_get_regs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_set_regs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_get_dbregs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_set_dbregs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_get_fpregs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_set_fpregs(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_get_fsgsbase(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_set_fsgsbase(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_set_breakpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_set_breakpoint_cond(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_clear_breakpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_set_watchpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_clear_watchpoint(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_thread_control(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len, bool suspend,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_poll_events(int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_get_breakpoints(int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_get_watchpoints(int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_clear_all_breakpoints(int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_response_fn);

memdbg_status_t handle_debug_clear_all_watchpoints(int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_response_fn);

/* ---- Tracer handler declarations (defined in handlers/tracer.c) ---- */

memdbg_status_t handle_tracer_attach(
    int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_fn);

memdbg_status_t handle_tracer_detach(
    int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_fn);

memdbg_status_t handle_tracer_poll(
    int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_fn);

memdbg_status_t handle_tracer_status(
    int fd,
    const memdbg_packet_header_t *req,
    memdbg_send_response_fn send_fn);

/* ---- Process-call handler declaration (defined in handlers/process.c) ---- */

memdbg_status_t handle_process_call(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn,
    void (*sleep_ms_fn)(uint32_t));

/* ---- Process protect/alloc/free handlers (defined in handlers/alloc.c) ---- */

memdbg_status_t handle_process_protect(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len);

memdbg_status_t handle_process_alloc(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len);

memdbg_status_t handle_process_free(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len);

memdbg_status_t handle_process_stack(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len);

memdbg_status_t handle_process_elf_load(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len);

/* ---- Process dump handler (defined in handlers/dump.c) ---- */

memdbg_status_t handle_process_dump(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DAEMON_INTERNAL_H */
