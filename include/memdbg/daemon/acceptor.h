/*
 * memDBG - Daemon acceptor / listener setup.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from memdbg.c.
 */

#ifndef MEMDBG_DAEMON_ACCEPTOR_H
#define MEMDBG_DAEMON_ACCEPTOR_H

#include "memdbg/core/memdbg.h"
#include "memdbg/daemon/thread_pool.h"
#include "memdbg/pal/pal_network.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  ACCEPTOR_EXIT_STOP_REQUESTED,   /* daemon shutting down normally */
  ACCEPTOR_EXIT_LISTENER_LOST     /* socket invalidated (rest mode / kernel reclaim) */
} acceptor_exit_reason_t;

memdbg_status_t open_debug_listener(const memdbg_config_t *cfg,
                                    socket_t *listen_fd);

int acceptor_start(const memdbg_config_t *cfg, socket_t listen_fd,
                   memdbg_thread_pool_t *pool, pthread_t *out_tid,
                   acceptor_exit_reason_t *exit_reason);

/* Wake all connection handlers during daemon replacement.  shutdown(2) is
 * used rather than close(2), so each handler retains ownership of its fd and
 * can perform normal cleanup without an fd-reuse race. */
void acceptor_shutdown_clients(void);
void acceptor_unregister_client(socket_t fd);

/* Group native sockets by the optional HELLO session identity.  The first
 * successfully negotiated socket emits the console notification; Memory,
 * Scan and Poll sockets only increase the session reference count. */
void acceptor_register_hello_session(socket_t fd, uint64_t session_id,
                                     uint32_t *session_cookie);
void acceptor_unregister_hello_session(uint32_t session_cookie);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DAEMON_ACCEPTOR_H */
