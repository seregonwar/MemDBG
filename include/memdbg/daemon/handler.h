/*
 * memDBG - Per-connection protocol handler.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from memdbg.c so that handle_client() can be tested directly.
 */

#ifndef MEMDBG_DAEMON_HANDLER_H
#define MEMDBG_DAEMON_HANDLER_H

#include "memdbg/core/memdbg.h"
#include "memdbg/pal/pal_network.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Arguments passed to a per-connection handler thread.
 * Heap-allocated by the acceptor and freed by the handler. */
typedef struct {
  socket_t       client_fd;
  memdbg_config_t cfg;  /* copy — owned by this thread */
} connection_args_t;

/**
 * handle_client - Process all requests on a single client connection.
 * @fd:  The connected client socket.
 * @cfg: Daemon configuration (idle timeout, max packet, etc.).
 *
 * Runs in a dedicated detached thread.  Reads and dispatches protocol
 * requests in a loop until the client disconnects, an idle timeout
 * fires, or the daemon is asked to stop.
 *
 * NOTE: g_active_connections must already be incremented by the caller
 * (the acceptor thread) before calling this function.  This function
 * decrements it on exit.
 */
void handle_client(socket_t fd, const memdbg_config_t *cfg);

/**
 * connection_handler_thread - pthread entry point for a client handler.
 * @arg: Pointer to a heap-allocated connection_args_t (freed internally).
 *
 * Extracts the client fd and config, then calls handle_client().
 */
void *connection_handler_thread(void *arg);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DAEMON_HANDLER_H */
