/*
 * memDBG - Portable I/O wait primitive (epoll/kqueue/select abstraction).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Abstracts the platform-specific wait-for-readability call so that the
 * daemon and unit tests can share the same code path.  Exported from the
 * static daemon internals so it can be tested directly.
 */

#ifndef MEMDBG_PAL_PAL_WAIT_H
#define MEMDBG_PAL_PAL_WAIT_H

#include "memdbg/pal/pal_network.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Fast enough for interactive connection setup without allocating console
 * kernel wait objects thousands of times per second. */
#define MEMDBG_ACCEPT_POLL_MS 10

/**
 * wait_for_client - Wait until a socket is readable or a timeout expires.
 * @fd:         The socket to monitor (listen or client fd).
 * @timeout_ms: Timeout in milliseconds.  0 means non-blocking poll.
 *
 * Return values:
 *   1  -> Data is available to read (or a new connection can be accept()ed).
 *   0  -> Timeout expired — no data within @timeout_ms.
 *  -1  -> Error (EPOLLERR, EV_ERROR, EV_EOF, or kevent/select failure).
 *         Check errno for details.
 */
int wait_for_client(socket_t fd, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PAL_PAL_WAIT_H */
