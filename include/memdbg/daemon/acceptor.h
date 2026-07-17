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
#include "memdbg/pal/pal_network.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

memdbg_status_t open_debug_listener(const memdbg_config_t *cfg,
                                    socket_t *listen_fd);

int acceptor_start(const memdbg_config_t *cfg, socket_t listen_fd,
                   pthread_t *out_tid);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DAEMON_ACCEPTOR_H */
