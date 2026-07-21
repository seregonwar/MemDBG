/*
 * memDBG - Fixed-size worker thread pool for connection handling.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Replaces the thread-per-connection model (pthread_create + detach)
 * with a bounded pool of pre-created worker threads.  Benefits:
 *   - Predictable resource usage (fixed thread count)
 *   - Graceful shutdown: signal workers, drain pending connections,
 *     join all threads
 *   - Centralised lifetime control — no detached threads to track
 */

#ifndef MEMDBG_DAEMON_THREAD_POOL_H
#define MEMDBG_DAEMON_THREAD_POOL_H

#include "memdbg/daemon/command_handler.h"
#include <pthread.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct memdbg_thread_pool memdbg_thread_pool_t;

/*
 * Create a thread pool with `num_workers` pre-started threads.
 * Returns NULL on allocation failure.
 * Workers immediately enter a dequeue loop; they only become
 * useful once the acceptor starts enqueuing connections.
 */
memdbg_thread_pool_t *memdbg_thread_pool_create(unsigned int num_workers);

/*
 * Enqueue a connection for handling by an available worker.
 * `args` ownership transfers to the pool — it is freed by the
 * worker after connection_handler_thread() returns.
 * Returns 0 on success, -1 if the pool is shutting down.
 */
int memdbg_thread_pool_enqueue(memdbg_thread_pool_t *pool,
                               connection_args_t *args);

/*
 * Signal all workers to finish their current work and exit.
 * Pending queued connections are drained (their fds are closed).
 * Blocks until every worker has joined.
 * Safe to call multiple times; subsequent calls are no-ops.
 */
void memdbg_thread_pool_shutdown(memdbg_thread_pool_t *pool);

/*
 * Destroy the pool, freeing all resources.
 * Must be called after shutdown().
 */
void memdbg_thread_pool_destroy(memdbg_thread_pool_t *pool);

/*
 * Return the number of workers currently active (for diagnostics).
 */
unsigned int memdbg_thread_pool_active_workers(
    const memdbg_thread_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DAEMON_THREAD_POOL_H */
