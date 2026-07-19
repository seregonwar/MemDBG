/*
 * memDBG - Thread pool implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Fixed-size pool of worker threads that dequeue connection_handler
 * invocations.  The acceptor thread enqueues new connections instead
 * of spawning per-connection threads.
 */

#include "memdbg/daemon/thread_pool.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/pal/pal_network.h"

#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- Work queue node ---- */
typedef struct work_node {
  connection_args_t *args;
  struct work_node  *next;
} work_node_t;

/* ---- Pool structure ---- */
struct memdbg_thread_pool {
  pthread_t       *workers;
  unsigned int     num_workers;
  unsigned int     active_workers;

  pthread_mutex_t  queue_mtx;
  pthread_cond_t   queue_cv;
  work_node_t     *queue_head;
  work_node_t     *queue_tail;
  unsigned int     queue_len;

  atomic_bool      shutting_down;
};

/* ---- Worker entry point ---- */
static void *pool_worker(void *arg) {
  memdbg_thread_pool_t *pool = (memdbg_thread_pool_t *)arg;

  for (;;) {
    /* Dequeue a work item. */
    pthread_mutex_lock(&pool->queue_mtx);

    while (pool->queue_head == NULL &&
           !atomic_load_explicit(&pool->shutting_down, memory_order_acquire))
      pthread_cond_wait(&pool->queue_cv, &pool->queue_mtx);

    /* If shutting down with an empty queue, exit. */
    if (pool->queue_head == NULL &&
        atomic_load_explicit(&pool->shutting_down, memory_order_acquire)) {
      pthread_mutex_unlock(&pool->queue_mtx);
      break;
    }

    work_node_t *node = pool->queue_head;
    pool->queue_head = node->next;
    if (pool->queue_head == NULL)
      pool->queue_tail = NULL;
    --pool->queue_len;

    pthread_mutex_unlock(&pool->queue_mtx);

    /* Process the connection on this worker. */
    connection_handler_thread(node->args);
    free(node);
  }

  return NULL;
}

/* ---- Public API ---- */

memdbg_thread_pool_t *memdbg_thread_pool_create(unsigned int num_workers) {
  if (num_workers == 0U) num_workers = 4U;
  if (num_workers > 32U)  num_workers = 32U;

  memdbg_thread_pool_t *pool =
      (memdbg_thread_pool_t *)calloc(1U, sizeof(*pool));
  if (pool == NULL) return NULL;

  pool->num_workers = num_workers;
  pool->workers = (pthread_t *)calloc(num_workers, sizeof(pthread_t));
  if (pool->workers == NULL) {
    free(pool);
    return NULL;
  }

  pthread_mutex_init(&pool->queue_mtx, NULL);
  pthread_cond_init(&pool->queue_cv, NULL);
  atomic_init(&pool->shutting_down, false);
  pool->active_workers = 0U;

  /* Start workers.  If any fail, we start with fewer. */
  for (unsigned int i = 0U; i < num_workers; ++i) {
    if (pthread_create(&pool->workers[i], NULL, pool_worker, pool) == 0)
      ++pool->active_workers;
    else
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "thread_pool: failed to create worker %u/%u",
                       i + 1U, num_workers);
  }

  if (pool->active_workers == 0U) {
    memdbg_log_write(MEMDBG_LOG_ERROR, "thread_pool: no workers started");
    free(pool->workers);
    pthread_mutex_destroy(&pool->queue_mtx);
    pthread_cond_destroy(&pool->queue_cv);
    free(pool);
    return NULL;
  }

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "thread_pool: started %u/%u workers",
                   pool->active_workers, num_workers);
  return pool;
}

int memdbg_thread_pool_enqueue(memdbg_thread_pool_t *pool,
                               connection_args_t *args) {
  if (pool == NULL || args == NULL) return -1;

  /* Reject if shutting down. */
  if (atomic_load_explicit(&pool->shutting_down, memory_order_acquire)) {
    free(args);
    return -1;
  }

  work_node_t *node = (work_node_t *)malloc(sizeof(*node));
  if (node == NULL) {
    free(args);
    return -1;
  }
  node->args = args;
  node->next = NULL;

  pthread_mutex_lock(&pool->queue_mtx);

  /* Double-check shutdown under lock. */
  if (atomic_load_explicit(&pool->shutting_down, memory_order_acquire)) {
    pthread_mutex_unlock(&pool->queue_mtx);
    free(args);
    free(node);
    return -1;
  }

  if (pool->queue_tail != NULL)
    pool->queue_tail->next = node;
  else
    pool->queue_head = node;
  pool->queue_tail = node;
  ++pool->queue_len;

  pthread_cond_signal(&pool->queue_cv);
  pthread_mutex_unlock(&pool->queue_mtx);

  return 0;
}

void memdbg_thread_pool_shutdown(memdbg_thread_pool_t *pool) {
  if (pool == NULL) return;

  /* Signal shutdown. */
  bool was_shutting_down =
      atomic_exchange_explicit(&pool->shutting_down, true,
                               memory_order_acq_rel);
  if (was_shutting_down) return; /* already shutting down */

  /* Wake all workers. */
  pthread_mutex_lock(&pool->queue_mtx);
  pthread_cond_broadcast(&pool->queue_cv);
  pthread_mutex_unlock(&pool->queue_mtx);

  /* Join workers. */
  for (unsigned int i = 0U; i < pool->num_workers; ++i) {
    if (pool->workers[i] != 0)
      pthread_join(pool->workers[i], NULL);
  }

  /* Drain remaining queued connections. */
  pthread_mutex_lock(&pool->queue_mtx);
  work_node_t *node = pool->queue_head;
  while (node != NULL) {
    work_node_t *next = node->next;
    if (node->args != NULL) {
      (void)pal_socket_close(node->args->client_fd);
      free(node->args);
    }
    free(node);
    node = next;
  }
  pool->queue_head = NULL;
  pool->queue_tail = NULL;
  pool->queue_len  = 0U;
  pthread_mutex_unlock(&pool->queue_mtx);

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "thread_pool: %u workers shut down",
                   pool->active_workers);
}

void memdbg_thread_pool_destroy(memdbg_thread_pool_t *pool) {
  if (pool == NULL) return;
  free(pool->workers);
  pthread_mutex_destroy(&pool->queue_mtx);
  pthread_cond_destroy(&pool->queue_cv);
  free(pool);
}

unsigned int memdbg_thread_pool_active_workers(
    const memdbg_thread_pool_t *pool) {
  return pool != NULL ? pool->active_workers : 0U;
}
