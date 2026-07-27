/*
 * memDBG - Thread pool implementation tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Include the implementation directly so the test can verify that every
 * field read by newly started workers is initialized before pthread_create.
 */

#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/core/daemon/thread_pool.c"

#define TEST_WORKERS 4U
#define TEST_TASKS 64U
#define TEST_INIT_ITERATIONS 32U
#define TEST_TIMEOUT_MS 5000U

static atomic_uint g_handled = ATOMIC_VAR_INIT(0U);
static int g_failed = 0;

void memdbg_log_write(memdbg_log_level_t level, const char *fmt, ...) {
  (void)level;
  (void)fmt;
}

int pal_socket_close(socket_t fd) {
  (void)fd;
  return 0;
}

void *connection_handler_thread(void *arg) {
  connection_args_t *args = (connection_args_t *)arg;
  free(args);
  atomic_fetch_add_explicit(&g_handled, 1U, memory_order_release);
  return NULL;
}

static void check(const char *label, bool condition) {
  if (condition) {
    printf("  PASS: %s\n", label);
  } else {
    fprintf(stderr, "  FAIL: %s\n", label);
    g_failed = 1;
  }
}

static void sleep_ms(unsigned int milliseconds) {
  struct timespec delay;
  delay.tv_sec = (time_t)(milliseconds / 1000U);
  delay.tv_nsec = (long)(milliseconds % 1000U) * 1000000L;
  (void)nanosleep(&delay, NULL);
}

static void poison_next_pool_allocation(void) {
  void *memory = NULL;
  if (posix_memalign(&memory, 64U, sizeof(memdbg_thread_pool_t)) == 0) {
    memset(memory, 0xA5, sizeof(memdbg_thread_pool_t));
    free(memory);
  }
}

static connection_args_t *make_args(unsigned int id) {
  connection_args_t *args =
      (connection_args_t *)malloc(sizeof(connection_args_t));
  if (args == NULL) return NULL;
  memset(args, 0, sizeof(*args));
  args->client_fd = (socket_t)(id + 1U);
  return args;
}

static void test_initialized_state(void) {
  printf("\n--- Initialized pool state ---\n");

  for (unsigned int i = 0U; i < TEST_INIT_ITERATIONS; ++i) {
    poison_next_pool_allocation();
    memdbg_thread_pool_t *pool = memdbg_thread_pool_create(2U);
    if (pool == NULL) {
      check("pool created after poisoned allocation", false);
      return;
    }

    (void)pthread_mutex_lock(&pool->queue_mtx);
    const bool queue_initialized =
        pool->queue_head == NULL && pool->queue_tail == NULL &&
        pool->queue_len == 0U;
    (void)pthread_mutex_unlock(&pool->queue_mtx);

    if (!queue_initialized) {
      check("queue fields start empty", false);
      memdbg_thread_pool_shutdown(pool);
      memdbg_thread_pool_destroy(pool);
      return;
    }

    memdbg_thread_pool_shutdown(pool);
    memdbg_thread_pool_destroy(pool);
  }

  check("queue fields start empty", true);
}

static void test_work_processing(void) {
  printf("\n--- Work processing ---\n");

  atomic_store_explicit(&g_handled, 0U, memory_order_relaxed);
  memdbg_thread_pool_t *pool = memdbg_thread_pool_create(TEST_WORKERS);
  check("pool created", pool != NULL);
  if (pool == NULL) return;

  check("all requested workers started",
        memdbg_thread_pool_active_workers(pool) == TEST_WORKERS);

  unsigned int enqueued = 0U;
  for (unsigned int i = 0U; i < TEST_TASKS; ++i) {
    connection_args_t *args = make_args(i);
    if (args == NULL) break;
    if (memdbg_thread_pool_enqueue(pool, args) != 0) {
      free(args);
      break;
    }
    ++enqueued;
  }
  check("all tasks enqueued", enqueued == TEST_TASKS);

  unsigned int waited_ms = 0U;
  while (atomic_load_explicit(&g_handled, memory_order_acquire) < enqueued &&
         waited_ms < TEST_TIMEOUT_MS) {
    sleep_ms(1U);
    ++waited_ms;
  }

  memdbg_thread_pool_shutdown(pool);
  check("all queued tasks handled",
        atomic_load_explicit(&g_handled, memory_order_acquire) == enqueued);

  connection_args_t *rejected = make_args(TEST_TASKS);
  check("post-shutdown test allocation", rejected != NULL);
  if (rejected != NULL) {
    check("enqueue rejects work after shutdown",
          memdbg_thread_pool_enqueue(pool, rejected) == -1);
    /* A failed enqueue must leave ownership with the caller. */
    free(rejected);
  }

  memdbg_thread_pool_destroy(pool);
}

int main(void) {
  printf("=== thread_pool unit tests ===\n");

  test_initialized_state();
  test_work_processing();

  printf("\n=== %s ===\n", g_failed == 0 ? "ALL PASSED" : "SOME FAILED");
  return g_failed;
}
