/*
 * memDBG - Reusable test fixture for memdbg_instance tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef TESTS_FIXTURE_MEMDBG_INSTANCE_H
#define TESTS_FIXTURE_MEMDBG_INSTANCE_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int g_fixture_passed;
extern int g_fixture_failed;

#define FIXTURE_TEST(name, expr)                                               \
  do {                                                                         \
    if (expr) {                                                                \
      ++g_fixture_passed;                                                      \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      ++g_fixture_failed;                                                      \
      printf("  FAIL  %s\n", name);                                            \
    }                                                                          \
  } while (0)

/* ---- Temporary directory helpers ---- */
int fixture_make_temp_dir(char *out, size_t out_size);
void fixture_cleanup_dir(const char *data_root);

/* ---- PID file helpers ---- */
#define FIXTURE_INSTANCE_ID 0xDEADBEEFCAFEBABEULL

int fixture_pid_file_path(const char *data_root, char *out, size_t out_size);
int fixture_write_pid_file(const char *data_root, int pid);
int fixture_write_pid_file_with_token(const char *data_root, int pid,
                                      uint64_t token);
void fixture_remove_pid_file(const char *data_root);
int fixture_pid_file_exists(const char *data_root);

/* ---- Network helpers ---- */
uint16_t fixture_get_free_port(void);

typedef struct {
  int listen_fd;
  uint16_t port;
  pthread_t thread;
  void *thread_args;
} fixture_listener_t;

int fixture_start_plain_listener(fixture_listener_t *out);
int fixture_start_memdbg_listener(fixture_listener_t *out);
void fixture_stop_listener(fixture_listener_t *listener);

#ifdef __cplusplus
}
#endif

#endif /* TESTS_FIXTURE_MEMDBG_INSTANCE_H */
