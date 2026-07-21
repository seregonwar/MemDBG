/*
 * memDBG - Instance management unit tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tests the PID-file based instance detection logic, including the
 * distinction between a stale reused PID and a true same-process
 * re-injection.
 */

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_instance.h"
#include "memdbg/pal/pal_network.h"

#include "fixture_memdbg_instance.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void copy_to_data_root(char *dest, size_t dest_size, const char *src) {
  size_t n = strlen(src);
  if (n >= dest_size) n = dest_size - 1;
  memcpy(dest, src, n);
  dest[n] = '\0';
}

static void test_no_pid_file(void) {
  memdbg_config_t cfg;
  char tmp[1024];

  printf("\n--- No PID file ---\n");
  if (fixture_make_temp_dir(tmp, sizeof(tmp)) != 0) {
    printf("  FAIL  could not create temp dir\n");
    ++g_fixture_failed;
    return;
  }

  memdbg_config_defaults(&cfg);
  copy_to_data_root(cfg.data_root, sizeof(cfg.data_root), tmp);
  cfg.debug_port = fixture_get_free_port();
  if (cfg.debug_port == 0U) {
    printf("  FAIL  could not obtain free port\n");
    ++g_fixture_failed;
    fixture_cleanup_dir(tmp);
    return;
  }

  FIXTURE_TEST("is_current_process false when no pid file",
               !memdbg_instance_is_current_process(&cfg));

  fixture_cleanup_dir(tmp);
}

static void test_stale_current_pid_no_listener(void) {
  memdbg_config_t cfg;
  char tmp[1024];

  printf("\n--- Stale PID file matching current PID, no listener ---\n");
  if (fixture_make_temp_dir(tmp, sizeof(tmp)) != 0) {
    printf("  FAIL  could not create temp dir\n");
    ++g_fixture_failed;
    return;
  }

  memdbg_config_defaults(&cfg);
  copy_to_data_root(cfg.data_root, sizeof(cfg.data_root), tmp);
  cfg.debug_port = fixture_get_free_port();
  if (cfg.debug_port == 0U) {
    printf("  FAIL  could not obtain free port\n");
    ++g_fixture_failed;
    fixture_cleanup_dir(tmp);
    return;
  }

  if (fixture_write_pid_file(tmp, (int)getpid()) != 0) {
    printf("  FAIL  could not write pid file\n");
    ++g_fixture_failed;
    fixture_cleanup_dir(tmp);
    return;
  }

  FIXTURE_TEST("is_current_process false when daemon is not responsive",
               !memdbg_instance_is_current_process(&cfg));
  FIXTURE_TEST("stop_previous removes stale pid file",
               memdbg_instance_stop_previous(&cfg) == MEMDBG_OK &&
                   !fixture_pid_file_exists(tmp));

  fixture_cleanup_dir(tmp);
}

static void test_stale_current_pid_plain_listener(void) {
  memdbg_config_t cfg;
  char tmp[1024];
  fixture_listener_t listener = { .listen_fd = -1, .port = 0 };

  printf("\n--- Stale PID file matching current PID, non-MemDBG listener ---\n");
  if (fixture_make_temp_dir(tmp, sizeof(tmp)) != 0) {
    printf("  FAIL  could not create temp dir\n");
    ++g_fixture_failed;
    return;
  }

  memdbg_config_defaults(&cfg);
  copy_to_data_root(cfg.data_root, sizeof(cfg.data_root), tmp);

  if (fixture_start_plain_listener(&listener) != 0) {
    printf("  FAIL  could not start plain listener\n");
    ++g_fixture_failed;
    fixture_cleanup_dir(tmp);
    return;
  }

  cfg.debug_port = listener.port;

  if (fixture_write_pid_file(tmp, (int)getpid()) != 0) {
    printf("  FAIL  could not write pid file\n");
    ++g_fixture_failed;
    fixture_stop_listener(&listener);
    fixture_cleanup_dir(tmp);
    return;
  }

  FIXTURE_TEST("is_current_process false when listener is not MemDBG",
               !memdbg_instance_is_current_process(&cfg));
  FIXTURE_TEST("stop_previous removes stale pid file with plain listener",
               memdbg_instance_stop_previous(&cfg) == MEMDBG_OK &&
                   !fixture_pid_file_exists(tmp));

  fixture_stop_listener(&listener);
  fixture_cleanup_dir(tmp);
}

static void test_same_process_reinjection(void) {
  memdbg_config_t cfg;
  char tmp[1024];
  fixture_listener_t listener = { .listen_fd = -1, .port = 0 };

  printf("\n--- Same-process re-injection (PID matches + MemDBG listener) ---\n");
  if (fixture_make_temp_dir(tmp, sizeof(tmp)) != 0) {
    printf("  FAIL  could not create temp dir\n");
    ++g_fixture_failed;
    return;
  }

  memdbg_config_defaults(&cfg);
  copy_to_data_root(cfg.data_root, sizeof(cfg.data_root), tmp);

  if (fixture_start_memdbg_listener(&listener) != 0) {
    printf("  FAIL  could not start fake MemDBG listener\n");
    ++g_fixture_failed;
    fixture_cleanup_dir(tmp);
    return;
  }

  cfg.debug_port = listener.port;

  if (fixture_write_pid_file_with_token(tmp, (int)getpid(),
                                        FIXTURE_INSTANCE_ID) != 0) {
    printf("  FAIL  could not write pid file\n");
    ++g_fixture_failed;
    fixture_stop_listener(&listener);
    fixture_cleanup_dir(tmp);
    return;
  }

  FIXTURE_TEST("is_current_process true when daemon responds to HELLO",
               memdbg_instance_is_current_process(&cfg));
  FIXTURE_TEST("stop_previous refuses to terminate live same-process instance",
               memdbg_instance_stop_previous(&cfg) == MEMDBG_ERR_STATE);

  fixture_stop_listener(&listener);
  fixture_cleanup_dir(tmp);
}

static void test_token_mismatch(void) {
  memdbg_config_t cfg;
  char tmp[1024];
  fixture_listener_t listener = { .listen_fd = -1, .port = 0 };

  printf("\n--- PID matches but instance token does not ---\n");
  if (fixture_make_temp_dir(tmp, sizeof(tmp)) != 0) {
    printf("  FAIL  could not create temp dir\n");
    ++g_fixture_failed;
    return;
  }

  memdbg_config_defaults(&cfg);
  copy_to_data_root(cfg.data_root, sizeof(cfg.data_root), tmp);

  if (fixture_start_memdbg_listener(&listener) != 0) {
    printf("  FAIL  could not start fake MemDBG listener\n");
    ++g_fixture_failed;
    fixture_cleanup_dir(tmp);
    return;
  }

  cfg.debug_port = listener.port;

  if (fixture_write_pid_file_with_token(tmp, (int)getpid(),
                                        0xBADBADBADBADBADBULL) != 0) {
    printf("  FAIL  could not write pid file\n");
    ++g_fixture_failed;
    fixture_stop_listener(&listener);
    fixture_cleanup_dir(tmp);
    return;
  }

  FIXTURE_TEST("is_current_process false when token mismatches",
               !memdbg_instance_is_current_process(&cfg));
  FIXTURE_TEST("stop_previous removes stale pid file on token mismatch",
               memdbg_instance_stop_previous(&cfg) == MEMDBG_OK &&
                   !fixture_pid_file_exists(tmp));

  fixture_stop_listener(&listener);
  fixture_cleanup_dir(tmp);
}

static void test_stale_other_pid(void) {
  memdbg_config_t cfg;
  char tmp[1024];

  printf("\n--- Stale PID file for unrelated non-existent process ---\n");
  if (fixture_make_temp_dir(tmp, sizeof(tmp)) != 0) {
    printf("  FAIL  could not create temp dir\n");
    ++g_fixture_failed;
    return;
  }

  memdbg_config_defaults(&cfg);
  copy_to_data_root(cfg.data_root, sizeof(cfg.data_root), tmp);
  cfg.debug_port = fixture_get_free_port();
  if (cfg.debug_port == 0U) {
    printf("  FAIL  could not obtain free port\n");
    ++g_fixture_failed;
    fixture_cleanup_dir(tmp);
    return;
  }

  if (fixture_write_pid_file(tmp, 0x7fffffff) != 0) {
    printf("  FAIL  could not write pid file\n");
    ++g_fixture_failed;
    fixture_cleanup_dir(tmp);
    return;
  }

  /* Stale PID (non-existent) — stop_previous removes the file and returns OK
   * without attempting PID-based termination. */
  FIXTURE_TEST("stop_previous removes stale pid file for unrelated pid",
               memdbg_instance_stop_previous(&cfg) == MEMDBG_OK &&
                   !fixture_pid_file_exists(tmp));

  fixture_cleanup_dir(tmp);
}

static void test_live_non_memdbg_pid(void) {
  memdbg_config_t cfg;
  char tmp[1024];

  printf("\n--- PID file for live non-MemDBG process (pid 1) ---\n");
  if (fixture_make_temp_dir(tmp, sizeof(tmp)) != 0) {
    printf("  FAIL  could not create temp dir\n");
    ++g_fixture_failed;
    return;
  }

  memdbg_config_defaults(&cfg);
  copy_to_data_root(cfg.data_root, sizeof(cfg.data_root), tmp);
  cfg.debug_port = fixture_get_free_port();
  if (cfg.debug_port == 0U) {
    printf("  FAIL  could not obtain free port\n");
    ++g_fixture_failed;
    fixture_cleanup_dir(tmp);
    return;
  }

  /* pid 1 (init/systemd) is always live and not a MemDBG process. */
  if (fixture_write_pid_file(tmp, 1) != 0) {
    printf("  FAIL  could not write pid file\n");
    ++g_fixture_failed;
    fixture_cleanup_dir(tmp);
    return;
  }

  FIXTURE_TEST("stop_previous refuses to terminate live non-MemDBG pid",
               memdbg_instance_stop_previous(&cfg) == MEMDBG_OK);
  /* The pid file should still exist — we refused to act on it. */
  FIXTURE_TEST("pid file preserved when refusing to terminate",
               fixture_pid_file_exists(tmp));

  fixture_cleanup_dir(tmp);
}

int main(void) {
  printf("=== memdbg_instance unit tests ===\n");

  if (pal_network_init() != 0) {
    fprintf(stderr, "FATAL: pal_network_init failed\n");
    return 1;
  }

  test_no_pid_file();
  test_stale_current_pid_no_listener();
  test_stale_current_pid_plain_listener();
  test_same_process_reinjection();
  test_token_mismatch();
  test_stale_other_pid();
  test_live_non_memdbg_pid();

  pal_network_fini();

  printf("\n=== Results ===\n");
  printf("Passed: %d\n", g_fixture_passed);
  printf("Failed: %d\n", g_fixture_failed);

  return g_fixture_failed == 0 ? 0 : 1;
}
