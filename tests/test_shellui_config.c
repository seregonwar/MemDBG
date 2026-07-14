/*
 * MemDBG - ShellUI configuration persistence unit tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tests shellui_config_load/save roundtrip and defaults.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Include module source for host testing */
#include "../../src/shellui/shellui_internal.h"
extern void shellui_config_defaults(memdbg_shellui_config_t *cfg);
extern bool shellui_config_load(memdbg_shellui_config_t *cfg, const char *path);
extern bool shellui_config_save(const memdbg_shellui_config_t *cfg, const char *path);

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s\n", name);                                            \
    }                                                                          \
  } while (0)

static void test_defaults(void) {
  printf("\n--- Config defaults ---\n");

  memdbg_shellui_config_t cfg;
  shellui_config_defaults(&cfg);

  TEST("debugger default on",     cfg.debugger_enabled == true);
  TEST("debugger port 9020",      cfg.debugger_port == 9020);
  TEST("tracer default on",       cfg.tracer_enabled == true);
  TEST("klog default off",        cfg.klog_enabled == false);
  TEST("klog max lines 5000",     cfg.klog_max_lines == 5000);
  TEST("ftp default off",         cfg.ftp_enabled == false);
  TEST("ftp port 1337",           cfg.ftp_port == 1337);
  TEST("ps5debug default off",    cfg.ps5debug_enabled == false);
  TEST("udp log default on",      cfg.udp_log_enabled == true);
  TEST("udp log port 9023",       cfg.udp_log_port == 9023);
  TEST("auto start default on",   cfg.auto_start == true);
  TEST("display version default on", cfg.display_version == true);
}

static void test_save_load_roundtrip(void) {
  printf("\n--- Config save/load roundtrip ---\n");

  const char *tmp_path = "/tmp/memdbg_test_shellui.ini";

  /* Remove any stale file */
  remove(tmp_path);

  /* Create a custom config */
  memdbg_shellui_config_t original;
  shellui_config_defaults(&original);
  original.debugger_enabled = false;
  original.ftp_enabled      = true;
  original.ftp_port         = 2121;
  original.klog_enabled     = true;
  original.klog_max_lines   = 999;
  original.ps5debug_enabled = true;
  original.auto_start       = false;

  /* Save */
  TEST("save succeeds", shellui_config_save(&original, tmp_path));

  /* Load into new struct */
  memdbg_shellui_config_t loaded;
  TEST("load succeeds", shellui_config_load(&loaded, tmp_path));

  /* Verify roundtrip */
  TEST("debugger off saved",     loaded.debugger_enabled == false);
  TEST("ftp on saved",           loaded.ftp_enabled == true);
  TEST("ftp port 2121 saved",    loaded.ftp_port == 2121);
  TEST("klog on saved",          loaded.klog_enabled == true);
  TEST("klog lines 999 saved",   loaded.klog_max_lines == 999);
  TEST("ps5debug on saved",      loaded.ps5debug_enabled == true);
  TEST("auto start off saved",   loaded.auto_start == false);

  /* Values not changed in original should stay at defaults */
  TEST("tracer still on",        loaded.tracer_enabled == true);
  TEST("debugger port still 9020", loaded.debugger_port == 9020);
  TEST("udp log still on",       loaded.udp_log_enabled == true);
  TEST("udp log port still 9023", loaded.udp_log_port == 9023);

  /* Cleanup */
  remove(tmp_path);
}

static void test_load_missing_file(void) {
  printf("\n--- Config load missing file ---\n");

  memdbg_shellui_config_t cfg;
  memset(&cfg, 0xAA, sizeof(cfg));

  bool ok = shellui_config_load(&cfg, "/tmp/memdbg_nonexistent_xyz.ini");
  TEST("load returns false for missing file", !ok);

  /* After failed load, struct should have defaults */
  TEST("defaults applied on missing", cfg.debugger_port == 9020);
}

static void test_load_bool_variants(void) {
  printf("\n--- Config bool parsing ---\n");

  const char *tmp_path = "/tmp/memdbg_test_bools.ini";

  FILE *f = fopen(tmp_path, "w");
  fprintf(f, "[MemDBG]\n"
             "debugger=true\n"
             "tracer=on\n"
             "klog=yes\n"
             "ftp=1\n"
             "ps5debug=false\n"
             "udp_log=off\n"
             "auto_start=no\n"
             "display_version=0\n");
  fclose(f);

  memdbg_shellui_config_t cfg;
  TEST("load bools file", shellui_config_load(&cfg, tmp_path));
  TEST("true parsed",  cfg.debugger_enabled == true);
  TEST("on parsed",    cfg.tracer_enabled == true);
  TEST("yes parsed",   cfg.klog_enabled == true);
  TEST("1 parsed",     cfg.ftp_enabled == true);
  TEST("false parsed", cfg.ps5debug_enabled == false);
  TEST("off parsed",   cfg.udp_log_enabled == false);
  TEST("no parsed",    cfg.auto_start == false);
  TEST("0 parsed",     cfg.display_version == false);

  remove(tmp_path);
}

int main(void) {
  printf("=== MemDBG ShellUI Config Tests ===\n");

  test_defaults();
  test_save_load_roundtrip();
  test_load_missing_file();
  test_load_bool_variants();

  printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  printf("Total:  %d\n", total);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}
