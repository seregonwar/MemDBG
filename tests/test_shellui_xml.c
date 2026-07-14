/*
 * MemDBG - ShellUI XML generation unit tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tests the shellui_xml_generate() function to verify it produces
 * well-formed XML with all expected settings entries.
 */

#include <stdio.h>
#include <string.h>

/* Include the module sources directly for host testing */
#include "../../src/shellui/shellui_internal.h"
extern void shellui_xml_generate(char *buf, size_t buf_size,
                                 const memdbg_shellui_config_t *cfg,
                                 const shellui_plugin_def_t *plugins,
                                 int plugin_count);

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

static void test_xml_generation(void) {
  printf("\n--- XML Generation ---\n");

  memdbg_shellui_config_t cfg;
  shellui_config_defaults(&cfg);

  char buf[8192];
  memset(buf, 0, sizeof(buf));
  shellui_xml_generate(buf, sizeof(buf), &cfg, NULL, 0);

  /* Structural checks */
  TEST("contains XML prolog",
       strstr(buf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>") != NULL);
  TEST("contains system_settings root",
       strstr(buf, "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">") != NULL);
  TEST("contains setting_list id",
       strstr(buf, "id=\"id_memdbg_toolbox\"") != NULL);
  TEST("contains MemDBG Toolbox title",
       strstr(buf, "MemDBG Toolbox") != NULL);
  TEST("ends with </system_settings>",
       strstr(buf, "</system_settings>") != NULL);

  /* All toggle switches present */
  TEST("debugger toggle", strstr(buf, "id=\"id_memdbg_debugger\"") != NULL);
  TEST("tracer toggle",   strstr(buf, "id=\"id_memdbg_tracer\"") != NULL);
  TEST("klog toggle",     strstr(buf, "id=\"id_memdbg_klog\"") != NULL);
  TEST("ftp toggle",      strstr(buf, "id=\"id_memdbg_ftp\"") != NULL);
  TEST("ps5debug toggle", strstr(buf, "id=\"id_memdbg_ps5debug\"") != NULL);
  TEST("udp log toggle",  strstr(buf, "id=\"id_memdbg_udp_log\"") != NULL);
  TEST("auto start toggle", strstr(buf, "id=\"id_memdbg_auto_start\"") != NULL);

  /* Action buttons */
  TEST("ping button",     strstr(buf, "id=\"id_memdbg_ping\"") != NULL);
  TEST("shutdown button", strstr(buf, "id=\"id_memdbg_shutdown\"") != NULL);

  /* Text fields */
  TEST("debugger port field", strstr(buf, "id=\"id_memdbg_debugger_port\"") != NULL);
  TEST("klog lines field",    strstr(buf, "id=\"id_memdbg_klog_lines\"") != NULL);
  TEST("ftp port field",      strstr(buf, "id=\"id_memdbg_ftp_port\"") != NULL);
  TEST("udp log port field",  strstr(buf, "id=\"id_memdbg_udp_log_port\"") != NULL);

  /* Info label */
  TEST("info label", strstr(buf, "id=\"id_memdbg_info\"") != NULL);
}

static void test_link_element(void) {
  printf("\n--- XML <link> element ---\n");

  memdbg_shellui_config_t cfg;
  shellui_config_defaults(&cfg);
  shellui_xml_invalidate();

  char buf[8192];
  memset(buf, 0, sizeof(buf));
  shellui_xml_generate(buf, sizeof(buf), &cfg, NULL, 0);

  /* The <link> to original Debug Settings */
  TEST("contains link element",
       strstr(buf, "<link") != NULL);
  TEST("link has correct id",
       strstr(buf, "id=\"id_memdbg_original_debug\"") != NULL);
  TEST("link has title Debug Settings",
       strstr(buf, "title=\"Debug Settings\"") != NULL);
  TEST("link has file attribute",
       strstr(buf, "file=\"original_debug.xml\"") != NULL);
  TEST("link has second_title",
       strstr(buf, "second_title=\"MemDBG v") != NULL);
  TEST("link second_title shows version",
       strstr(buf, shellui_version_string()) != NULL);
  TEST("link second_title shows debugger status",
       strstr(buf, "Debugger:") != NULL);
  TEST("link second_title shows tracer status",
       strstr(buf, "Tracer:") != NULL);
  TEST("link second_title shows ftp status",
       strstr(buf, "FTP:") != NULL);

  /* Verify link appears BEFORE closing </setting_list> */
  const char *link = strstr(buf, "id_memdbg_original_debug");
  const char *close_list = strstr(buf, "</setting_list>");
  TEST("link before closing setting_list",
       link != NULL && close_list != NULL && link < close_list);
}

static void test_link_with_disabled_services(void) {
  printf("\n--- XML <link> disabled services ---\n");

  memdbg_shellui_config_t cfg;
  shellui_config_defaults(&cfg);
  cfg.debugger_enabled = false;
  cfg.tracer_enabled   = false;
  cfg.ftp_enabled      = false;
  shellui_xml_invalidate();

  char buf[8192];
  memset(buf, 0, sizeof(buf));
  shellui_xml_generate(buf, sizeof(buf), &cfg, NULL, 0);

  /* Check the link shows services as "off" */
  const char *link_start = strstr(buf, "id_memdbg_original_debug");
  TEST("link shows debugger off",
       link_start != NULL && strstr(link_start, "Debugger:off") != NULL);
  TEST("link shows tracer off",
       link_start != NULL && strstr(link_start, "Tracer:off") != NULL);
  TEST("link shows ftp off",
       link_start != NULL && strstr(link_start, "FTP:off") != NULL);
}

static void test_xml_with_config(void) {
  printf("\n--- XML with custom config ---\n");

  memdbg_shellui_config_t cfg;
  shellui_config_defaults(&cfg);

  /* Invalidate cache so the new config is rebuilt */
  shellui_xml_invalidate();

  /* Override some values */
  cfg.debugger_enabled = false;
  cfg.tracer_enabled   = false;
  cfg.ftp_enabled      = true;
  cfg.ftp_port         = 2121;
  cfg.klog_enabled     = true;
  cfg.klog_max_lines   = 1000;

  char buf[8192];
  memset(buf, 0, sizeof(buf));
  shellui_xml_generate(buf, sizeof(buf), &cfg, NULL, 0);

  /* Check that disabled toggles show value="0" within their own element */
  {
    const char *dbg = strstr(buf, "id=\"id_memdbg_debugger\"");
    TEST("debugger off value=0", dbg != NULL && strstr(dbg, "value=\"0\"") != NULL);
  }
  {
    const char *tracer = strstr(buf, "id=\"id_memdbg_tracer\"");
    TEST("tracer off value=0", tracer != NULL && strstr(tracer, "value=\"0\"") != NULL);
  }
  /* Check FTP port appears in XML */
  TEST("ftp port 2121 appears", strstr(buf, "2121") != NULL);
  TEST("klog lines 1000 appears", strstr(buf, "1000") != NULL);
}

static void test_xml_buffer_safety(void) {
  printf("\n--- XML buffer safety ---\n");

  memdbg_shellui_config_t cfg;
  shellui_config_defaults(&cfg);

  /* Tiny buffer: should not crash */
  char small[64];
  memset(small, 0xAA, sizeof(small));
  shellui_xml_generate(small, sizeof(small), &cfg, NULL, 0);
  small[63] = '\0';
  TEST("small buffer null terminated", small[63] == '\0');

  /* Zero-size buffer: should not crash */
  shellui_xml_generate(NULL, 0, &cfg, NULL, 0);
  TEST("null buffer handled", 1);

  /* Large buffer: should produce valid XML */
  char large[16384];
  memset(large, 0, sizeof(large));
  shellui_xml_generate(large, sizeof(large), &cfg, NULL, 0);
  TEST("large buffer contains closing tag",
       strstr(large, "</system_settings>") != NULL);
}

int main(void) {
  printf("=== MemDBG ShellUI XML Generation Tests ===\n");

  test_xml_generation();
  test_xml_with_config();
  test_xml_buffer_safety();
  test_link_element();
  test_link_with_disabled_services();

  printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  printf("Total:  %d\n", total);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}
