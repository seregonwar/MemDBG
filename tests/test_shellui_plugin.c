/*
 * MemDBG - ShellUI plugin discovery & XML generation unit tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tests shellui_plugin_discover(), shellui_plugin_xml_generate(),
 * and the integration with shellui_xml_generate().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Include module source for host testing */
#include "../../src/shellui/shellui_internal.h"
extern void shellui_plugin_set_dir(const char *dir);
extern int  shellui_plugin_xml_generate(char *buf, size_t buf_size,
                                        const shellui_plugin_def_t *plugins,
                                        int plugin_count);
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

/* ---- Plugin discovery & XML with temp directory ---- */

static char g_tmpdir[256];
static char g_plugin_path[512];

static int setup_mock_plugin_dir(void) {
  snprintf(g_tmpdir, sizeof(g_tmpdir),
           "/tmp/memdbg_plugin_test_%d", getpid());
  mkdir(g_tmpdir, 0755);

  snprintf(g_plugin_path, sizeof(g_plugin_path),
           "%s/test_plugin.memdbg_plugin", g_tmpdir);

  /* Write a valid .memdbg_plugin file with header + element lines */
  FILE *f = fopen(g_plugin_path, "wb");
  if (!f) return -1;

  /* Binary header */
  memdbg_plugin_header_t header;
  memset(&header, 0, sizeof(header));
  memcpy(header.prefix, "MEMDBG_PLUGIN", 13);
  header.prefix[13] = '\0';
  header.shellui_elements = 4;
  fwrite(&header, 1, sizeof(header), f);

  /* Element lines: TYPE:ID:TITLE:SECOND_TITLE:DEFAULT_VALUE */
  fprintf(f, "toggle_switch:plg_toggle:My Toggle:Enable or disable my feature:1\n");
  fprintf(f, "button:plg_button:My Button:Click to trigger action:\n");
  fprintf(f, "label:plg_info:Plugin v1.0 by Author: :\n");
  fprintf(f, "text_field:plg_port:Listen Port:0-65535:8080\n");

  fclose(f);
  return 0;
}

static void test_plugin_discovery(void) {
  printf("\n--- Plugin Discovery (simulated) ---\n");

  /* Parse the mock file directly via parse logic */
  shellui_plugin_def_t plugins[8];
  memset(plugins, 0, sizeof(plugins));

  /* Since dir scanning needs the real plugin_dirs path, we test
   * by directly reading the mock file */
  FILE *f = fopen(g_plugin_path, "rb");
  TEST("mock plugin file exists", f != NULL);
  if (!f) return;

  /* Read header */
  memdbg_plugin_header_t header;
  TEST("read header", fread(&header, 1, sizeof(header), f) == sizeof(header));
  TEST("header prefix matches", strncmp(header.prefix, "MEMDBG_PLUGIN", 13) == 0);
  TEST("header elements count", header.shellui_elements == 4);

  /* Read element lines manually */
  char line[512];
  int count = 0;
  while (count < 4 && fgets(line, sizeof(line), f)) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
      line[--len] = '\0';

    if (line[0] == '#' || line[0] == '\0') continue;

    char *saveptr = NULL;
    char *type_str = strtok_r(line, ":", &saveptr);
    char *id_str   = strtok_r(NULL, ":", &saveptr);
    char *title_str = strtok_r(NULL, ":", &saveptr);

    TEST("element type parsed", type_str != NULL);
    TEST("element id parsed",   id_str != NULL);
    TEST("element title parsed", title_str != NULL);
    count++;
  }
  fclose(f);

  TEST("parsed 4 elements", count == 4);
}

static void test_discovery_end_to_end(void) {
  printf("\n--- Plugin Discovery (end-to-end via env var) ---\n");

  /* Point plugin discovery at our mock directory */
  shellui_plugin_set_dir(g_tmpdir);

  shellui_plugin_def_t plugins[8];
  memset(plugins, 0, sizeof(plugins));

  int found = shellui_plugin_discover(plugins, 8);
  TEST("discovery found plugins", found == 1);

  if (found >= 1) {
    TEST("plugin id is test_plugin",
         strcmp(plugins[0].plugin_id, "test_plugin") == 0);
    TEST("plugin has 4 elements",
         plugins[0].element_count == 4);
    TEST("element 0 is toggle_switch",
         plugins[0].elements[0].type == SHELLUI_EL_TOGGLE_SWITCH);
    TEST("element 0 id matches",
         strcmp(plugins[0].elements[0].id, "plg_toggle") == 0);
    TEST("element 1 is button",
         plugins[0].elements[1].type == SHELLUI_EL_BUTTON);
    TEST("element 2 is label",
         plugins[0].elements[2].type == SHELLUI_EL_LABEL);
    TEST("element 3 is text_field",
         plugins[0].elements[3].type == SHELLUI_EL_TEXT_FIELD);
    TEST("text field port value",
         strcmp(plugins[0].elements[3].default_value, "8080") == 0);
  }

  /* Reset to default */
  shellui_plugin_set_dir(NULL);
}

static void test_plugin_xml_generation(void) {
  printf("\n--- Plugin XML Generation ---\n");

  /* Build a mock plugin definition */
  shellui_plugin_def_t plugins[2];
  memset(plugins, 0, sizeof(plugins));

  /* Plugin 1: ExamplePlugin with 2 elements */
  snprintf(plugins[0].plugin_id, sizeof(plugins[0].plugin_id), "example");
  snprintf(plugins[0].plugin_name, sizeof(plugins[0].plugin_name),
           "Example Plugin");
  snprintf(plugins[0].plugin_version, sizeof(plugins[0].plugin_version),
           "1.2.3");
  plugins[0].element_count = 2;
  plugins[0].elements[0].type = SHELLUI_EL_TOGGLE_SWITCH;
  snprintf(plugins[0].elements[0].id, sizeof(plugins[0].elements[0].id),
           "plg_ex_toggle");
  snprintf(plugins[0].elements[0].title,
           sizeof(plugins[0].elements[0].title), "Example Toggle");
  snprintf(plugins[0].elements[0].second_title,
           sizeof(plugins[0].elements[0].second_title),
           "Turn this feature on or off");
  snprintf(plugins[0].elements[0].default_value,
           sizeof(plugins[0].elements[0].default_value), "1");

  plugins[0].elements[1].type = SHELLUI_EL_BUTTON;
  snprintf(plugins[0].elements[1].id, sizeof(plugins[0].elements[1].id),
           "plg_ex_btn");
  snprintf(plugins[0].elements[1].title,
           sizeof(plugins[0].elements[1].title), "Example Action");
  snprintf(plugins[0].elements[1].second_title,
           sizeof(plugins[0].elements[1].second_title),
           "Trigger the example action");

  /* Plugin 2: AnotherPlugin with 1 element */
  snprintf(plugins[1].plugin_id, sizeof(plugins[1].plugin_id), "another");
  snprintf(plugins[1].plugin_name, sizeof(plugins[1].plugin_name),
           "Another Plugin");
  snprintf(plugins[1].plugin_version, sizeof(plugins[1].plugin_version),
           "0.1.0");
  plugins[1].element_count = 1;
  plugins[1].elements[0].type = SHELLUI_EL_LABEL;
  snprintf(plugins[1].elements[0].id, sizeof(plugins[1].elements[0].id),
           "plg_another_label");
  snprintf(plugins[1].elements[0].title,
           sizeof(plugins[1].elements[0].title),
           "Another Plugin v0.1.0 (status: active)");

  /* Generate XML */
  char buf[4096];
  memset(buf, 0, sizeof(buf));
  int len = shellui_plugin_xml_generate(buf, sizeof(buf), plugins, 2);
  TEST("plugin XML generated with content", len > 0);

  /* Check for expected content */
  TEST("contains plugin section comment",
       strstr(buf, "Plugin Section") != NULL);
  TEST("contains setting_list for example",
       strstr(buf, "id=\"id_plugin_example\"") != NULL);
  TEST("contains example plugin name",
       strstr(buf, "Example Plugin (v1.2.3)") != NULL);
  TEST("contains toggle_switch element",
       strstr(buf, "id=\"plg_ex_toggle\"") != NULL);
  TEST("contains toggle title",
       strstr(buf, "Example Toggle") != NULL);
  TEST("contains toggle default value",
       strstr(buf, "value=\"1\"") != NULL);
  TEST("contains button element",
       strstr(buf, "id=\"plg_ex_btn\"") != NULL);
  TEST("contains setting_list for another",
       strstr(buf, "id=\"id_plugin_another\"") != NULL);
  TEST("contains label element",
       strstr(buf, "id=\"plg_another_label\"") != NULL);
  TEST("contains label title",
       strstr(buf, "Another Plugin v0.1.0 (status: active)") != NULL);

  /* Test with zero plugins: should return 0 */
  char empty_buf[256];
  memset(empty_buf, 0, sizeof(empty_buf));
  int empty_len = shellui_plugin_xml_generate(empty_buf, sizeof(empty_buf),
                                              NULL, 0);
  TEST("zero plugins returns 0", empty_len == 0);

  /* Test buffer safety */
  char tiny[16];
  memset(tiny, 0xAA, sizeof(tiny));
  shellui_plugin_xml_generate(tiny, sizeof(tiny), plugins, 2);
  TEST("tiny buffer doesn't crash", 1);
}

static void test_full_xml_integration(void) {
  printf("\n--- Full XML Integration (config + plugins) ---\n");

  memdbg_shellui_config_t cfg;
  shellui_config_defaults(&cfg);
  cfg.ftp_enabled = true;
  cfg.ftp_port = 31337;

  /* Mock plugins */
  shellui_plugin_def_t plugins[1];
  memset(plugins, 0, sizeof(plugins));
  snprintf(plugins[0].plugin_id, sizeof(plugins[0].plugin_id), "testplug");
  snprintf(plugins[0].plugin_name, sizeof(plugins[0].plugin_name),
           "Test Plugin");
  snprintf(plugins[0].plugin_version, sizeof(plugins[0].plugin_version), "1.0");
  plugins[0].element_count = 1;
  plugins[0].elements[0].type = SHELLUI_EL_TOGGLE_SWITCH;
  snprintf(plugins[0].elements[0].id, sizeof(plugins[0].elements[0].id),
           "plg_int_toggle");
  snprintf(plugins[0].elements[0].title,
           sizeof(plugins[0].elements[0].title), "Integration Toggle");

  char buf[16384];
  memset(buf, 0, sizeof(buf));
  shellui_xml_generate(buf, sizeof(buf), &cfg, plugins, 1);

  /* Verify both core content and plugins are present */
  TEST("core: system_settings root",
       strstr(buf, "<system_settings version=\"1.0\"") != NULL);
  TEST("core: toolbox appears",
       strstr(buf, "MemDBG Toolbox") != NULL);
  TEST("core: FTP port 31337",
       strstr(buf, "31337") != NULL);
  TEST("integration: plugin section after toolbox",
       strstr(buf, "id=\"id_plugin_testplug\"") != NULL);
  TEST("integration: plugin element present",
       strstr(buf, "plg_int_toggle") != NULL);

  /* Verify correct order: toolbox </setting_list> comes before plugin section */
  const char *toolbox_end = strstr(buf, "</setting_list>");
  const char *plugin_start = strstr(buf, "id=\"id_plugin_testplug\"");
  TEST("integration: toolbox closed before plugin section",
       toolbox_end != NULL && plugin_start != NULL &&
       toolbox_end < plugin_start);

  /* Verify the full XML closes properly */
  TEST("integration: closes with </system_settings>",
       strstr(buf, "</system_settings>") != NULL);
}

int main(void) {
  printf("=== MemDBG ShellUI Plugin Tests ===\n");

  if (setup_mock_plugin_dir() != 0) {
    printf("ERROR: failed to set up mock plugin directory\n");
    return 1;
  }

  test_plugin_discovery();
  test_discovery_end_to_end();
  test_plugin_xml_generation();
  test_full_xml_integration();

  /* Cleanup */
  remove(g_plugin_path);
  rmdir(g_tmpdir);

  printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  printf("Total:  %d\n", total);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}
