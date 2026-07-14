/*
 * MemDBG - ShellUI configuration persistence v2 (INIfile (dirty flag).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "shellui_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool parse_bool(const char *value, bool def) {
  if (!value || !*value) return def;
  if (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 ||
      strcmp(value, "on")  == 0 || strcmp(value, "yes") == 0)
    return true;
  if (strcmp(value, "0") == 0 || strcmp(value, "false") == 0 ||
      strcmp(value, "off") == 0 || strcmp(value, "no") == 0)
    return false;
  return def;
}

static int parse_int(const char *value, int def) {
  if (!value || !*value) return def;
  char *end = NULL;
  long v = strtol(value, &end, 10);
  if (end == value || *end != '\0') return def;
  if (v < 0 || v > 65535) return def;
  return (int)v;
}

void shellui_config_defaults(memdbg_shellui_config_t *cfg) {
  if (!cfg) return;
  cfg->debugger_enabled = true;   cfg->debugger_port     = 9020;
  cfg->tracer_enabled    = true;
  cfg->klog_enabled      = false;  cfg->klog_max_lines    = 5000;
  cfg->ftp_enabled       = false;  cfg->ftp_port          = 1337;
  cfg->ps5debug_enabled  = false;
  cfg->udp_log_enabled   = true;   cfg->udp_log_port      = 9023;
  cfg->auto_start        = true;
  cfg->display_version   = true;
}

bool shellui_config_load(memdbg_shellui_config_t *cfg, const char *path) {
  if (!cfg || !path) return false;
  shellui_config_defaults(cfg);

  FILE *f = fopen(path, "r");
  if (!f) return false;

  char line[512];
  while (fgets(line, sizeof(line), f)) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
      line[--len] = '\0';
    char *start = line;
    while (*start == ' ' || *start == '\t') start++;
    if (*start == '#' || *start == ';' || *start == '\0') continue;
    if (*start == '[') continue;

    char *eq = strchr(start, '=');
    if (!eq) continue;
    *eq = '\0';
    const char *key = start;
    const char *value = eq + 1;
    char *kend = eq - 1;
    while (kend >= key && (*kend == ' ' || *kend == '\t')) *kend-- = '\0';
    while (*value == ' ' || *value == '\t') value++;

    if (strcmp(key, "debugger") == 0)       cfg->debugger_enabled = parse_bool(value, true);
    else if (strcmp(key, "debugger_port") == 0) cfg->debugger_port = parse_int(value, 9020);
    else if (strcmp(key, "tracer") == 0)    cfg->tracer_enabled = parse_bool(value, true);
    else if (strcmp(key, "klog") == 0)      cfg->klog_enabled = parse_bool(value, false);
    else if (strcmp(key, "klog_max_lines") == 0) cfg->klog_max_lines = parse_int(value, 5000);
    else if (strcmp(key, "ftp") == 0)       cfg->ftp_enabled = parse_bool(value, false);
    else if (strcmp(key, "ftp_port") == 0)  cfg->ftp_port = parse_int(value, 1337);
    else if (strcmp(key, "ps5debug") == 0)  cfg->ps5debug_enabled = parse_bool(value, false);
    else if (strcmp(key, "udp_log") == 0)   cfg->udp_log_enabled = parse_bool(value, true);
    else if (strcmp(key, "udp_log_port") == 0) cfg->udp_log_port = parse_int(value, 9023);
    else if (strcmp(key, "auto_start") == 0) cfg->auto_start = parse_bool(value, true);
    else if (strcmp(key, "display_version") == 0) cfg->display_version = parse_bool(value, true);
  }
  fclose(f);
  return true;
}

bool shellui_config_save(const memdbg_shellui_config_t *cfg, const char *path) {
  if (!cfg || !path) return false;
  FILE *f = fopen(path, "w");
  if (!f) return false;

  fprintf(f,
    "[MemDBG]\n"
    "debugger=%d\ndebugger_port=%d\n"
    "tracer=%d\n"
    "klog=%d\nklog_max_lines=%d\n"
    "ftp=%d\nftp_port=%d\n"
    "ps5debug=%d\n"
    "udp_log=%d\nudp_log_port=%d\n"
    "auto_start=%d\ndisplay_version=%d\n",
    cfg->debugger_enabled, cfg->debugger_port,
    cfg->tracer_enabled,
    cfg->klog_enabled, cfg->klog_max_lines,
    cfg->ftp_enabled, cfg->ftp_port,
    cfg->ps5debug_enabled,
    cfg->udp_log_enabled, cfg->udp_log_port,
    cfg->auto_start, cfg->display_version);
  fclose(f);

  /* Invalidate XML cache on save */
  shellui_xml_invalidate();
  return true;
}
