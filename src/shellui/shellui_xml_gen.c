/*
 * MemDBG - ShellUI XML generation v2 (cached).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "shellui_internal.h"
#include "memdbg/core/memdbg_version.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif

/* ---- XML cache (global) ---- */
shellui_xml_cache_t g_xml_cache = { NULL, 0, 0, true, false };

void shellui_xml_invalidate(void) {
  g_xml_cache.dirty = true;
}

static void xml_append(char *buf, size_t *pos, size_t buf_size,
                       const char *fmt, ...) {
  if (!buf || *pos >= buf_size) return;
  va_list args;
  va_start(args, fmt);
  int written = vsnprintf(buf + *pos, buf_size - *pos, fmt, args);
  va_end(args);
  if (written > 0)
    *pos += (size_t)written < (buf_size - *pos)
                ? (size_t)written : (buf_size - *pos - 1);
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

/* Rebuild the XML cache from config + plugins */
static void rebuild_cache(const memdbg_shellui_config_t *cfg,
                          const shellui_plugin_def_t *plugins,
                          int plugin_count) {
  /* Allocate initial buffer */
  size_t cap = 8192;
  char *buf = malloc(cap);
  if (!buf) return;
  size_t pos = 0;
  buf[0] = '\0';

  /* Prologue */
  xml_append(buf, &pos, cap,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">\n\n"
    "<setting_list id=\"id_memdbg_toolbox\""
    " title=\"MemDBG Toolbox\">\n");

  if (cfg->display_version) {
    xml_append(buf, &pos, cap,
      "  <label id=\"id_memdbg_version\""
      " title=\"MemDBG v%s\" style=\"center\"/>\n",
      shellui_version_string());
  }

  xml_append(buf, &pos, cap,
    "  <toggle_switch id=\"id_memdbg_debugger\""
    " title=\"Debugger\""
    " second_title=\"Enable debugger on port %d\""
    " value=\"%d\"/>\n",
    cfg->debugger_port, cfg->debugger_enabled ? 1 : 0);

  xml_append(buf, &pos, cap,
    "  <text_field id=\"id_memdbg_debugger_port\""
    " title=\"Debugger Port\""
    " keyboard_type=\"number\""
    " min_length=\"1\" max_length=\"5\""
    " value=\"%d\"/>\n", cfg->debugger_port);

  xml_append(buf, &pos, cap,
    "  <toggle_switch id=\"id_memdbg_tracer\""
    " title=\"Syscall Tracer\""
    " second_title=\"Trace syscalls on the target process\""
    " value=\"%d\"/>\n", cfg->tracer_enabled ? 1 : 0);

  xml_append(buf, &pos, cap,
    "  <toggle_switch id=\"id_memdbg_klog\""
    " title=\"Kernel Log Streaming\""
    " second_title=\"Stream klog to the frontend\""
    " value=\"%d\"/>\n", cfg->klog_enabled ? 1 : 0);

  xml_append(buf, &pos, cap,
    "  <text_field id=\"id_memdbg_klog_lines\""
    " title=\"Max Klog Lines\""
    " keyboard_type=\"number\""
    " min_length=\"1\" max_length=\"6\""
    " value=\"%d\"/>\n", cfg->klog_max_lines);

  xml_append(buf, &pos, cap,
    "  <toggle_switch id=\"id_memdbg_ftp\""
    " title=\"FTP Server\""
    " second_title=\"FTP access on port %d\""
    " value=\"%d\"/>\n",
    cfg->ftp_port, cfg->ftp_enabled ? 1 : 0);

  xml_append(buf, &pos, cap,
    "  <text_field id=\"id_memdbg_ftp_port\""
    " title=\"FTP Port\""
    " keyboard_type=\"number\""
    " min_length=\"1\" max_length=\"5\""
    " value=\"%d\"/>\n", cfg->ftp_port);

  xml_append(buf, &pos, cap,
    "  <toggle_switch id=\"id_memdbg_ps5debug\""
    " title=\"PS5Debug Compat\""
    " second_title=\"ps5debug-compatible legacy listener on port 7445\""
    " value=\"%d\"/>\n", cfg->ps5debug_enabled ? 1 : 0);

  xml_append(buf, &pos, cap,
    "  <toggle_switch id=\"id_memdbg_udp_log\""
    " title=\"UDP Log Forwarding\""
    " second_title=\"Forward logs to frontend on port %d\""
    " value=\"%d\"/>\n",
    cfg->udp_log_port, cfg->udp_log_enabled ? 1 : 0);

  xml_append(buf, &pos, cap,
    "  <text_field id=\"id_memdbg_udp_log_port\""
    " title=\"UDP Log Port\""
    " keyboard_type=\"number\""
    " min_length=\"1\" max_length=\"5\""
    " value=\"%d\"/>\n", cfg->udp_log_port);

  xml_append(buf, &pos, cap,
    "  <button id=\"id_memdbg_ping\""
    " title=\"Ping Daemon\""
    " second_title=\"Check if the MemDBG daemon is responsive\"/>\n");

  xml_append(buf, &pos, cap,
    "  <button id=\"id_memdbg_shutdown\""
    " title=\"Shutdown Daemon\""
    " second_title=\"Stop all MemDBG services\""
    " confirm=\"This will stop all MemDBG services on the console.\"\n"
    " confirm_phrase=\"OK,Cancel\"/>\n");

  xml_append(buf, &pos, cap,
    "  <toggle_switch id=\"id_memdbg_auto_start\""
    " title=\"Auto-start on Boot\""
    " second_title=\"Start MemDBG services automatically after payload load\""
    " value=\"%d\"/>\n", cfg->auto_start ? 1 : 0);

  xml_append(buf, &pos, cap,
    "  <label id=\"id_memdbg_info\""
    " title=\"Debug:0.0.0.0:%d  UDP:%d  KLOG:%s  FTP:%s\""
    " style=\"center\"/>\n",
    cfg->debugger_port, cfg->udp_log_port,
    cfg->klog_enabled ? "on" : "off",
    cfg->ftp_enabled   ? "on" : "off");

  xml_append(buf, &pos, cap,
    "  <link id=\"id_memdbg_original_debug\""
    " title=\"Debug Settings\""
    " file=\"original_debug.xml\""
    " second_title=\"MemDBG v%s — Debugger:%s:%d  Tracer:%s  FTP:%s:%d\"/>\n",
    shellui_version_string(),
    cfg->debugger_enabled ? "on" : "off", cfg->debugger_port,
    cfg->tracer_enabled    ? "on" : "off",
    cfg->ftp_enabled       ? "on" : "off", cfg->ftp_port);

  xml_append(buf, &pos, cap, "</setting_list>\n");

  /* Plugin sections */
  if (plugins && plugin_count > 0) {
    /* Grow buffer if needed for plugins */
    size_t need = pos + (size_t)plugin_count * 2048;
    if (need > cap) {
      cap = need + 4096;
    char *nb = realloc(buf, cap);
    if (!nb) return; /* realloc failed — leave old cache intact */
    buf = nb;
    }
    shellui_plugin_xml_generate(buf + pos, cap - pos,
                                plugins, plugin_count);
    pos = strlen(buf);
  }

  xml_append(buf, &pos, cap, "</system_settings>\n");

  /* Swap cache */
  g_xml_cache.len  = pos;
  g_xml_cache.cap  = cap;
  g_xml_cache.dirty = false;
  g_xml_cache.valid = true;

  /* Realloc down to exact size */
  char *final_buf = realloc(buf, pos + 1);
  if (final_buf) buf = final_buf;

  free(g_xml_cache.buf);
  g_xml_cache.buf = buf;
}

/* Copy cached XML into caller buffer, rebuilding if needed */
void shellui_xml_generate(char *buf, size_t buf_size,
                          const memdbg_shellui_config_t *cfg,
                          const shellui_plugin_def_t *plugins,
                          int plugin_count) {
  if (!buf || buf_size == 0) return;

  /* Rebuild cache if dirty or never built */
  if (g_xml_cache.dirty || !g_xml_cache.valid)
    rebuild_cache(cfg, plugins, plugin_count);

  /* Copy from cache */
  size_t copy_len = g_xml_cache.len < buf_size - 1
                        ? g_xml_cache.len : buf_size - 1;
  if (g_xml_cache.buf && copy_len > 0) {
    memcpy(buf, g_xml_cache.buf, copy_len);
  }
  buf[copy_len] = '\0';
}

const char *shellui_version_string(void) {
  return MEMDBG_VERSION_STRING;
}
