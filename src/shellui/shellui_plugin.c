/*
 * MemDBG - ShellUI plugin discovery and dynamic XML generation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scans plugin directories for .memdbg_plugin metadata files.
 * Each file contains a binary header followed by key=value lines
 * describing ShellUI elements (toggle_switch, button, label, text_field).
 */

#include "shellui_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <sys/fcntl.h>
#include <unistd.h>

/* ---- Plugin metadata file format ----
 *
 * Binary header (16 bytes):
 *   char prefix[14]    = "MEMDBG_PLUGIN"
 *   uint16_t elements  = number of element lines following
 *
 * Element lines (one per element, format):
 *   TYPE:ID:TITLE:SECOND_TITLE:DEFAULT_VALUE
 *
 * TYPE is one of:
 *   toggle_switch, button, label, text_field
 */

/* Directories to scan for plugins.
 * Override via shellui_plugin_set_dir() (useful for testing). */
static const char *g_plugin_dir = NULL;

static const char *get_plugin_dir(void) {
  return g_plugin_dir ? g_plugin_dir : "/user/data/memdbg/plugins";
}

void shellui_plugin_set_dir(const char *dir) {
  g_plugin_dir = dir;
}

static shellui_element_type_t parse_element_type(const char *s) {
  if (!s) return SHELLUI_EL_LABEL;
  if (strcmp(s, "toggle_switch") == 0) return SHELLUI_EL_TOGGLE_SWITCH;
  if (strcmp(s, "button") == 0)        return SHELLUI_EL_BUTTON;
  if (strcmp(s, "text_field") == 0)    return SHELLUI_EL_TEXT_FIELD;
  if (strcmp(s, "link") == 0)          return SHELLUI_EL_LINK;
  return SHELLUI_EL_LABEL;
}

/* Parse one plugin metadata file */
static int parse_plugin_file(const char *path,
                             shellui_plugin_def_t *plugin) {
  FILE *f = fopen(path, "rb");
  if (!f) return -1;

  /* Read binary header */
  memdbg_plugin_header_t header;
  if (fread(&header, 1, sizeof(header), f) != sizeof(header)) {
    fclose(f);
    return -1;
  }

  /* Validate prefix */
  if (strncmp(header.prefix, "MEMDBG_PLUGIN", 13) != 0) {
    fclose(f);
    return -1;
  }

  /* Copy plugin identity from filename */
  const char *basename = strrchr(path, '/');
  basename = basename ? basename + 1 : path;

  /* Remove .memdbg_plugin extension */
  size_t name_len = strlen(basename);
  size_t copy_len = name_len > 14 ? name_len - 14 : name_len;
  if (copy_len >= sizeof(plugin->plugin_id)) copy_len = sizeof(plugin->plugin_id) - 1;
  memcpy(plugin->plugin_id, basename, copy_len);
  plugin->plugin_id[copy_len] = '\0';

  snprintf(plugin->plugin_name, sizeof(plugin->plugin_name),
           "%s", plugin->plugin_id);
  snprintf(plugin->plugin_version, sizeof(plugin->plugin_version),
           "1.0");

  /* Read element lines */
  int count = 0;
  int max_elements = header.shellui_elements;
  if (max_elements > 16) max_elements = 16;

  char line[512];
  while (count < max_elements && fgets(line, sizeof(line), f)) {
    /* Trim newline */
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
      line[--len] = '\0';

    if (line[0] == '#' || line[0] == '\0') continue;

    shellui_plugin_element_t *el = &plugin->elements[count];

    /* Format: TYPE:ID:TITLE:SECOND_TITLE:DEFAULT_VALUE */
    char *saveptr = NULL;
    char *type_str = strtok_r(line, ":", &saveptr);
    char *id_str   = strtok_r(NULL, ":", &saveptr);
    char *title_str = strtok_r(NULL, ":", &saveptr);
    char *second_str = strtok_r(NULL, ":", &saveptr);
    char *value_str  = strtok_r(NULL, ":", &saveptr);

    el->type = parse_element_type(type_str);
    if (id_str)   snprintf(el->id, sizeof(el->id), "%s", id_str);
    else          el->id[0] = '\0';
    if (title_str) snprintf(el->title, sizeof(el->title), "%s", title_str);
    else           el->title[0] = '\0';
    if (second_str) snprintf(el->second_title, sizeof(el->second_title),
                              "%s", second_str);
    else            el->second_title[0] = '\0';
    if (value_str)  snprintf(el->default_value, sizeof(el->default_value),
                              "%s", value_str);
    else            snprintf(el->default_value, sizeof(el->default_value), "0");

    count++;
  }

  fclose(f);
  plugin->element_count = count;
  return 0;
}

/* Scan directories for .memdbg_plugin files */
int shellui_plugin_discover(shellui_plugin_def_t *plugins, int max_plugins) {
  if (!plugins || max_plugins <= 0) return 0;
  int found = 0;

  const char *scan_dir = get_plugin_dir();
  DIR *dir = opendir(scan_dir);
  if (!dir) return 0;

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL && found < max_plugins) {
    const char *name = entry->d_name;
    size_t name_len = strlen(name);

    /* Match .memdbg_plugin files */
    if (name_len > 14 &&
        strcmp(name + name_len - 14, ".memdbg_plugin") == 0) {
      char full_path[512];
      snprintf(full_path, sizeof(full_path),
               "%s/%s", scan_dir, name);

      if (parse_plugin_file(full_path, &plugins[found]) == 0)
        found++;
    }
  }
  closedir(dir);

  return found;
}

/* Generate ShellUI XML for all discovered plugins */
int shellui_plugin_xml_generate(char *buf, size_t buf_size,
                                const shellui_plugin_def_t *plugins,
                                int plugin_count) {
  if (!buf || buf_size == 0 || !plugins || plugin_count <= 0) return 0;

  size_t pos = 0;

  (void)snprintf(buf + pos, buf_size - pos > 0 ? buf_size - pos : 0,
    "  <!-- === Plugin Section === -->\n");

  for (int p = 0; p < plugin_count; p++) {
    const shellui_plugin_def_t *plugin = &plugins[p];

    pos = strlen(buf);
    if (pos >= buf_size) break;

    snprintf(buf + pos, buf_size - pos,
      "  <setting_list id=\"id_plugin_%s\""
      " title=\"%s (v%s)\">\n",
      plugin->plugin_id, plugin->plugin_name, plugin->plugin_version);
    pos = strlen(buf);

    for (int e = 0; e < plugin->element_count; e++) {
      const shellui_plugin_element_t *el = &plugin->elements[e];
      if (pos >= buf_size) break;

      switch (el->type) {
      case SHELLUI_EL_TOGGLE_SWITCH:
        snprintf(buf + pos, buf_size - pos,
          "    <toggle_switch id=\"%s\""
          " title=\"%s\""
          " second_title=\"%s\""
          " value=\"%s\"/>\n",
          el->id, el->title, el->second_title, el->default_value);
        pos = strlen(buf);
        break;

      case SHELLUI_EL_BUTTON:
        snprintf(buf + pos, buf_size - pos,
          "    <button id=\"%s\""
          " title=\"%s\""
          " second_title=\"%s\"/>\n",
          el->id, el->title, el->second_title);
        pos = strlen(buf);
        break;

      case SHELLUI_EL_LABEL:
        snprintf(buf + pos, buf_size - pos,
          "    <label id=\"%s\""
          " title=\"%s\""
          " style=\"center\"/>\n",
          el->id, el->title);
        pos = strlen(buf);
        break;

      case SHELLUI_EL_TEXT_FIELD:
        snprintf(buf + pos, buf_size - pos,
          "    <text_field id=\"%s\""
          " title=\"%s\""
          " keyboard_type=\"ascii\""
          " min_length=\"1\" max_length=\"255\""
          " value=\"%s\"/>\n",
          el->id, el->title, el->default_value);
        pos = strlen(buf);
        break;

      case SHELLUI_EL_LINK:
        snprintf(buf + pos, buf_size - pos,
          "    <link id=\"%s\""
          " title=\"%s\""
          " file=\"%s\""
          " second_title=\"%s\"/>\n",
          el->id, el->title, el->default_value, el->second_title);
        pos = strlen(buf);
        break;
      }
    }
    pos = strlen(buf);
    if (pos < buf_size)
      snprintf(buf + pos, buf_size - pos, "  </setting_list>\n");
  }

  return (int)strlen(buf);
}
