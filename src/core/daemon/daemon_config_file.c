/*
 * MemDBG - Persistent daemon.conf under data_root.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/daemon/daemon_config_file.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/pal/pal_fileio.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t g_runtime_mu = PTHREAD_MUTEX_INITIALIZER;
static memdbg_config_t g_runtime_cfg;
static bool g_runtime_published = false;

int memdbg_daemon_config_path(const char *data_root, char *out, size_t out_size) {
  if (out == NULL || out_size == 0U) return -1;
  const char *root =
      (data_root != NULL && data_root[0] != '\0') ? data_root
                                                 : MEMDBG_DEFAULT_DATA_ROOT;
  const int n =
      snprintf(out, out_size, "%s/%s", root, MEMDBG_DAEMON_CONF_NAME);
  if (n < 0 || (size_t)n >= out_size) {
    out[0] = '\0';
    return -1;
  }
  return 0;
}

static void trim_inplace(char *s) {
  if (s == NULL) return;
  char *begin = s;
  while (*begin != '\0' && isspace((unsigned char)*begin)) ++begin;
  if (begin != s) memmove(s, begin, strlen(begin) + 1U);
  size_t len = strlen(s);
  while (len > 0U && isspace((unsigned char)s[len - 1U])) {
    s[len - 1U] = '\0';
    --len;
  }
}

int memdbg_daemon_config_parse_line(const char *line, memdbg_config_t *cfg) {
  if (line == NULL || cfg == NULL) return -1;
  char buf[256];
  (void)snprintf(buf, sizeof(buf), "%s", line);
  trim_inplace(buf);
  if (buf[0] == '\0' || buf[0] == '#' || buf[0] == ';') return 0;

  char *eq = strchr(buf, '=');
  if (eq == NULL) return -1;
  *eq = '\0';
  char *key = buf;
  char *value = eq + 1;
  trim_inplace(key);
  trim_inplace(value);
  if (key[0] == '\0') return -1;

  if (strcmp(key, "legacy_compat") == 0) {
    if (strcmp(value, "0") == 0 || strcmp(value, "false") == 0 ||
        strcmp(value, "off") == 0 || strcmp(value, "no") == 0) {
      cfg->enable_legacy_compat = false;
      return 0;
    }
    if (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 ||
        strcmp(value, "on") == 0 || strcmp(value, "yes") == 0) {
      cfg->enable_legacy_compat = true;
      return 0;
    }
    return -1;
  }

  /* Unknown keys are ignored so future fields do not break older payloads. */
  return 0;
}

int memdbg_daemon_config_load(const char *data_root, memdbg_config_t *cfg) {
  if (cfg == NULL) return -1;
  char path[MEMDBG_PATH_MAX];
  if (memdbg_daemon_config_path(data_root, path, sizeof(path)) != 0) return -1;

  FILE *fp = fopen(path, "r");
  if (fp == NULL) return 0; /* missing file is fine */

  char line[256];
  while (fgets(line, sizeof(line), fp) != NULL) {
    (void)memdbg_daemon_config_parse_line(line, cfg);
  }
  (void)fclose(fp);
  memdbg_log_write(MEMDBG_LOG_INFO,
                   "daemon.conf: loaded %s (legacy_compat=%d)", path,
                   cfg->enable_legacy_compat ? 1 : 0);
  return 0;
}

int memdbg_daemon_config_save(const char *data_root, const memdbg_config_t *cfg) {
  if (cfg == NULL) return -1;
  const char *root =
      (data_root != NULL && data_root[0] != '\0') ? data_root : cfg->data_root;
  if (pal_mkdir_p(root, MEMDBG_DIR_PERM) != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "daemon.conf: cannot create data root %s", root);
    return -1;
  }

  char path[MEMDBG_PATH_MAX];
  if (memdbg_daemon_config_path(root, path, sizeof(path)) != 0) return -1;

  char tmp[MEMDBG_PATH_MAX + 8];
  if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) < 0 ||
      (size_t)strlen(tmp) >= sizeof(tmp)) {
    return -1;
  }

  FILE *fp = fopen(tmp, "w");
  if (fp == NULL) {
    memdbg_log_write(MEMDBG_LOG_WARN, "daemon.conf: cannot write %s", tmp);
    return -1;
  }
  (void)fprintf(fp,
                "# MemDBG daemon persistent settings\n"
                "# Edited by MEMDBG_CMD_SET_SERVICES; survives payload restart.\n"
                "legacy_compat=%d\n",
                cfg->enable_legacy_compat ? 1 : 0);
  if (fclose(fp) != 0) {
    (void)remove(tmp);
    return -1;
  }
  if (rename(tmp, path) != 0) {
    (void)remove(tmp);
    memdbg_log_write(MEMDBG_LOG_WARN, "daemon.conf: rename failed for %s",
                     path);
    return -1;
  }
  memdbg_log_write(MEMDBG_LOG_INFO,
                   "daemon.conf: saved %s (legacy_compat=%d)", path,
                   cfg->enable_legacy_compat ? 1 : 0);
  return 0;
}

void memdbg_daemon_config_publish(const memdbg_config_t *cfg) {
  if (cfg == NULL) return;
  pthread_mutex_lock(&g_runtime_mu);
  g_runtime_cfg = *cfg;
  g_runtime_published = true;
  pthread_mutex_unlock(&g_runtime_mu);
}

void memdbg_daemon_config_snapshot(memdbg_config_t *out) {
  if (out == NULL) return;
  pthread_mutex_lock(&g_runtime_mu);
  if (g_runtime_published) {
    *out = g_runtime_cfg;
  } else {
    memdbg_config_defaults(out);
  }
  pthread_mutex_unlock(&g_runtime_mu);
}

bool memdbg_daemon_config_legacy_enabled(void) {
  bool enabled = false;
  pthread_mutex_lock(&g_runtime_mu);
  if (g_runtime_published) enabled = g_runtime_cfg.enable_legacy_compat;
  pthread_mutex_unlock(&g_runtime_mu);
  return enabled;
}

void memdbg_daemon_config_set_legacy_enabled(bool enabled) {
  pthread_mutex_lock(&g_runtime_mu);
  if (!g_runtime_published) {
    memdbg_config_defaults(&g_runtime_cfg);
    g_runtime_published = true;
  }
  g_runtime_cfg.enable_legacy_compat = enabled;
  pthread_mutex_unlock(&g_runtime_mu);
}
