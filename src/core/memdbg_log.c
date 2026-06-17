/*
 * memDBG - Memory debugger payload for jailbroken consoles.
 * Copyright (C) 2026 SeregonWar
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/core/memdbg_log.h"

#include "memdbg/core/memdbg.h"
#include "memdbg/pal/pal_fileio.h"
#include "memdbg/telemetry/udp_log.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MEMDBG_LOG_FILE_NAME "memdbg.log"

static FILE *g_data_log_file = NULL;
static FILE *g_mirror_log_file = NULL;
static bool g_log_stderr = true;
static char g_data_log_path[MEMDBG_PATH_MAX] = "";
static char g_mirror_log_path[MEMDBG_PATH_MAX] = "";
static pthread_mutex_t g_log_mtx = PTHREAD_MUTEX_INITIALIZER;

static const char *level_name(memdbg_log_level_t level) {
  switch (level) {
  case MEMDBG_LOG_DEBUG:
    return "DEBUG";
  case MEMDBG_LOG_INFO:
    return "INFO";
  case MEMDBG_LOG_WARN:
    return "WARN";
  case MEMDBG_LOG_ERROR:
    return "ERROR";
  default:
    return "LOG";
  }
}

static int open_log_sink(const char *root, char *path_out, size_t path_size,
                         FILE **file_out) {
  if (root == NULL || root[0] == '\0' || path_out == NULL || path_size == 0U ||
      file_out == NULL) {
    errno = EINVAL;
    return -1;
  }
  path_out[0] = '\0';
  *file_out = NULL;

  if (pal_mkdir_p(root, MEMDBG_DIR_PERM) != 0) {
    return -1;
  }

  int n = snprintf(path_out, path_size, "%s/%s", root, MEMDBG_LOG_FILE_NAME);
  if (n < 0 || (size_t)n >= path_size) {
    errno = ENAMETOOLONG;
    return -1;
  }

  *file_out = fopen(path_out, "a");
  if (*file_out == NULL) {
    path_out[0] = '\0';
    return -1;
  }
  return 0;
}

int memdbg_log_init(const char *data_root) {
  const char *effective_root = (data_root != NULL && data_root[0] != '\0')
                                   ? data_root
                                   : MEMDBG_DEFAULT_DATA_ROOT;

  memdbg_log_close();

  bool data_ok = open_log_sink(effective_root, g_data_log_path,
                               sizeof(g_data_log_path),
                               &g_data_log_file) == 0;

  /* Mirror only opens when explicitly requested with a different root. */
  bool mirror_ok = false;
  if (data_root != NULL && data_root[0] != '\0' &&
      strcmp(data_root, MEMDBG_DEFAULT_DATA_ROOT) != 0) {
    mirror_ok = open_log_sink(MEMDBG_DEFAULT_DATA_ROOT,
                              g_mirror_log_path, sizeof(g_mirror_log_path),
                              &g_mirror_log_file) == 0;
  }

  return (data_ok || mirror_ok) ? 0 : -1;
}

void memdbg_log_close(void) {
  if (g_data_log_file != NULL) {
    (void)fflush(g_data_log_file);
    (void)fclose(g_data_log_file);
    g_data_log_file = NULL;
  }
  if (g_mirror_log_file != NULL) {
    (void)fflush(g_mirror_log_file);
    (void)fclose(g_mirror_log_file);
    g_mirror_log_file = NULL;
  }
}

void memdbg_log_set_stderr(bool enabled) { g_log_stderr = enabled; }

const char *memdbg_log_path(void) { return g_data_log_path; }

const char *memdbg_log_mirror_path(void) { return g_mirror_log_path; }

void memdbg_log_vwrite(memdbg_log_level_t level, const char *fmt, va_list ap) {
  char body[1024];
  char line[1280];
  time_t now = time(NULL);
  struct tm tmv;

  if (fmt == NULL) {
    return;
  }

#if defined(_POSIX_THREAD_SAFE_FUNCTIONS) || defined(__APPLE__) ||             \
    defined(__linux__) || defined(__FreeBSD__)
  (void)localtime_r(&now, &tmv);
#else
  {
    struct tm *tmp = localtime(&now);
    if (tmp != NULL) {
      tmv = *tmp;
    } else {
      memset(&tmv, 0, sizeof(tmv));
    }
  }
#endif

  (void)vsnprintf(body, sizeof(body), fmt, ap);
  (void)snprintf(line, sizeof(line),
                 "[%04d-%02d-%02d %02d:%02d:%02d] %-5s %s\n",
                 tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour,
                 tmv.tm_min, tmv.tm_sec, level_name(level), body);

  pthread_mutex_lock(&g_log_mtx);
  if (g_data_log_file != NULL) {
    (void)fputs(line, g_data_log_file);
    (void)fflush(g_data_log_file);
  }
  if (g_mirror_log_file != NULL) {
    (void)fputs(line, g_mirror_log_file);
    (void)fflush(g_mirror_log_file);
  }
  pthread_mutex_unlock(&g_log_mtx);

  memdbg_udp_log_send(line, strlen(line));
  if (g_log_stderr) {
    (void)fputs(line, stderr);
  }
}

void memdbg_log_write(memdbg_log_level_t level, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  memdbg_log_vwrite(level, fmt, ap);
  va_end(ap);
}
