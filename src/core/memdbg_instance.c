/*
 * memDBG — Instance management: PID file and previous-instance termination.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Writes a PID file to ${data_root}/memdbg.pid so subsequent payload
 * injections can discover and terminate the previous daemon.  On startup,
 * if --replace-existing (the default), reads any existing PID file,
 * sends SIGTERM (graceful), waits, and escalates to SIGKILL if needed.
 */

#include "memdbg/core/memdbg_instance.h"

#include "memdbg/core/memdbg_log.h"
#include "memdbg/pal/pal_fileio.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ---- PID file path helper ---- */

static int build_pid_path(const memdbg_config_t *cfg,
                          char *out, size_t out_size) {
  int n;
  if (cfg == NULL || out == NULL || out_size == 0U) {
    errno = EINVAL;
    return -1;
  }
  n = snprintf(out, out_size, "%s/memdbg.pid", cfg->data_root);
  if (n < 0 || (size_t)n >= out_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

/* ---- Read PID from file ---- */

static int read_pid_file(const char *path) {
  FILE *fp;
  char buf[64];
  char *end;
  long pid;

  if (path == NULL || path[0] == '\0') return -1;

  fp = fopen(path, "r");
  if (fp == NULL) return -1;   /* file doesn't exist — not an error */

  if (fgets(buf, sizeof(buf), fp) == NULL) {
    (void)fclose(fp);
    return -1;
  }
  (void)fclose(fp);

  errno = 0;
  pid = strtol(buf, &end, 10);
  if (end == buf || (*end != '\0' && *end != '\n' && *end != '\r') ||
      pid <= 0L || pid > (long)INT32_MAX || errno != 0) {
    return -1;                 /* corrupt file — ignore */
  }
  return (int)pid;
}

/* ---- Check whether a process exists (kill(pid, 0)) ---- */

static bool process_exists(int pid) {
  if (pid <= 0) return false;
  return kill((pid_t)pid, 0) == 0 || errno != ESRCH;
}

/* ---- Verify the target PID actually belongs to a MemDBG instance.
 *      On systems with /proc/<pid>/comm we require the name to contain
 *      "memdbg" (case-insensitive).  On other platforms we accept any
 *      process that exists, because we cannot safely inspect it. ---- */

static bool process_name_contains_memdbg(int pid) {
  char path[256];
  char comm[64];
  FILE *fp;
  size_t len;
  bool found = false;

  (void)snprintf(path, sizeof(path), "/proc/%d/comm", pid);
  fp = fopen(path, "r");
  if (fp == NULL) return true;  /* cannot verify — be conservative */

  if (fgets(comm, sizeof(comm), fp) != NULL) {
    len = strlen(comm);
    if (len > 0U && comm[len - 1U] == '\n') comm[len - 1U] = '\0';
    for (size_t i = 0; comm[i]; ++i) {
      char c = comm[i];
      if ((c >= 'A' && c <= 'Z')) c = (char)(c + ('a' - 'A'));
      if (c == 'm' && strstr(&comm[i], "memdbg") == &comm[i]) {
        found = true;
        break;
      }
    }
  }
  (void)fclose(fp);
  return found;
}

/* ---- Terminate a process: SIGTERM → wait → SIGKILL ---- */

static void terminate_process(int pid) {
  if (pid <= 0) return;

  memdbg_log_write(MEMDBG_LOG_INFO, "instance: sending SIGTERM to pid %d",
                   pid);
  if (kill((pid_t)pid, SIGTERM) != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: SIGTERM failed pid=%d: %s", pid,
                     strerror(errno));
    return;
  }

  /* Wait up to 2 s for graceful shutdown. */
  for (int i = 0; i < 20; ++i) {
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L }; /* 100 ms */
    nanosleep(&ts, NULL);
    if (!process_exists(pid)) {
      memdbg_log_write(MEMDBG_LOG_INFO, "instance: pid %d exited cleanly",
                       pid);
      return;
    }
  }

  /* Process still alive — escalate. */
  memdbg_log_write(MEMDBG_LOG_WARN, "instance: SIGKILL pid %d", pid);
  (void)kill((pid_t)pid, SIGKILL);

  /* Brief wait for the kill to take effect. */
  { struct timespec ts = { .tv_sec = 0, .tv_nsec = 200000000L };
    nanosleep(&ts, NULL); }

  if (!process_exists(pid))
    memdbg_log_write(MEMDBG_LOG_INFO, "instance: pid %d killed", pid);
  else
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: pid %d still alive after SIGKILL", pid);
}

/* ---- Public API ---- */

memdbg_status_t memdbg_instance_stop_previous(const memdbg_config_t *cfg) {
  char path[MEMDBG_PATH_MAX];
  int prev_pid;

  if (cfg == NULL) return MEMDBG_ERR_PARAM;

  if (build_pid_path(cfg, path, sizeof(path)) != 0)
    return MEMDBG_ERR_PARAM;

  prev_pid = read_pid_file(path);
  if (prev_pid <= 0) return MEMDBG_OK; /* no previous instance */

  /* Never kill ourself. */
  if (prev_pid == getpid()) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: pid file contains our own pid (%d); ignoring",
                     prev_pid);
    return MEMDBG_OK;
  }

  if (!process_exists(prev_pid)) {
    /* Stale PID file — clean it up. */
    memdbg_log_write(MEMDBG_LOG_INFO,
                     "instance: stale pid file for pid %d; removing",
                     prev_pid);
    (void)unlink(path);
    return MEMDBG_OK;
  }

  if (!process_name_contains_memdbg(prev_pid)) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: pid %d does not appear to be a MemDBG process; refusing to terminate",
                     prev_pid);
    return MEMDBG_OK;
  }

  terminate_process(prev_pid);
  return MEMDBG_OK;
}

int memdbg_instance_write_pid_file(const memdbg_config_t *cfg) {
  char path[MEMDBG_PATH_MAX];
  FILE *fp;

  if (cfg == NULL) return -1;
  if (build_pid_path(cfg, path, sizeof(path)) != 0) return -1;

  /* Ensure directory exists. */
  if (pal_mkdir_p(cfg->data_root, MEMDBG_DIR_PERM) != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: cannot create data root %s: %s",
                     cfg->data_root, strerror(errno));
    return -1;
  }

  fp = fopen(path, "w");
  if (fp == NULL) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: cannot write pid file %s: %s",
                     path, strerror(errno));
    return -1;
  }

  if (fprintf(fp, "%d\n", getpid()) < 0) {
    int saved = errno;
    (void)fclose(fp);
    (void)unlink(path);
    errno = saved;
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: failed to write pid to %s: %s",
                     path, strerror(errno));
    return -1;
  }

  (void)fclose(fp);
  memdbg_log_write(MEMDBG_LOG_INFO, "instance: wrote pid %d to %s",
                   getpid(), path);
  return 0;
}

void memdbg_instance_remove_pid_file(const memdbg_config_t *cfg) {
  char path[MEMDBG_PATH_MAX];
  pid_t my_pid = getpid();
  int prev_pid;

  if (cfg == NULL) return;
  if (build_pid_path(cfg, path, sizeof(path)) != 0) return;

  /* Only remove if the file contains our own PID. */
  prev_pid = read_pid_file(path);
  if (prev_pid <= 0 || prev_pid != (int)my_pid) return;

  if (unlink(path) != 0 && errno != ENOENT)
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: failed to remove pid file %s: %s",
                     path, strerror(errno));
  else
    memdbg_log_write(MEMDBG_LOG_INFO, "instance: removed pid file %s", path);
}
