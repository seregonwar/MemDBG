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
#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/pal/pal_fileio.h"
#include "memdbg/pal/pal_network.h"

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

  (void)snprintf(path, sizeof(path), "/proc/%d/comm", pid);
  fp = fopen(path, "r");
  if (fp == NULL) return true;  /* cannot verify — be conservative */

  if (fgets(comm, sizeof(comm), fp) != NULL) {
    size_t len = strlen(comm);
    if (len > 0U && comm[len - 1U] == '\n') comm[len - 1U] = '\0';
    for (size_t i = 0U; comm[i] != '\0'; ++i) {
      static const char needle[] = "memdbg";
      size_t j = 0U;
      while (needle[j] != '\0' && comm[i + j] != '\0') {
        char c = comm[i + j];
        if (c >= 'A' && c <= 'Z') c = (char)(c + ('a' - 'A'));
        if (c != needle[j]) break;
        ++j;
      }
      if (needle[j] == '\0') {
        (void)fclose(fp);
        return true;
      }
    }
  }
  (void)fclose(fp);
  return false;
}

/* ---- Cooperative previous-instance shutdown ----
 *
 * A PID file is useful after a hard crash, but it is not the best control
 * path for a live daemon.  Ask the listener to stop first: that detaches an
 * active debugger session before the process exits and does not rely on the
 * new payload having signal permission over the old one.
 */

static const char *instance_control_host(const memdbg_config_t *cfg) {
  if (cfg == NULL || cfg->bind_host[0] == '\0' ||
      strcmp(cfg->bind_host, "0.0.0.0") == 0 ||
      strcmp(cfg->bind_host, "*") == 0) {
    return "127.0.0.1";
  }
  return cfg->bind_host;
}

static bool request_previous_shutdown(const memdbg_config_t *cfg) {
  const uint32_t request_id = 0x4d444247U; /* "MDBG" */
  memdbg_packet_header_t request;
  memdbg_response_header_t response;
  socket_t fd = PAL_INVALID_SOCKET;
  bool stopped = false;

  if (cfg == NULL || cfg->debug_port == 0U) return false;
  if (pal_tcp_connect(instance_control_host(cfg), cfg->debug_port, 500U,
                      &fd) != 0) {
    return false;
  }

  memset(&request, 0, sizeof(request));
  request.magic = MEMDBG_PACKET_MAGIC;
  request.version = MEMDBG_PROTOCOL_VERSION;
  request.command = MEMDBG_CMD_SHUTDOWN;
  request.request_id = request_id;

  if (pal_socket_write_all(fd, &request, sizeof(request)) ==
          (ssize_t)sizeof(request) &&
      pal_socket_read_exact(fd, &response, sizeof(response)) ==
          (ssize_t)sizeof(response) &&
      response.magic == MEMDBG_PACKET_MAGIC &&
      response.version == MEMDBG_PROTOCOL_VERSION &&
      response.command == MEMDBG_CMD_SHUTDOWN &&
      response.request_id == request_id && response.status == MEMDBG_OK &&
      response.length == 0U) {
    stopped = true;
    memdbg_log_write(MEMDBG_LOG_INFO,
                     "instance: previous payload accepted shutdown on %s:%u",
                     instance_control_host(cfg), cfg->debug_port);
  }

  (void)pal_socket_close(fd);
  return stopped;
}

static bool request_previous_legacy_shutdown(const memdbg_config_t *cfg) {
  struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t command;
    uint32_t data_len;
  } request = {0xFFAABBCCU, 0xBDDD0002U, 0U};
  uint32_t response = 0U;
  socket_t fd = PAL_INVALID_SOCKET;

  if (cfg == NULL || !cfg->enable_legacy_compat || cfg->legacy_port == 0U)
    return false;
  if (pal_tcp_connect(instance_control_host(cfg), cfg->legacy_port, 500U,
                      &fd) != 0)
    return false;
  const bool accepted =
      pal_socket_write_all(fd, &request, sizeof(request)) ==
          (ssize_t)sizeof(request) &&
      pal_socket_read_exact(fd, &response, sizeof(response)) ==
          (ssize_t)sizeof(response);
  (void)pal_socket_close(fd);
  if (accepted)
    memdbg_log_write(MEMDBG_LOG_INFO,
                     "instance: previous payload accepted legacy shutdown on %s:%u",
                     instance_control_host(cfg), cfg->legacy_port);
  return accepted;
}

static bool wait_for_process_exit(int pid, uint32_t timeout_ms) {
  const uint32_t step_ms = 50U;
  uint32_t waited = 0U;

  while (waited < timeout_ms) {
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 50000000L };
    nanosleep(&ts, NULL);
    if (!process_exists(pid)) return true;
    waited += step_ms;
  }
  return !process_exists(pid);
}

/* ---- Terminate a process: SIGTERM → wait → SIGKILL ---- */

static bool terminate_process(int pid) {
  if (pid <= 0) return true;

  memdbg_log_write(MEMDBG_LOG_INFO, "instance: sending SIGTERM to pid %d",
                   pid);
  if (kill((pid_t)pid, SIGTERM) != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: SIGTERM failed pid=%d: %s", pid,
                     strerror(errno));
    return !process_exists(pid);
  }

  if (wait_for_process_exit(pid, 1000U)) {
    memdbg_log_write(MEMDBG_LOG_INFO, "instance: pid %d exited cleanly", pid);
    return true;
  }

  /* Process still alive — escalate. */
  memdbg_log_write(MEMDBG_LOG_WARN, "instance: SIGKILL pid %d", pid);
  (void)kill((pid_t)pid, SIGKILL);

  if (wait_for_process_exit(pid, 1000U)) {
    memdbg_log_write(MEMDBG_LOG_INFO, "instance: pid %d killed", pid);
    return true;
  }

  memdbg_log_write(MEMDBG_LOG_WARN,
                   "instance: pid %d still alive after SIGKILL", pid);
  return false;
}

/* ---- Public API ---- */

bool memdbg_instance_is_current_process(const memdbg_config_t *cfg) {
  char path[MEMDBG_PATH_MAX];

  if (cfg == NULL || build_pid_path(cfg, path, sizeof(path)) != 0)
    return false;
  return read_pid_file(path) == (int)getpid();
}

memdbg_status_t memdbg_instance_stop_previous(const memdbg_config_t *cfg) {
  char path[MEMDBG_PATH_MAX];
  int prev_pid;
  bool confirmed_live_payload;

  if (cfg == NULL) return MEMDBG_ERR_PARAM;

  if (build_pid_path(cfg, path, sizeof(path)) != 0)
    return MEMDBG_ERR_PARAM;

  /* GoldHEN can invoke an ELF again inside the same loader process.  In that
   * case killing or cooperatively shutting down the PID would also tear down
   * the already healthy instance.  Treat the existing daemon as authoritative
   * and let the second entry point return without touching its sockets. */
  prev_pid = read_pid_file(path);
  if (prev_pid == getpid()) {
    memdbg_log_write(MEMDBG_LOG_INFO,
                     "instance: MemDBG is already running in pid %d",
                     prev_pid);
    return MEMDBG_ERR_STATE;
  }

  /* This also covers old payloads whose pid file was lost or pre-dates the
   * file lifecycle.  Its matching response proves that the listener is
   * memDBG before we ever consider a PID-based fallback. */
  confirmed_live_payload = request_previous_shutdown(cfg);
  if (!confirmed_live_payload)
    confirmed_live_payload = request_previous_legacy_shutdown(cfg);

  prev_pid = read_pid_file(path);
  if (prev_pid <= 0) return MEMDBG_OK; /* no PID fallback available */

  if (!process_exists(prev_pid)) {
    /* Stale PID file — clean it up. */
    memdbg_log_write(MEMDBG_LOG_INFO,
                     "instance: stale pid file for pid %d; removing",
                     prev_pid);
    (void)unlink(path);
    return MEMDBG_OK;
  }

  if (!process_name_contains_memdbg(prev_pid)) {
    memdbg_log_write(confirmed_live_payload ? MEMDBG_LOG_INFO : MEMDBG_LOG_WARN,
                     confirmed_live_payload
                         ? "instance: previous payload is stopping; refusing PID fallback for unrelated pid %d"
                         : "instance: pid %d does not appear to be a MemDBG process; refusing to terminate",
                     prev_pid);
    return MEMDBG_OK;
  }

  return terminate_process(prev_pid) ? MEMDBG_OK : MEMDBG_ERR_STATE;
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
