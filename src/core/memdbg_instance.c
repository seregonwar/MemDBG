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
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || \
    defined(__NetBSD__) || defined(__OpenBSD__)
#define MEMDBG_HAVE_FLOCK 1
#include <sys/file.h>
#endif

/* ---- Instance ID ---- */

static uint64_t g_daemon_instance_id = 0U;
static uint64_t g_daemon_start_ns = 0U;

uint64_t memdbg_daemon_instance_id(void) {
  if (g_daemon_instance_id == 0U) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
      g_daemon_start_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
                          (uint64_t)ts.tv_nsec;
    uint64_t seed = g_daemon_start_ns ^
                    (uint64_t)(uintptr_t)&g_daemon_instance_id ^
                    (uint64_t)getpid();
    seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
    g_daemon_instance_id = seed ? seed : 1ULL;
  }
  return g_daemon_instance_id;
}

uint64_t memdbg_daemon_start_ns(void) {
  (void)memdbg_daemon_instance_id();
  return g_daemon_start_ns;
}

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

/* ---- Best-effort advisory lock on the PID file ---- */

static void lock_pid_file(int fd, bool exclusive) {
#ifdef MEMDBG_HAVE_FLOCK
  int op = exclusive ? LOCK_EX : LOCK_SH;
  int rc;
  if (fd < 0) return;
  do {
    rc = flock(fd, op);
  } while (rc < 0 && errno == EINTR);
  if (rc < 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: flock failed (fd=%d): %s",
                     fd, strerror(errno));
  }
#else
  (void)fd;
  (void)exclusive;
  /* No flock on this platform — continue without locking. */
#endif
}

static void unlock_pid_file(int fd) {
#ifdef MEMDBG_HAVE_FLOCK
  if (fd < 0) return;
  (void)flock(fd, LOCK_UN);
#else
  (void)fd;
#endif
}

/* ---- Read PID + optional instance token from an already-opened file ---- */

static int read_pid_file_fp(FILE *fp, uint64_t *out_token) {
  char buf[128];
  char *end;
  long pid;
  uint64_t token = 0U;

  if (fp == NULL) return -1;

  if (fgets(buf, sizeof(buf), fp) == NULL) {
    return -1;
  }

  errno = 0;
  pid = strtol(buf, &end, 10);
  if (end == buf || (*end != '\0' && *end != '\n' && *end != '\r' &&
                     *end != ' ' && *end != '\t') ||
      pid <= 0L || pid > (long)INT32_MAX || errno != 0) {
    return -1;                 /* corrupt file — ignore */
  }

  /* Optional instance token (hex) follows the PID.  Old files that only
   * contain the PID are treated as having token == 0. */
  if (*end == ' ' || *end == '\t') {
    const char *tok_start = end + 1;
    while (*tok_start == ' ' || *tok_start == '\t') ++tok_start;
    if (*tok_start != '\0' && *tok_start != '\n' && *tok_start != '\r') {
      char *tok_end = NULL;
      unsigned long long parsed = strtoull(tok_start, &tok_end, 16);
      if (tok_end != tok_start &&
          (*tok_end == '\0' || *tok_end == '\n' || *tok_end == '\r' ||
           *tok_end == ' ' || *tok_end == '\t')) {
        token = (uint64_t)parsed;
      }
    }
  }

  if (out_token != NULL) *out_token = token;
  return (int)pid;
}

/* ---- Read PID + optional instance token from file ---- */

static int read_pid_file(const char *path, uint64_t *out_token) {
  FILE *fp;
  int fd;
  int pid;

  if (path == NULL || path[0] == '\0') return -1;

  fp = fopen(path, "r");
  if (fp == NULL) return -1;   /* file doesn't exist — not an error */

  fd = fileno(fp);
  lock_pid_file(fd, false);
  pid = read_pid_file_fp(fp, out_token);
  unlock_pid_file(fd);
  (void)fclose(fp);

  return pid;
}

/* ---- Check whether a process exists (kill(pid, 0)) ---- */

static bool process_exists(int pid) {
  if (pid <= 0) return false;
  return kill((pid_t)pid, 0) == 0 || errno != ESRCH;
}

/* ---- Verify the target PID actually belongs to a MemDBG instance.
 *      On systems with /proc/<pid>/comm we require the name to contain
 *      "memdbg" (case-insensitive).  On platforms without /proc (PS4/PS5)
 *      we cannot inspect the process, so we REFUSE PID-based termination
 *      and rely on the authoritative TCP SHUTDOWN probe
 *      (request_previous_shutdown) instead.  Returning true here would
 *      let us SIGKILL an unrelated live process (e.g. the shared loader
 *      at a reused PID), which can freeze the console. ---- */

static bool process_name_contains_memdbg(int pid) {
  char path[256];
  char comm[64];
  FILE *fp;

  (void)snprintf(path, sizeof(path), "/proc/%d/comm", pid);
  fp = fopen(path, "r");
  if (fp == NULL) return false;  /* cannot verify — refuse to terminate */

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

/* ---- Verify a daemon is actually listening on the debug port.
 *      A stale PID file can be left behind after a crash; if the kernel
 *      later reuses that PID for a fresh payload launch, the PID file alone
 *      is not enough to conclude MemDBG is already running in this process. */

static bool is_daemon_responsive(const memdbg_config_t *cfg,
                                 uint64_t expected_token) {
  socket_t fd = PAL_INVALID_SOCKET;
  memdbg_packet_header_t request;
  memdbg_response_header_t response;
  memdbg_hello_response_t hello;
  bool responsive = false;

  if (cfg == NULL || cfg->debug_port == 0U) return false;
  if (pal_tcp_connect(instance_control_host(cfg), cfg->debug_port, 500U,
                      &fd) != 0) {
    return false;
  }

  /* pal_tcp_connect already sets send/recv timeouts to 500 ms, but keep the
   * whole probe under a generous ceiling in case the platform ignored it. */
  (void)pal_socket_set_timeouts(fd, 1000U, 1000U);

  memset(&request, 0, sizeof(request));
  request.magic = MEMDBG_PACKET_MAGIC;
  request.version = MEMDBG_PROTOCOL_VERSION;
  request.command = MEMDBG_CMD_HELLO;
  request.request_id = 0x4d444247U; /* "MDBG" */
  request.length = 0U;

  if (pal_socket_write_all(fd, &request, sizeof(request)) ==
          (ssize_t)sizeof(request) &&
      pal_socket_read_exact(fd, &response, sizeof(response)) ==
          (ssize_t)sizeof(response) &&
      response.magic == MEMDBG_PACKET_MAGIC &&
      response.version == MEMDBG_PROTOCOL_VERSION &&
      response.command == MEMDBG_CMD_HELLO &&
      response.request_id == request.request_id &&
      response.status == MEMDBG_OK &&
      response.length == sizeof(memdbg_hello_response_t) &&
      pal_socket_read_exact(fd, &hello, sizeof(hello)) ==
          (ssize_t)sizeof(hello) &&
      hello.protocol_version == MEMDBG_PROTOCOL_VERSION &&
      hello.feature_level == MEMDBG_PROTOCOL_FEATURE_LEVEL) {
    /* If the PID file carried an token, the daemon we are talking to must
     * identify itself with the same instance ID.  A mismatch means the PID
     * was reused by a fresh payload and the file is stale. */
    if (expected_token != 0ULL &&
        hello.daemon_instance_id != expected_token) {
      responsive = false;
    } else {
      responsive = true;
    }
  }

  (void)pal_socket_close(fd);
  return responsive;
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

  /* Never signal our own process or process group.  On consoles the payload
   * shares a PID/PGID with the loader (reused PID 46 on PS4/GoldHEN); a stray
   * SIGTERM/SIGKILL here would tear down the payload itself and freeze the
   * console. */
  if (pid == (int)getpid() || pid == (int)getpgrp()) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: refusing to signal own pid/pgrp %d", pid);
    return true;
  }

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
  int pid;
  uint64_t token = 0U;

  if (cfg == NULL || build_pid_path(cfg, path, sizeof(path)) != 0)
    return false;
  pid = read_pid_file(path, &token);
  if (pid != (int)getpid()) return false;

  /* The PID file matches our PID, but that can happen because of PID reuse
   * after a stale file was left behind.  Only claim this process is the
   * current instance if the daemon is actually responsive on its port and,
   * when the PID file carries an instance token, the daemon reports the
   * same token. */
  return is_daemon_responsive(cfg, token);
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
  uint64_t prev_token = 0U;
  prev_pid = read_pid_file(path, &prev_token);
  if (prev_pid == getpid()) {
    if (is_daemon_responsive(cfg, prev_token)) {
      memdbg_log_write(MEMDBG_LOG_INFO,
                       "instance: MemDBG is already running in pid %d",
                       prev_pid);
      return MEMDBG_ERR_STATE;
    }
    /* The PID file matches our PID but nobody is listening.  This is a
     * stale file left after a crash where the kernel reused the PID. */
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: stale pid file matches current pid %d; removing",
                     prev_pid);
    (void)unlink(path);
    return MEMDBG_OK;
  }

  /* This also covers old payloads whose pid file was lost or pre-dates the
   * file lifecycle.  Its matching response proves that the listener is
   * memDBG before we ever consider a PID-based fallback. */
  confirmed_live_payload = request_previous_shutdown(cfg);
  if (!confirmed_live_payload)
    confirmed_live_payload = request_previous_legacy_shutdown(cfg);

  prev_pid = read_pid_file(path, NULL);
  if (prev_pid <= 0) return MEMDBG_OK; /* no PID fallback available */

  /* Defense-in-depth: never signal ourselves even if the earlier same-PID
   * check was bypassed (e.g. the file was rewritten between reads). */
  if (prev_pid == (int)getpid()) return MEMDBG_OK;

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

  /* Open without truncating, then lock exclusively before modifying.  This
   * keeps two concurrent payload launches from interleaving writes. */
  {
    int fd = open(path, O_WRONLY | O_CREAT, MEMDBG_FILE_PERM);
    if (fd < 0) {
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "instance: cannot write pid file %s: %s",
                       path, strerror(errno));
      return -1;
    }
    lock_pid_file(fd, true);
    if (ftruncate(fd, 0) != 0) {
      int saved = errno;
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "instance: ftruncate failed for %s: %s",
                       path, strerror(errno));
      unlock_pid_file(fd);
      (void)pal_file_close(fd);
      errno = saved;
      return -1;
    }

    fp = fdopen(fd, "w");
    if (fp == NULL) {
      int saved = errno;
      unlock_pid_file(fd);
      (void)close(fd);
      errno = saved;
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "instance: cannot fdopen pid file %s: %s",
                       path, strerror(errno));
      return -1;
    }

    /* New format: "<pid> <instance_id_hex>\n".  Old files that contain only
     * the PID are still read correctly (token == 0 means "no token"). */
    if (fprintf(fp, "%d %016llx\n", getpid(),
                (unsigned long long)memdbg_daemon_instance_id()) < 0) {
      int saved = errno;
      (void)fclose(fp);
      (void)unlink(path);
      errno = saved;
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "instance: failed to write pid to %s: %s",
                       path, strerror(errno));
      return -1;
    }

    unlock_pid_file(fd);
    (void)fclose(fp);
  }
  memdbg_log_write(MEMDBG_LOG_INFO, "instance: wrote pid %d to %s",
                   getpid(), path);
  return 0;
}

void memdbg_instance_remove_pid_file(const memdbg_config_t *cfg) {
  char path[MEMDBG_PATH_MAX];
  pid_t my_pid = getpid();
  int prev_pid;
  FILE *fp;
  int fd;

  if (cfg == NULL) return;
  if (build_pid_path(cfg, path, sizeof(path)) != 0) return;

  /* Lock the file before reading/unlinking so we don't race a concurrent
   * writer that is between ftruncate and fprintf.  Open read-only because
   * we only need to inspect the content before unlinking it. */
  fp = fopen(path, "r");
  if (fp == NULL) return;
  fd = fileno(fp);
  lock_pid_file(fd, true);

  /* Only remove if the file contains our own PID. */
  prev_pid = read_pid_file_fp(fp, NULL);
  if (prev_pid <= 0 || prev_pid != (int)my_pid) {
    unlock_pid_file(fd);
    (void)fclose(fp);
    return;
  }

  if (unlink(path) != 0 && errno != ENOENT)
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "instance: failed to remove pid file %s: %s",
                     path, strerror(errno));
  else
    memdbg_log_write(MEMDBG_LOG_INFO, "instance: removed pid file %s", path);

  unlock_pid_file(fd);
  (void)fclose(fp);
}
