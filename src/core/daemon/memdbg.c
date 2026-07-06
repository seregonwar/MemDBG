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

#include "memdbg/core/memdbg.h"

#include "daemon_internal.h"
#include "memdbg/core/memdbg_instance.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/debug/memdbg_process.h"
#include "memdbg/tracer/memdbg_tracer_daemon.h"
#include "memdbg/pal/pal_debug.h"
#include "memdbg/pal/pal_kernel.h"
#include "memdbg/pal/pal_memory.h"
#include "memdbg/pal/pal_network.h"
#include "memdbg/pal/pal_notification.h"
#include "memdbg/privilege/privilege.h"
#include "memdbg/scanner/flashscan.h"
#include "memdbg/telemetry/discovery.h"
#include "memdbg/telemetry/udp_log.h"
#include "memdbg/pal/pal_time.h"
#include "memdbg/pal/lz4.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

#if defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
#include <ps4/klog.h>
#define MEMDBG_DAEMON_CONSOLE 1
#elif defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#include <ps5/klog.h>
#include <sys/reboot.h>
#define MEMDBG_DAEMON_CONSOLE 1
#define MEMDBG_DAEMON_HAS_REBOOT 1
#endif

/* ---- External declarations for features.c ---- */

extern int memdbg_klog_start(pthread_t *out_tid);
extern void memdbg_klog_stop(void);
extern int memdbg_beacon_start(pthread_t *out_tid);
extern void memdbg_beacon_stop(void);

/* ---- Globals ---- */

static atomic_bool g_stop_requested = false;
atomic_uint g_active_connections = 0;
uint64_t    g_start_ticks = 0;

/* ---- Config ---- */

void memdbg_config_defaults(memdbg_config_t *cfg) {
  if (cfg == NULL) return;
  memset(cfg, 0, sizeof(*cfg));
#if defined(PLATFORM_PS4) || defined(PLATFORM_PS5) || defined(PS4) ||          \
    defined(PS5) || defined(__ORBIS__) || defined(__PROSPERO__)
  (void)snprintf(cfg->bind_host, sizeof(cfg->bind_host), "0.0.0.0");
#else
  (void)snprintf(cfg->bind_host, sizeof(cfg->bind_host), "127.0.0.1");
#endif
  (void)snprintf(cfg->udp_log_host, sizeof(cfg->udp_log_host), "%s",
                 MEMDBG_DEFAULT_UDP_LOG_HOST);
  (void)snprintf(cfg->data_root, sizeof(cfg->data_root), "%s",
                 MEMDBG_DEFAULT_DATA_ROOT);
  cfg->debug_port      = MEMDBG_DEFAULT_DEBUG_PORT;
  cfg->legacy_port     = MEMDBG_DEFAULT_LEGACY_PORT;
  cfg->udp_log_port    = MEMDBG_DEFAULT_UDP_LOG_PORT;
  cfg->discovery_port  = MEMDBG_DEFAULT_DISCOVERY_PORT;
  cfg->enable_udp_log  = true;
#if defined(PLATFORM_PS4) || defined(PLATFORM_PS5) || defined(PS4) ||          \
    defined(PS5) || defined(__ORBIS__) || defined(__PROSPERO__)
  cfg->enable_legacy_compat = true;
#else
  cfg->enable_legacy_compat = false;
#endif
  cfg->replace_existing = true;
  cfg->max_packet_bytes = MEMDBG_PROTOCOL_MAX_PACKET;
  cfg->max_read_bytes   = MEMDBG_PROTOCOL_MAX_READ;
  cfg->max_scan_results = 200000U;
}

const char *memdbg_strerror(memdbg_status_t status) {
  switch (status) {
  case MEMDBG_OK:             return "ok";
  case MEMDBG_ERR_PARAM:      return "invalid parameter";
  case MEMDBG_ERR_NOMEM:      return "out of memory";
  case MEMDBG_ERR_IO:         return "i/o error";
  case MEMDBG_ERR_NET:        return "network error";
  case MEMDBG_ERR_PROTOCOL:   return "protocol error";
  case MEMDBG_ERR_UNSUPPORTED: return "unsupported";
  case MEMDBG_ERR_NOT_FOUND:  return "not found";
  case MEMDBG_ERR_PERMISSION: return "permission denied";
  case MEMDBG_ERR_OVERFLOW:   return "overflow";
  case MEMDBG_ERR_STATE:      return "invalid state";
  default:                    return "unknown error";
  }
}

void memdbg_daemon_request_stop(void) {
  atomic_store_explicit(&g_stop_requested, true, memory_order_relaxed);
}

bool memdbg_daemon_should_stop(void) {
  return atomic_load_explicit(&g_stop_requested, memory_order_relaxed);
}

/* ---- Helpers ---- */

uint32_t memdbg_capabilities(const memdbg_config_t *cfg) {
  uint32_t caps = MEMDBG_CAP_PROCESS_LIST | MEMDBG_CAP_PROCESS_MAPS |
                  MEMDBG_CAP_MEMORY_READ | MEMDBG_CAP_MEMORY_WRITE |
                  MEMDBG_CAP_SCAN_EXACT | MEMDBG_CAP_SCAN_PROCESS_EXACT |
                  MEMDBG_CAP_SCAN_TELEMETRY | MEMDBG_CAP_PROCESS_INFO |
                  MEMDBG_CAP_SCAN_AOB | MEMDBG_CAP_SCAN_POINTER |
                  MEMDBG_CAP_FOREGROUND_APP | MEMDBG_CAP_PROCESS_CONTROL |
                  MEMDBG_CAP_BATCH_READ | MEMDBG_CAP_BATCH_WRITE |
                  MEMDBG_CAP_PERF_TELEMETRY | MEMDBG_CAP_LZ4 |
                  MEMDBG_CAP_SCAN_UNKNOWN | MEMDBG_CAP_SCAN_PROCESS_AOB |
                  MEMDBG_CAP_DISCOVERY;
  if (pal_debug_supported())
    caps |= MEMDBG_CAP_DEBUGGER | MEMDBG_CAP_TRACER | MEMDBG_CAP_STACK_WALK;
  if (pal_debug_fpregs_supported())
    caps |= MEMDBG_CAP_DEBUG_FPREGS;
  if (pal_debug_fsgsbase_supported())
    caps |= MEMDBG_CAP_DEBUG_FSGS;
#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
  caps |= MEMDBG_CAP_MEMORY_PROTECT | MEMDBG_CAP_MEMORY_ALLOC;
  if (pal_debug_supported())
    caps |= MEMDBG_CAP_REMOTE_CALL;
#endif
  if (pal_kernel_supported())
    caps |= MEMDBG_CAP_KERNEL_ACCESS;
#if defined(MEMDBG_DAEMON_CONSOLE)
  caps |= MEMDBG_CAP_CONSOLE_UI;
#endif
  if (cfg != NULL && cfg->enable_udp_log)
    caps |= MEMDBG_CAP_UDP_LOG;
#if defined(MEMDBG_HAS_KEYSTONE) || defined(MEMDBG_HAS_ZYDIS)
  caps |= MEMDBG_CAP_DISASSEMBLY;
#endif
  caps |= MEMDBG_CAP_HIJACK_MASK;
  return caps;
}

#define MEMDBG_LZ4_THRESHOLD 4096U

uint64_t monotonic_seconds(void) {
#if defined(CLOCK_MONOTONIC)
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
    return (uint64_t)ts.tv_sec;
  }
#endif
  time_t now = time(NULL);
  return now > 0 ? (uint64_t)now : 0U;
}

/* ---- Framed payload compression ---- */

memdbg_status_t build_framed_payload(const void *data, uint32_t data_len,
                                     unsigned char **out,
                                     uint32_t *out_len) {
  unsigned char *raw;

  if (out == NULL || out_len == NULL || (data == NULL && data_len != 0U)) {
    return MEMDBG_ERR_PARAM;
  }
  *out = NULL;
  *out_len = 0U;

  if (data == NULL || data_len == 0U) {
    raw = (unsigned char *)malloc(1U);
    if (raw == NULL) return MEMDBG_ERR_NOMEM;
    raw[0] = 0x00U;
    *out = raw;
    *out_len = 1U;
    return MEMDBG_OK;
  }

  if (data_len < MEMDBG_LZ4_THRESHOLD) {
    raw = (unsigned char *)malloc(data_len + 1U);
    if (raw == NULL) return MEMDBG_ERR_NOMEM;
    raw[0] = 0x00U;
    memcpy(raw + 1, data, data_len);
    *out = raw;
    *out_len = data_len + 1U;
    return MEMDBG_OK;
  }

  int bound = lz4_compress_bound((int)data_len);
  unsigned char *compressed = (unsigned char *)malloc((size_t)bound + 5U);
  if (compressed == NULL) goto _send_raw;

  int csize = lz4_compress_default((const char *)data, (char *)(compressed + 5),
                                   (int)data_len, bound);
  if (csize <= 0 || (uint32_t)csize >= data_len - (data_len / 8U)) {
    free(compressed);
    goto _send_raw;
  }

  compressed[0] = 0x01U;
  compressed[1] = (unsigned char)(data_len & 0xFFU);
  compressed[2] = (unsigned char)((data_len >> 8U) & 0xFFU);
  compressed[3] = (unsigned char)((data_len >> 16U) & 0xFFU);
  compressed[4] = (unsigned char)((data_len >> 24U) & 0xFFU);
  *out = compressed;
  *out_len = (uint32_t)csize + 5U;
  return MEMDBG_OK;

_send_raw:
  {
    raw = (unsigned char *)malloc(data_len + 1U);
    if (raw == NULL) return MEMDBG_ERR_NOMEM;
    raw[0] = 0x00U;
    memcpy(raw + 1, data, data_len);
    *out = raw;
    *out_len = data_len + 1U;
    return MEMDBG_OK;
  }
}

int send_framed_response(int fd, const memdbg_packet_header_t *req,
                         memdbg_status_t status, const void *data,
                         uint32_t data_len) {
  unsigned char *payload = NULL;
  uint32_t payload_len = 0U;
  memdbg_status_t frame_status =
      build_framed_payload(data, data_len, &payload, &payload_len);
  int rc;

  if (frame_status != MEMDBG_OK) {
    return send_response(fd, req, frame_status, NULL, 0U);
  }

  rc = send_response(fd, req, status, payload, payload_len);
  free(payload);
  return rc;
}

/* ---- Send response ---- */

int send_response(int fd, const memdbg_packet_header_t *req,
                  memdbg_status_t status, const void *payload,
                  uint32_t payload_len) {
  memdbg_response_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic      = MEMDBG_PACKET_MAGIC;
  hdr.version    = MEMDBG_PROTOCOL_VERSION;
  hdr.command    = req != NULL ? req->command : 0U;
  hdr.request_id = req != NULL ? req->request_id : 0U;
  hdr.status     = (int32_t)status;
  hdr.length     = payload_len;

  if (pal_socket_write_all(fd, &hdr, sizeof(hdr)) < 0) return -1;
  if (payload_len != 0U && pal_socket_write_all(fd, payload, payload_len) < 0) return -1;
  return 0;
}

/* daemon_sleep_ms is now memdbg_sleep_ms (from pal_time.h) */

/* ---- Per-client handler ---- */

static int wait_for_client(socket_t listen_fd);

static void handle_client(socket_t fd, const memdbg_config_t *cfg) {
  atomic_fetch_add_explicit(&g_active_connections, 1U, memory_order_relaxed);
  (void)pal_socket_set_nonblocking(fd, false);
  (void)pal_socket_configure(fd);

  while (!memdbg_daemon_should_stop()) {
    memdbg_packet_header_t req;
    int ready = wait_for_client(fd);
    if (ready == 0) continue;
    if (ready < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (memdbg_daemon_should_stop()) break;
    if (pal_socket_read_exact(fd, &req, sizeof(req)) < 0) break;

    if (req.magic != MEMDBG_PACKET_MAGIC || req.version != MEMDBG_PROTOCOL_VERSION ||
        req.length > cfg->max_packet_bytes) {
      (void)send_response(fd, &req, MEMDBG_ERR_PROTOCOL, NULL, 0U);
      break;
    }

    void *body = NULL;
    if (req.length != 0U) {
      body = malloc(req.length);
      if (body == NULL) {
        (void)send_response(fd, &req, MEMDBG_ERR_NOMEM, NULL, 0U);
        break;
      }
      if (pal_socket_read_exact(fd, body, req.length) < 0) { free(body); break; }
    }

    memdbg_status_t status = dispatch_packet(fd, cfg, &req, body);
    free(body);
    if (status != MEMDBG_OK)
      (void)send_response(fd, &req, status, NULL, 0U);
  }

  if (atomic_load_explicit(&g_active_connections, memory_order_relaxed) <= 1U &&
      memdbg_debugger_is_attached()) {
    memdbg_log_write(MEMDBG_LOG_INFO,
                     "debugger: detaching because the last client disconnected");
    (void)memdbg_debugger_detach();
  }

  (void)pal_socket_close(fd);
  atomic_fetch_sub_explicit(&g_active_connections, 1U, memory_order_relaxed);
}

/* ---- Thread pool worker ---- */

typedef struct {
  socket_t            listen_fd;
  const memdbg_config_t *cfg;
} worker_args_t;

static int wait_for_client(socket_t listen_fd) {
  fd_set rfds;
  struct timeval tv;
  int rc;

  FD_ZERO(&rfds);
  FD_SET(listen_fd, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = 250000;

  do {
    rc = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
  } while (rc < 0 && errno == EINTR);

  if (rc <= 0) return rc;
  return FD_ISSET(listen_fd, &rfds) ? 1 : 0;
}

static bool udp_log_should_follow_client(const memdbg_config_t *cfg) {
  if (cfg == NULL || !cfg->enable_udp_log || cfg->udp_log_port == 0U) {
    return false;
  }
  return strcmp(cfg->udp_log_host, MEMDBG_DEFAULT_UDP_LOG_HOST) == 0 ||
         strcmp(cfg->udp_log_host, "255.255.255.255") == 0 ||
         strcmp(cfg->udp_log_host, "0.0.0.0") == 0 ||
         strcmp(cfg->udp_log_host, "*") == 0;
}

static bool sockaddr_ipv4_host(const struct sockaddr_storage *ss, char *host,
                               size_t host_len) {
  const struct sockaddr_in *sin;

  if (ss == NULL || host == NULL || host_len == 0U ||
      ss->ss_family != AF_INET) {
    return false;
  }

  sin = (const struct sockaddr_in *)ss;
  return inet_ntop(AF_INET, &sin->sin_addr, host, host_len) != NULL;
}

static bool client_peer_allowed(const memdbg_config_t *cfg,
                                const struct sockaddr_storage *ss) {
  char peer_host[INET_ADDRSTRLEN];

  if (cfg == NULL || cfg->allow_host[0] == '\0') {
    return true;
  }

  if (!sockaddr_ipv4_host(ss, peer_host, sizeof(peer_host))) {
    return false;
  }

  return strcmp(cfg->allow_host, peer_host) == 0;
}

static void update_udp_log_peer_from_client(const memdbg_config_t *cfg,
                                            const struct sockaddr_storage *ss) {
  char host[INET_ADDRSTRLEN];
  memdbg_status_t status;

  if (!udp_log_should_follow_client(cfg) ||
      !sockaddr_ipv4_host(ss, host, sizeof(host))) {
    return;
  }

  status = memdbg_udp_log_set_destination(host, cfg->udp_log_port, false);
  if (status == MEMDBG_OK) {
    memdbg_log_write(MEMDBG_LOG_INFO, "udp_log: streaming to %s:%u", host,
                     cfg->udp_log_port);
  } else {
    memdbg_log_write(MEMDBG_LOG_WARN, "udp_log: failed to follow client %s:%u: %s",
                     host, cfg->udp_log_port, memdbg_strerror(status));
  }
}

static void *worker_thread(void *arg) {
  worker_args_t *args = (worker_args_t *)arg;
  socket_t listen_fd  = args->listen_fd;
  memdbg_config_t cfg = *args->cfg;

  while (!memdbg_daemon_should_stop()) {
    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)sizeof(ss);
    int ready = wait_for_client(listen_fd);

    if (ready == 0) continue;
    if (ready < 0) {
      if (memdbg_daemon_should_stop()) break;
      memdbg_log_write(MEMDBG_LOG_WARN, "listener wait failed: %s",
                       pal_socket_last_error());
      break;
    }

    socket_t client_fd = accept(listen_fd, (struct sockaddr *)&ss, &slen);

    if (client_fd < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
      if (memdbg_daemon_should_stop()) break;
      memdbg_log_write(MEMDBG_LOG_WARN, "accept failed: %s", pal_socket_last_error());
      continue;
    }

    if (!client_peer_allowed(&cfg, &ss)) {
      char peer_host[INET_ADDRSTRLEN];
      const char *peer = "unknown";
      if (sockaddr_ipv4_host(&ss, peer_host, sizeof(peer_host))) {
        peer = peer_host;
      }
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "client rejected by allowlist: peer=%s allow=%s",
                       peer, cfg.allow_host);
      (void)pal_socket_close(client_fd);
      continue;
    }

    update_udp_log_peer_from_client(&cfg, &ss);
    {
      char peer_host[INET_ADDRSTRLEN];
      if (sockaddr_ipv4_host(&ss, peer_host, sizeof(peer_host))) {
        char notify_msg[INET_ADDRSTRLEN + 32];
        (void)snprintf(notify_msg, sizeof(notify_msg), "MemDBG %s connected",
                       peer_host);
        pal_notification_send(notify_msg);
      }
    }
    handle_client(client_fd, &cfg);
  }

  return NULL;
}

/* ---- Signal handlers ---- */

static void signal_handler(int signum) {
  (void)signum;
  memdbg_daemon_request_stop();
}

static void install_signal_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  (void)sigemptyset(&sa.sa_mask);
  (void)sigaction(SIGINT,  &sa, NULL);
  (void)sigaction(SIGTERM, &sa, NULL);
#ifdef SIGHUP
  (void)sigaction(SIGHUP, &sa, NULL);
#endif
#ifdef SIGPIPE
  sa.sa_handler = SIG_IGN;
  (void)sigaction(SIGPIPE, &sa, NULL);
#endif
}

/* ---- Listener ---- */

static memdbg_status_t open_debug_listener(const memdbg_config_t *cfg,
                                           socket_t *listen_fd) {
  int saved_errno;
  memdbg_status_t replace_status;

  if (cfg == NULL || listen_fd == NULL) return MEMDBG_ERR_PARAM;

  if (cfg->replace_existing) {
    replace_status = memdbg_instance_stop_previous(cfg);
    if (replace_status == MEMDBG_OK) {
      memdbg_sleep_ms(200U);
    }
  }

  if (pal_tcp_listen(cfg->bind_host, cfg->debug_port, 16, listen_fd) == 0) {
    return MEMDBG_OK;
  }

  saved_errno = errno;
  if (!cfg->replace_existing || saved_errno != EADDRINUSE) {
    errno = saved_errno;
    return MEMDBG_ERR_NET;
  }

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "debug port %u is still busy; retrying previous payload stop",
                   cfg->debug_port);
  (void)memdbg_instance_stop_previous(cfg);

  for (uint32_t i = 0U; i < 25U; ++i) {
    memdbg_sleep_ms(100U);
    if (pal_tcp_listen(cfg->bind_host, cfg->debug_port, 16, listen_fd) == 0) {
      memdbg_log_write(MEMDBG_LOG_INFO,
                       "debug listener rebound after replacing previous payload");
      return MEMDBG_OK;
    }
    saved_errno = errno;
    if (saved_errno != EADDRINUSE) break;
  }

  errno = saved_errno;
  return MEMDBG_ERR_NET;
}

/* ---- Daemon entry point ---- */

int memdbg_daemon_run(const memdbg_config_t *cfg_in) {
  memdbg_config_t cfg;
  socket_t listen_fd = PAL_INVALID_SOCKET;
  int worker_count = 0;

  if (cfg_in == NULL) memdbg_config_defaults(&cfg);
  else                cfg = *cfg_in;

  atomic_store_explicit(&g_stop_requested, false, memory_order_relaxed);
  g_start_ticks = monotonic_seconds();

  if (pal_network_init() != 0) return MEMDBG_ERR_NET;

  if (memdbg_log_init(cfg.data_root) != 0) {
    (void)pal_network_fini();
    return MEMDBG_ERR_IO;
  }
  int notification_ready = (pal_notification_init() == 0);

  install_signal_handlers();

  if (cfg.enable_udp_log) {
    memdbg_udp_log_config_t ucfg;
    memdbg_udp_log_config_defaults(&ucfg);
    (void)snprintf(ucfg.host, sizeof(ucfg.host), "%s", cfg.udp_log_host);
    ucfg.port = cfg.udp_log_port;
    ucfg.broadcast = strcmp(cfg.udp_log_host, "255.255.255.255") == 0;
    memdbg_status_t ustatus = memdbg_udp_log_start(&ucfg);
    if (ustatus != MEMDBG_OK)
      memdbg_log_write(MEMDBG_LOG_WARN, "UDP log disabled: %s", memdbg_strerror(ustatus));
  }

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "MemDBG %s starting debug=%s:%u legacy=%s:%u udp_log=%s:%u pool=%d",
                   MEMDBG_VERSION_STRING, cfg.bind_host, cfg.debug_port,
                   cfg.enable_legacy_compat ? cfg.bind_host : "off",
                   cfg.enable_legacy_compat ? cfg.legacy_port : 0U,
                   cfg.enable_udp_log ? cfg.udp_log_host : "off",
                   cfg.enable_udp_log ? cfg.udp_log_port : 0U,
                   MEMDBG_THREAD_POOL_SIZE);
  if (cfg.allow_host[0] != '\0') {
    memdbg_log_write(MEMDBG_LOG_INFO, "network: allowing TCP client %s only",
                     cfg.allow_host);
  }
  memdbg_log_write(MEMDBG_LOG_INFO, "logging: file=%s mirror=%s",
                   memdbg_log_path()[0] ? memdbg_log_path() : "unavailable",
                   memdbg_log_mirror_path()[0] ? memdbg_log_mirror_path() : "off");

  if (memdbg_privilege_supported() &&
      memdbg_privilege_jailbreak_self() != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "privilege: payload escalation failed; memory actions may fail with permission/i-o status");
  }

  if (open_debug_listener(&cfg, &listen_fd) != MEMDBG_OK) {
    memdbg_log_write(MEMDBG_LOG_ERROR, "debug listener failed: %s", pal_socket_last_error());
    if (notification_ready) pal_notification_shutdown();
    memdbg_udp_log_stop();
    memdbg_log_close();
    pal_network_fini();
    return MEMDBG_ERR_NET;
  }

  if (memdbg_instance_write_pid_file(&cfg) != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN, "instance: failed to write pid file");
  }

  if (cfg.enable_legacy_compat) {
    memdbg_status_t lstatus = memdbg_ps5debug_compat_start(&cfg);
    if (lstatus == MEMDBG_OK) {
      memdbg_log_write(MEMDBG_LOG_INFO,
                       "ps5debug-compat: active on tcp/%u", cfg.legacy_port);
    } else {
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "ps5debug-compat: disabled: %s",
                       memdbg_strerror(lstatus));
    }
  }

  {
    memdbg_status_t dstatus = memdbg_discovery_start(&cfg);
    if (dstatus != MEMDBG_OK)
      memdbg_log_write(MEMDBG_LOG_WARN, "discovery: %s",
                       memdbg_strerror(dstatus));
  }

  {
    pthread_t btid;
    if (memdbg_beacon_start(&btid) == 0)
      memdbg_log_write(MEMDBG_LOG_INFO, "beacon: active on udp/0x3F2");
  }

  {
    pthread_t ktid;
    if (memdbg_klog_start(&ktid) == 0)
      memdbg_log_write(MEMDBG_LOG_INFO, "klog: streaming on tcp/0xA00C");
  }

  flashscan_init();

  if (notification_ready)
    pal_notification_send("MemDBG by seregonwar started");

  worker_args_t wargs;
  wargs.listen_fd = listen_fd;
  wargs.cfg       = &cfg;

  pthread_t workers[MEMDBG_THREAD_POOL_SIZE];
  for (int i = 0; i < MEMDBG_THREAD_POOL_SIZE; ++i) {
    if (pthread_create(&workers[i], NULL, worker_thread, &wargs) != 0) {
      memdbg_log_write(MEMDBG_LOG_ERROR, "failed to create worker thread %d", i);
      memdbg_daemon_request_stop();
      break;
    }
    worker_count++;
  }

  for (int i = 0; i < worker_count; ++i)
    (void)pthread_join(workers[i], NULL);

  memdbg_tracer_daemon_stop();
  memdbg_ps5debug_compat_stop();

  (void)pal_socket_close(listen_fd);
  memdbg_discovery_stop();
  memdbg_klog_stop();
  memdbg_beacon_stop();
  pal_memory_fd_cache_flush(0);
  memdbg_instance_remove_pid_file(&cfg);
  memdbg_process_maps_cache_flush(0);

  memdbg_log_write(MEMDBG_LOG_INFO, "MemDBG stopped");
  if (notification_ready) pal_notification_shutdown();
  memdbg_udp_log_stop();
  memdbg_log_close();
  pal_network_fini();
  return MEMDBG_OK;
}
