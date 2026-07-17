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
#include "memdbg/pal/pal_wait.h"
#include "memdbg/daemon/handler.h"
#include "memdbg/daemon/net_util.h"
#include "memdbg/daemon/response.h"
#include "memdbg/daemon/acceptor.h"

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
#if defined(__linux__)
#include <sys/epoll.h>
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif
#elif defined(__FreeBSD__) || defined(__APPLE__) || defined(PLATFORM_PS4) || \
      defined(PS4) || defined(__ORBIS__) || defined(PLATFORM_PS5) ||        \
      defined(PS5) || defined(__PROSPERO__)
#include <sys/event.h>
#endif
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
  cfg->max_connections  = MEMDBG_DEFAULT_MAX_CONNECTIONS;
  cfg->idle_timeout_ms  = MEMDBG_DEFAULT_IDLE_TIMEOUT_MS;
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

/* ---- Daemon entry point ---- */

int memdbg_daemon_run(const memdbg_config_t *cfg_in) {
  memdbg_config_t cfg;
  socket_t listen_fd = PAL_INVALID_SOCKET;

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
                   "MemDBG %s starting debug=%s:%u legacy=%s:%u udp_log=%s:%u acceptor: %s, max_conn=%u, idle_timeout=%u ms",
                   MEMDBG_VERSION_STRING, cfg.bind_host, cfg.debug_port,
                   cfg.enable_legacy_compat ? cfg.bind_host : "off",
                   cfg.enable_legacy_compat ? cfg.legacy_port : 0U,
                   cfg.enable_udp_log ? cfg.udp_log_host : "off",
                   cfg.enable_udp_log ? cfg.udp_log_port : 0U,
#if defined(__linux__)
                   "epoll",
#elif defined(__FreeBSD__) || defined(__APPLE__) || defined(PLATFORM_PS4) || \
      defined(PS4) || defined(__ORBIS__) || defined(PLATFORM_PS5) ||        \
      defined(PS5) || defined(__PROSPERO__)
                   "kqueue",
#else
                   "select",
#endif
                   cfg.max_connections,
                   cfg.idle_timeout_ms);
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
    memdbg_status_t lstatus = memdbg_legacy_start(&cfg);
    if (lstatus == MEMDBG_OK) {
      memdbg_log_write(MEMDBG_LOG_INFO,
                       "legacy: active on tcp/%u, debugger-intr tcp/755",
                       cfg.legacy_port);
    } else {
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "legacy: disabled: %s",
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
  resp_pool_init();

  if (notification_ready)
    pal_notification_send("MemDBG by seregonwar started");

  pthread_t acceptor_tid;
  if (acceptor_start(&cfg, listen_fd, &acceptor_tid) != 0) {
    memdbg_daemon_request_stop();
    goto shutdown_cleanup;
  }

  (void)pthread_join(acceptor_tid, NULL);

  /* Drain: wait for all active handler threads to finish.
   * listen_fd is closed inside shutdown_cleanup below. */
  /* We spin with a 10ms sleep so we don't burn CPU. */
  memdbg_log_write(MEMDBG_LOG_INFO,
                   "shutdown: draining %u active connections...",
                   atomic_load_explicit(&g_active_connections,
                                        memory_order_relaxed));
  while (atomic_load_explicit(&g_active_connections, memory_order_relaxed) > 0U)
    memdbg_sleep_ms(10U);

shutdown_cleanup:

  memdbg_tracer_daemon_stop();
  memdbg_legacy_stop();

  (void)pal_socket_close(listen_fd);
  memdbg_discovery_stop();
  memdbg_klog_stop();
  memdbg_beacon_stop();
  pal_memory_fd_cache_flush(0);
  memdbg_instance_remove_pid_file(&cfg);
  memdbg_process_maps_cache_flush(0);

  resp_pool_fini();
  memdbg_log_write(MEMDBG_LOG_INFO, "MemDBG stopped");
  if (notification_ready) pal_notification_shutdown();
  memdbg_udp_log_stop();
  memdbg_log_close();
  pal_network_fini();
  return MEMDBG_OK;
}
