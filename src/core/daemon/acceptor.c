/*
 * memDBG - Daemon acceptor thread and listener setup.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from memdbg.c.
 */

#include "memdbg/daemon/acceptor.h"

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/core/memdbg_instance.h"
#include "memdbg/pal/pal_network.h"
#include "memdbg/pal/pal_notification.h"
#include "memdbg/pal/pal_time.h"
#include "memdbg/pal/pal_wait.h"
#include "memdbg/daemon/net_util.h"
#include "memdbg/daemon/handler.h"

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

extern atomic_uint g_active_connections;

/* Shared globals declared in daemon_internal.h */
extern atomic_uint g_active_connections;

/* ---- Acceptor thread ---- */

typedef struct {
  socket_t       listen_fd;
  memdbg_config_t cfg;
} acceptor_args_t;

static void *acceptor_thread(void *arg) {
  acceptor_args_t *aargs = (acceptor_args_t *)arg;
  socket_t listen_fd      = aargs->listen_fd;
  memdbg_config_t cfg     = aargs->cfg;
  free(aargs);

  while (!memdbg_daemon_should_stop()) {
    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)sizeof(ss);
    int ready = wait_for_client(listen_fd, MEMDBG_ACCEPT_POLL_MS);

    if (ready == 0) continue;
    if (ready < 0) {
      if (memdbg_daemon_should_stop()) break;
      memdbg_log_write(MEMDBG_LOG_WARN, "acceptor wait failed: %s",
                       pal_socket_last_error());
      break;
    }

    socket_t client_fd = accept(listen_fd, (struct sockaddr *)&ss, &slen);

    if (client_fd < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
      if (memdbg_daemon_should_stop()) break;
      memdbg_log_write(MEMDBG_LOG_WARN, "accept failed: %s",
                       pal_socket_last_error());
      continue;
    }

    if (!client_peer_allowed(&cfg, &ss)) {
      char peer_host[INET_ADDRSTRLEN];
      const char *peer = "unknown";
      if (sockaddr_ipv4_host(&ss, peer_host, sizeof(peer_host)))
        peer = peer_host;
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "client rejected by allowlist: peer=%s allow=%s",
                       peer, cfg.allow_host);
      (void)pal_socket_close(client_fd);
      continue;
    }

    {
      uint32_t post = atomic_fetch_add_explicit(
                          &g_active_connections, 1U,
                          memory_order_acq_rel) + 1U;
      if (post > cfg.max_connections) {
        atomic_fetch_sub_explicit(&g_active_connections, 1U,
                                  memory_order_relaxed);
        memdbg_log_write(MEMDBG_LOG_WARN,
                         "connection rejected: post=%u max=%u",
                         post, cfg.max_connections);
        (void)pal_socket_close(client_fd);
        continue;
      }
    }

    update_udp_log_peer_from_client(&cfg, &ss);
    {
      char peer_host[INET_ADDRSTRLEN];
      if (sockaddr_ipv4_host(&ss, peer_host, sizeof(peer_host))) {
        char notify_msg[INET_ADDRSTRLEN + 32];
        (void)snprintf(notify_msg, sizeof(notify_msg),
                       "MemDBG %s connected", peer_host);
        pal_notification_send(notify_msg);
      }
    }

    connection_args_t *hargs = (connection_args_t *)malloc(sizeof(*hargs));
    if (hargs == NULL) {
      atomic_fetch_sub_explicit(&g_active_connections, 1U,
                                memory_order_relaxed);
      memdbg_log_write(MEMDBG_LOG_ERROR,
                       "failed to allocate handler args; dropping connection");
      (void)pal_socket_close(client_fd);
      continue;
    }
    hargs->client_fd = client_fd;
    hargs->cfg       = cfg;

    pthread_t hthread;
    if (pthread_create(&hthread, NULL, connection_handler_thread, hargs) != 0) {
      atomic_fetch_sub_explicit(&g_active_connections, 1U,
                                memory_order_relaxed);
      memdbg_log_write(MEMDBG_LOG_ERROR,
                       "failed to spawn handler thread; dropping connection");
      free(hargs);
      (void)pal_socket_close(client_fd);
      continue;
    }
    pthread_detach(hthread);
  }

  return NULL;
}

memdbg_status_t open_debug_listener(const memdbg_config_t *cfg,
                                    socket_t *listen_fd) {
  int saved_errno;

  if (cfg == NULL || listen_fd == NULL) return MEMDBG_ERR_PARAM;

  if (cfg->replace_existing) {
    memdbg_status_t rs = memdbg_instance_stop_previous(cfg);
    if (rs == MEMDBG_OK) memdbg_sleep_ms(200U);
  }

  if (pal_tcp_listen(cfg->bind_host, cfg->debug_port, 16, listen_fd) == 0)
    return MEMDBG_OK;

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

int acceptor_start(const memdbg_config_t *cfg, socket_t listen_fd,
                   pthread_t *out_tid) {
  acceptor_args_t *aargs = (acceptor_args_t *)malloc(sizeof(*aargs));
  if (aargs == NULL) {
    memdbg_log_write(MEMDBG_LOG_ERROR, "failed to allocate acceptor args");
    return -1;
  }
  aargs->listen_fd = listen_fd;
  aargs->cfg       = *cfg;

  if (pthread_create(out_tid, NULL, acceptor_thread, aargs) != 0) {
    free(aargs);
    memdbg_log_write(MEMDBG_LOG_ERROR, "failed to create acceptor thread");
    return -1;
  }
  return 0;
}
