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
#include "memdbg/pal/pal_wait.h" /* MEMDBG_ACCEPT_POLL_MS */
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

#define MEMDBG_TRACKED_CLIENTS 64U
static pthread_mutex_t g_clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static socket_t g_clients[MEMDBG_TRACKED_CLIENTS];
static pthread_once_t g_clients_once = PTHREAD_ONCE_INIT;

static void clients_init(void) {
  for (size_t i = 0U; i < MEMDBG_TRACKED_CLIENTS; ++i)
    g_clients[i] = PAL_INVALID_SOCKET;
}

static bool acceptor_register_client(socket_t fd) {
  bool registered = false;
  (void)pthread_once(&g_clients_once, clients_init);
  (void)pthread_mutex_lock(&g_clients_mutex);
  for (size_t i = 0U; i < MEMDBG_TRACKED_CLIENTS; ++i) {
    if (g_clients[i] != PAL_INVALID_SOCKET) continue;
    g_clients[i] = fd;
    registered = true;
    break;
  }
  (void)pthread_mutex_unlock(&g_clients_mutex);
  return registered;
}

void acceptor_unregister_client(socket_t fd) {
  (void)pthread_once(&g_clients_once, clients_init);
  (void)pthread_mutex_lock(&g_clients_mutex);
  for (size_t i = 0U; i < MEMDBG_TRACKED_CLIENTS; ++i) {
    if (g_clients[i] == fd) {
      g_clients[i] = PAL_INVALID_SOCKET;
      break;
    }
  }
  (void)pthread_mutex_unlock(&g_clients_mutex);
}

void acceptor_shutdown_clients(void) {
  (void)pthread_once(&g_clients_once, clients_init);
  (void)pthread_mutex_lock(&g_clients_mutex);
  for (size_t i = 0U; i < MEMDBG_TRACKED_CLIENTS; ++i) {
    if (g_clients[i] != PAL_INVALID_SOCKET)
      (void)shutdown(g_clients[i], SHUT_RDWR);
  }
  (void)pthread_mutex_unlock(&g_clients_mutex);
}

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
    socket_t client_fd = accept(listen_fd, (struct sockaddr *)&ss, &slen);

    if (client_fd < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        /* The listening socket is non-blocking.  Polling accept directly is
         * intentionally used here instead of select/kqueue: affected console
         * kernels can return a transient wait error which used to kill the
         * acceptor while leaving the port apparently open. */
        memdbg_sleep_ms(MEMDBG_ACCEPT_POLL_MS);
        continue;
      }
      if (memdbg_daemon_should_stop()) break;
      if (errno == EBADF || errno == ENOTSOCK) break;
      memdbg_log_write(MEMDBG_LOG_WARN, "accept failed: %s",
                       pal_socket_last_error());
      /* A temporary kernel/network error must not permanently disable the
       * protocol endpoint. Keep the retry bounded so it cannot busy-spin. */
      memdbg_sleep_ms(MEMDBG_ACCEPT_POLL_MS);
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

    uint32_t active_after_accept =
        atomic_fetch_add_explicit(&g_active_connections, 1U,
                                  memory_order_acq_rel) + 1U;
    {
      uint32_t post = active_after_accept;
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
    /* A desktop session deliberately opens Control, Memory, Scan and Poll
       sockets.  Notify the console only for the first socket in the session;
       otherwise one user action produces four indistinguishable popups and
       role reconnections keep interrupting the game. */
    if (active_after_accept == 1U) {
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

    if (!acceptor_register_client(client_fd)) {
      atomic_fetch_sub_explicit(&g_active_connections, 1U,
                                memory_order_relaxed);
      free(hargs);
      (void)pal_socket_close(client_fd);
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "connection registry full; dropping connection");
      continue;
    }

    pthread_t hthread;
    if (pthread_create(&hthread, NULL, connection_handler_thread, hargs) != 0) {
      acceptor_unregister_client(client_fd);
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
    if (rs == MEMDBG_ERR_STATE &&
        memdbg_instance_is_current_process(cfg)) {
      errno = EADDRINUSE;
      return MEMDBG_ERR_STATE;
    }
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
