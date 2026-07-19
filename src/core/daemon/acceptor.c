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
#include "memdbg/daemon/thread_pool.h"

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
#define MEMDBG_TRACKED_SESSIONS 64U
static pthread_mutex_t g_clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static socket_t g_clients[MEMDBG_TRACKED_CLIENTS];
static pthread_once_t g_clients_once = PTHREAD_ONCE_INIT;

typedef struct tracked_session {
  uint64_t session_id;
  uint32_t peer_address;
  uint32_t connections;
  bool used;
} tracked_session_t;

static pthread_mutex_t g_sessions_mutex = PTHREAD_MUTEX_INITIALIZER;
static tracked_session_t g_sessions[MEMDBG_TRACKED_SESSIONS];

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

void acceptor_register_hello_session(socket_t fd, uint64_t session_id,
                                     uint32_t *session_cookie) {
  struct sockaddr_storage ss;
  socklen_t slen = (socklen_t)sizeof(ss);
  uint32_t peer_address;
  size_t match = MEMDBG_TRACKED_SESSIONS;
  size_t empty = MEMDBG_TRACKED_SESSIONS;
  bool notify = false;

  if (session_cookie == NULL || *session_cookie != 0U) return;
  memset(&ss, 0, sizeof(ss));
  if (getpeername(fd, (struct sockaddr *)&ss, &slen) != 0 ||
      ss.ss_family != AF_INET)
    return;
  peer_address = ((const struct sockaddr_in *)&ss)->sin_addr.s_addr;

  (void)pthread_mutex_lock(&g_sessions_mutex);
  for (size_t i = 0U; i < MEMDBG_TRACKED_SESSIONS; ++i) {
    if (!g_sessions[i].used) {
      if (empty == MEMDBG_TRACKED_SESSIONS) empty = i;
      continue;
    }
    if (g_sessions[i].session_id == session_id &&
        g_sessions[i].peer_address == peer_address) {
      match = i;
      break;
    }
  }
  if (match == MEMDBG_TRACKED_SESSIONS) {
    match = empty;
    if (match != MEMDBG_TRACKED_SESSIONS) {
      g_sessions[match].session_id = session_id;
      g_sessions[match].peer_address = peer_address;
      g_sessions[match].connections = 0U;
      g_sessions[match].used = true;
      notify = true;
    }
  }
  if (match != MEMDBG_TRACKED_SESSIONS) {
    ++g_sessions[match].connections;
    *session_cookie = (uint32_t)match + 1U;
  }
  (void)pthread_mutex_unlock(&g_sessions_mutex);

  if (notify) {
    char peer_host[INET_ADDRSTRLEN];
    char notify_msg[INET_ADDRSTRLEN + 32];
    if (sockaddr_ipv4_host(&ss, peer_host, sizeof(peer_host))) {
      memdbg_log_write(MEMDBG_LOG_INFO,
                       "client session established: peer=%s identity=%s",
                       peer_host, session_id != 0U ? "native" : "legacy");
      (void)snprintf(notify_msg, sizeof(notify_msg),
                     "MemDBG %s connected", peer_host);
      pal_notification_send(notify_msg);
    }
  }
}

void acceptor_unregister_hello_session(uint32_t session_cookie) {
  if (session_cookie == 0U || session_cookie > MEMDBG_TRACKED_SESSIONS) return;
  const size_t index = (size_t)session_cookie - 1U;
  (void)pthread_mutex_lock(&g_sessions_mutex);
  if (g_sessions[index].used && g_sessions[index].connections > 0U) {
    --g_sessions[index].connections;
    if (g_sessions[index].connections == 0U)
      memset(&g_sessions[index], 0, sizeof(g_sessions[index]));
  }
  (void)pthread_mutex_unlock(&g_sessions_mutex);
}

/* ---- Acceptor thread ---- */

typedef struct {
  socket_t             listen_fd;
  memdbg_config_t      cfg;
  memdbg_thread_pool_t *pool;
  acceptor_exit_reason_t *exit_reason;
} acceptor_args_t;

static void *acceptor_thread(void *arg) {
  acceptor_args_t *aargs = (acceptor_args_t *)arg;
  socket_t listen_fd      = aargs->listen_fd;
  memdbg_config_t cfg     = aargs->cfg;
  memdbg_thread_pool_t *pool = aargs->pool;
  acceptor_exit_reason_t *exit_reason = aargs->exit_reason;
  free(aargs);

  /* Default to normal stop unless we detect a socket loss. */
  if (exit_reason != NULL) *exit_reason = ACCEPTOR_EXIT_STOP_REQUESTED;

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
      if (errno == EBADF || errno == ENOTSOCK) {
        /* Listener was invalidated (rest mode, kernel reclaim).  Signal the
         * daemon supervisor to recreate the network endpoint. */
        if (exit_reason != NULL)
          *exit_reason = ACCEPTOR_EXIT_LISTENER_LOST;
        break;
      }
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
    /* Console notifications are emitted after a valid HELLO, not for raw TCP
       accepts.  This avoids popups from port probes and lets the four native
       role sockets be grouped by their shared frontend session identity. */

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

    /* Enqueue for handling by a pre-created worker thread.
     * If the pool is shutting down or full, fall back to dropping. */
    if (memdbg_thread_pool_enqueue(pool, hargs) != 0) {
      acceptor_unregister_client(client_fd);
      atomic_fetch_sub_explicit(&g_active_connections, 1U,
                                memory_order_relaxed);
      memdbg_log_write(MEMDBG_LOG_ERROR,
                       "failed to enqueue handler; dropping connection");
      free(hargs);
      (void)pal_socket_close(client_fd);
      continue;
    }
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
                   memdbg_thread_pool_t *pool, pthread_t *out_tid,
                   acceptor_exit_reason_t *exit_reason) {
  acceptor_args_t *aargs = (acceptor_args_t *)malloc(sizeof(*aargs));
  if (aargs == NULL) {
    memdbg_log_write(MEMDBG_LOG_ERROR, "failed to allocate acceptor args");
    return -1;
  }
  aargs->listen_fd = listen_fd;
  aargs->cfg       = *cfg;
  aargs->pool      = pool;
  aargs->exit_reason = exit_reason;

  if (pthread_create(out_tid, NULL, acceptor_thread, aargs) != 0) {
    free(aargs);
    memdbg_log_write(MEMDBG_LOG_ERROR, "failed to create acceptor thread");
    return -1;
  }
  return 0;
}
