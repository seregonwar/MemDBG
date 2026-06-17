/*
 * memDBG — UDP discovery listener implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Binds a UDP socket on the configured discovery port, optionally with
 * SO_REUSEADDR, and runs a recvfrom() loop in a dedicated thread.
 * Every incoming discovery ping triggers a unicast response containing
 * the payload's HELLO-equivalent metadata.
 */

#include "memdbg/telemetry/discovery.h"

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/pal/pal_network.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- Globals ---- */

static socket_t      g_disc_fd      = PAL_INVALID_SOCKET;
static pthread_t     g_disc_thread;
static atomic_bool   g_disc_running = ATOMIC_VAR_INIT(false);

/* ---- Platform-id helper (mirrors memdbg.c) ---- */

static uint16_t discovery_platform_id(void) {
#if defined(PLATFORM_PS4) || defined(PS4)
  return (uint16_t)MEMDBG_PLATFORM_PS4;
#elif defined(PLATFORM_PS5) || defined(PS5)
  return (uint16_t)MEMDBG_PLATFORM_PS5;
#else
  return (uint16_t)MEMDBG_PLATFORM_HOST;
#endif
}

/* ---- Thread main ---- */

static void *discovery_thread_main(void *arg) {
  const memdbg_config_t *cfg = (const memdbg_config_t *)arg;
  memdbg_discovery_response_t resp;
  struct sockaddr_in sender;
  socklen_t sender_len;

  memset(&resp, 0, sizeof(resp));
  resp.magic            = MEMDBG_PACKET_MAGIC;
  resp.protocol_version = MEMDBG_PROTOCOL_VERSION;
  resp.platform_id      = discovery_platform_id();
  resp.capabilities     = memdbg_capabilities(cfg);
  resp.debug_port       = cfg->debug_port;
  resp.udp_log_port     = cfg->enable_udp_log ? cfg->udp_log_port : 0U;
  (void)snprintf(resp.version, sizeof(resp.version), "%s",
                 MEMDBG_VERSION_STRING);
  (void)snprintf(resp.name, sizeof(resp.name), "MemDBG");

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "discovery: listening on udp *:%u", cfg->discovery_port);

  while (atomic_load_explicit(&g_disc_running, memory_order_relaxed)) {
    memdbg_discovery_ping_t ping;
    ssize_t n;

    sender_len = (socklen_t)sizeof(sender);
    n = recvfrom(g_disc_fd, &ping, sizeof(ping), 0,
                 (struct sockaddr *)&sender, &sender_len);

    if (n < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
      if (!atomic_load_explicit(&g_disc_running, memory_order_relaxed)) break;
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "discovery: recvfrom error: %s", strerror(errno));
      break;
    }

    /* Validate magic + version to avoid replying to noise. */
    if ((size_t)n < sizeof(ping) ||
        ping.magic   != MEMDBG_PACKET_MAGIC ||
        ping.version != MEMDBG_PROTOCOL_VERSION) {
      continue;
    }

    n = sendto(g_disc_fd, &resp, sizeof(resp), 0,
               (const struct sockaddr *)&sender, sender_len);

    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
        atomic_load_explicit(&g_disc_running, memory_order_relaxed)) {
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "discovery: sendto failed: %s", strerror(errno));
    }
  }

  return NULL;
}

/* ---- Public API ---- */

memdbg_status_t memdbg_discovery_start(const memdbg_config_t *cfg) {
  struct sockaddr_in addr;
  int one = 1;

  if (cfg == NULL) return MEMDBG_ERR_PARAM;
  if (cfg->discovery_port == 0U) return MEMDBG_OK; /* disabled */

  /* Already running — stop first. */
  memdbg_discovery_stop();

  g_disc_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (g_disc_fd < 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "discovery: socket() failed: %s", strerror(errno));
    return MEMDBG_ERR_NET;
  }

  (void)setsockopt(g_disc_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  (void)setsockopt(g_disc_fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));

  memset(&addr, 0, sizeof(addr));
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port        = htons(cfg->discovery_port);

  if (bind(g_disc_fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int saved = errno;
    (void)pal_socket_close(g_disc_fd);
    g_disc_fd = PAL_INVALID_SOCKET;
    errno = saved;
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "discovery: bind(0.0.0.0:%u) failed: %s",
                     cfg->discovery_port, strerror(errno));
    return MEMDBG_ERR_NET;
  }

  atomic_store_explicit(&g_disc_running, true, memory_order_relaxed);

  if (pthread_create(&g_disc_thread, NULL, discovery_thread_main,
                     (void *)cfg) != 0) {
    atomic_store_explicit(&g_disc_running, false, memory_order_relaxed);
    (void)pal_socket_close(g_disc_fd);
    g_disc_fd = PAL_INVALID_SOCKET;
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "discovery: pthread_create failed: %s", strerror(errno));
    return MEMDBG_ERR_NET;
  }

  return MEMDBG_OK;
}

void memdbg_discovery_stop(void) {
  if (!atomic_exchange_explicit(&g_disc_running, false, memory_order_relaxed))
    return; /* not running */

  /* Close the socket to unblock recvfrom(). */
  if (g_disc_fd >= 0) {
    (void)pal_socket_close(g_disc_fd);
    g_disc_fd = PAL_INVALID_SOCKET;
  }

  (void)pthread_join(g_disc_thread, NULL);
  memdbg_log_write(MEMDBG_LOG_INFO, "discovery: stopped");
}
