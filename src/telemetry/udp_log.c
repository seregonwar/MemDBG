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

#include "memdbg/telemetry/udp_log.h"

#include "memdbg/pal/pal_network.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MEMDBG_UDP_LOG_MAX_DATAGRAM 1200U

static socket_t g_udp_fd = PAL_INVALID_SOCKET;
static struct sockaddr_in g_udp_addr;
static atomic_bool g_udp_enabled = ATOMIC_VAR_INIT(false);

void memdbg_udp_log_config_defaults(memdbg_udp_log_config_t *cfg) {
  if (cfg == NULL) {
    return;
  }
  memset(cfg, 0, sizeof(*cfg));
  (void)snprintf(cfg->host, sizeof(cfg->host), "%s",
                 MEMDBG_DEFAULT_UDP_LOG_HOST);
  cfg->port = MEMDBG_DEFAULT_UDP_LOG_PORT;
  cfg->broadcast = true;
}

memdbg_status_t memdbg_udp_log_start(const memdbg_udp_log_config_t *cfg) {
  memdbg_udp_log_config_t local_cfg;
  if (cfg == NULL) {
    memdbg_udp_log_config_defaults(&local_cfg);
    cfg = &local_cfg;
  }
  if (cfg->port == 0U || cfg->host[0] == '\0') {
    return MEMDBG_ERR_PARAM;
  }

  memdbg_udp_log_stop();

  socket_t fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return MEMDBG_ERR_NET;
  }

  if (cfg->broadcast) {
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
  }

  memset(&g_udp_addr, 0, sizeof(g_udp_addr));
  g_udp_addr.sin_family = AF_INET;
  g_udp_addr.sin_port = htons(cfg->port);
  if (inet_pton(AF_INET, cfg->host, &g_udp_addr.sin_addr) != 1) {
    (void)pal_socket_close(fd);
    return MEMDBG_ERR_PARAM;
  }

  g_udp_fd = fd;
  atomic_store_explicit(&g_udp_enabled, true, memory_order_relaxed);
  return MEMDBG_OK;
}

void memdbg_udp_log_stop(void) {
  atomic_store_explicit(&g_udp_enabled, false, memory_order_relaxed);
  if (g_udp_fd >= 0) {
    (void)pal_socket_close(g_udp_fd);
    g_udp_fd = PAL_INVALID_SOCKET;
  }
  memset(&g_udp_addr, 0, sizeof(g_udp_addr));
}

bool memdbg_udp_log_enabled(void) {
  return atomic_load_explicit(&g_udp_enabled, memory_order_relaxed);
}

void memdbg_udp_log_send(const char *data, size_t len) {
  if (!memdbg_udp_log_enabled() || g_udp_fd < 0 || data == NULL || len == 0U) {
    return;
  }

  while (len != 0U) {
    size_t chunk = len > MEMDBG_UDP_LOG_MAX_DATAGRAM
                       ? MEMDBG_UDP_LOG_MAX_DATAGRAM
                       : len;
    ssize_t n;
    do {
      n = sendto(g_udp_fd, data, chunk, 0, (const struct sockaddr *)&g_udp_addr,
                 (socklen_t)sizeof(g_udp_addr));
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
      return;
    }
    data += chunk;
    len -= chunk;
  }
}
