/*
 * memDBG - Daemon network utility helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from memdbg.c so that acceptor and network code can share
 * these helpers without duplicating them.
 */

#ifndef MEMDBG_DAEMON_NET_UTIL_H
#define MEMDBG_DAEMON_NET_UTIL_H

#include "memdbg/core/memdbg.h"

#include <stddef.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * sockaddr_ipv4_host - Extract the IPv4 address string from a sockaddr_storage.
 * @ss:       The socket address (must be AF_INET).
 * @host:     Output buffer for the dotted-quad string.
 * @host_len: Size of @host (at least INET_ADDRSTRLEN).
 *
 * Return: true on success, false if @ss is NULL, not AF_INET, or conversion fails.
 */
bool sockaddr_ipv4_host(const struct sockaddr_storage *ss, char *host,
                        size_t host_len);

/**
 * udp_log_should_follow_client - Check whether UDP logging should redirect to
 *                                 the peer that just connected.
 * @cfg: Daemon configuration.
 *
 * Returns true when the configured UDP log host is a wildcard/broadcast address
 * that should be replaced by the connecting client's IP.
 */
bool udp_log_should_follow_client(const memdbg_config_t *cfg);

/**
 * client_peer_allowed - Check whether a connecting peer is on the allowlist.
 * @cfg: Daemon configuration (may have allow_host set).
 * @ss:  The connecting peer's socket address.
 *
 * If cfg->allow_host is empty, every peer is allowed.
 */
bool client_peer_allowed(const memdbg_config_t *cfg,
                         const struct sockaddr_storage *ss);

/**
 * update_udp_log_peer_from_client - Point UDP logging at the connecting client.
 * @cfg: Daemon configuration (UDP host/port).
 * @ss:  The connecting peer's socket address.
 *
 * If udp_log_should_follow_client() is true, redirects the UDP log stream to
 * the connecting client's IP address.  Logs the result.
 */
void update_udp_log_peer_from_client(const memdbg_config_t *cfg,
                                     const struct sockaddr_storage *ss);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DAEMON_NET_UTIL_H */
