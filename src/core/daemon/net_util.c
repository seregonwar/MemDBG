/*
 * Daemon – network utility helpers.
 *
 * This file is part of MemDBG.
 */

#include "memdbg/daemon/net_util.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/telemetry/udp_log.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

/* ---------------------------------------------------------------- */

bool sockaddr_ipv4_host(const struct sockaddr_storage *addr,
                         char *host, size_t hostlen) {
  if (addr == NULL || host == NULL || hostlen == 0U ||
      addr->ss_family != AF_INET) {
    if (host != NULL && hostlen > 0U) host[0] = '\0';
    return false;
  }
  const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
  if (hostlen > 0U) host[0] = '\0';
  return inet_ntop(AF_INET, &sin->sin_addr, host, (socklen_t)hostlen) != NULL;
}

/* ---------------------------------------------------------------- */

bool udp_log_should_follow_client(const memdbg_config_t *cfg) {
  if (cfg == NULL || !cfg->enable_udp_log || cfg->udp_log_port == 0U) {
    return false;
  }
  return strcmp(cfg->udp_log_host, MEMDBG_DEFAULT_UDP_LOG_HOST) == 0 ||
         strcmp(cfg->udp_log_host, "255.255.255.255") == 0 ||
         strcmp(cfg->udp_log_host, "0.0.0.0") == 0 ||
         strcmp(cfg->udp_log_host, "*") == 0;
}

/* ---------------------------------------------------------------- */

bool client_peer_allowed(const memdbg_config_t *cfg,
                         const struct sockaddr_storage *addr) {
  char peer_host[INET_ADDRSTRLEN];

  if (cfg == NULL || cfg->allow_host[0] == '\0') {
    return true;
  }

  if (!sockaddr_ipv4_host(addr, peer_host, sizeof(peer_host))) {
    return false;
  }
  return strcmp(cfg->allow_host, peer_host) == 0;

}

/* ---------------------------------------------------------------- */

void update_udp_log_peer_from_client(const memdbg_config_t *cfg,
                                     const struct sockaddr_storage *addr) {
  char host[INET_ADDRSTRLEN];
  uint16_t port;

  if (!udp_log_should_follow_client(cfg)) return;

  sockaddr_ipv4_host(addr, host, sizeof(host));
  if (host[0] == '\0') return;

  port = cfg->udp_log_port;
  if (memdbg_udp_log_set_destination(host, port, false) == 0) {
    memdbg_log_write(MEMDBG_LOG_INFO,
                     "udp log now following client at %s:%u", host, port);
  } else {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "udp log: failed to follow client at %s:%u", host, port);
  }
}
