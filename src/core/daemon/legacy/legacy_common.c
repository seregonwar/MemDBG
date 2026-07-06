/*
 * memDBG - ps5debug compat: shared helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "legacy_internal.h"

uint32_t legacy_bitswap32(uint32_t value) {
  return ((value >> 1) & 0x55555555U) | ((value << 1) & 0xAAAAAAAAU);
}

uint32_t legacy_status_from_memdbg(memdbg_status_t status) {
  if (status == MEMDBG_OK) return LEGACY_CMD_SUCCESS;
  if (status == MEMDBG_ERR_NOMEM || status == MEMDBG_ERR_NOT_FOUND)
    return LEGACY_CMD_DATA_NULL;
  return LEGACY_CMD_ERROR;
}

int legacy_send_status(socket_t fd, uint32_t status) {
  uint32_t wire = legacy_bitswap32(status);
  return pal_socket_write_all(fd, &wire, sizeof(wire)) < 0 ? -1 : 0;
}

int legacy_send_memdbg_status(socket_t fd, memdbg_status_t status) {
  return legacy_send_status(fd, legacy_status_from_memdbg(status));
}

int legacy_send_blob(socket_t fd, const void *data, size_t length) {
  if (length == 0U) return 0;
  return pal_socket_write_all(fd, data, length) < 0 ? -1 : 0;
}

int legacy_send_sized_string(socket_t fd, const char *data, uint32_t length) {
  if (pal_socket_write_all(fd, &length, sizeof(length)) < 0) return -1;
  return legacy_send_blob(fd, data, length);
}

void legacy_copy_fixed(char *dst, size_t dst_len, const char *src) {
  if (dst == NULL || dst_len == 0U) return;
  memset(dst, 0, dst_len);
  if (src != NULL && src[0] != '\0')
    (void)snprintf(dst, dst_len, "%s", src);
}

bool legacy_is_valid_command(uint32_t command) {
  return (command >> 24U) == 0xBDU;
}

bool legacy_has_body(const void *body, uint32_t body_len, size_t expected) {
  return body != NULL && body_len == expected;
}

uint32_t legacy_platform_id(void) {
#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
  return 5U;
#elif defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
  return 4U;
#else
  return 0U;
#endif
}

int legacy_wait_for_fd(socket_t fd) {
  fd_set rfds;
  struct timeval tv;
  int rc;
  FD_ZERO(&rfds); FD_SET(fd, &rfds);
  tv.tv_sec = 0; tv.tv_usec = 250000;
  do { rc = select(fd + 1, &rfds, NULL, NULL, &tv); } while (rc < 0 && errno == EINTR);
  if (rc <= 0) return rc;
  return FD_ISSET(fd, &rfds) ? 1 : 0;
}

bool legacy_sockaddr_ipv4_host(const struct sockaddr_storage *ss, char *host, size_t host_len) {
  if (ss == NULL || host == NULL || host_len == 0U || ss->ss_family != AF_INET)
    return false;
  const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;
  return inet_ntop(AF_INET, &sin->sin_addr, host, host_len) != NULL;
}

bool legacy_peer_allowed(const memdbg_config_t *cfg, const struct sockaddr_storage *ss) {
  char peer_host[INET_ADDRSTRLEN];
  if (cfg == NULL || cfg->allow_host[0] == '\0') return true;
  if (!legacy_sockaddr_ipv4_host(ss, peer_host, sizeof(peer_host))) return false;
  return strcmp(cfg->allow_host, peer_host) == 0;
}

bool legacy_rw_allowed(const memdbg_config_t *cfg, uint32_t length) {
  uint32_t max_read = cfg != NULL ? cfg->max_read_bytes : MEMDBG_PROTOCOL_MAX_READ;
  return length <= max_read;
}
