/*
 * memDBG - Shared E2E test utilities (implementation).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "e2e_utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int   e2e_test_socket   = -1;
int   e2e_quiet_errors  = 0;
static uint32_t e2e_next_id = 1;

int e2e_connect(const char *host, uint16_t port, int timeout_sec) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { perror("socket"); return -1; }

  struct timeval tv = { timeout_sec, 0 };
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(port);
  if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
    fprintf(stderr, "inet_pton failed\n"); close(fd); return -1;
  }

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("connect"); close(fd); return -1;
  }
  return fd;
}

int e2e_read_all(int fd, void *buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t n = recv(fd, (uint8_t *)buf + total, len - total, 0);
    if (n <= 0) {
      if (n == 0) fprintf(stderr, "  connection closed by peer\n");
      else perror("  recv");
      return -1;
    }
    total += (size_t)n;
  }
  return 0;
}

int e2e_send_request(int fd, uint16_t cmd,
                     const void *body, uint32_t body_len,
                     uint8_t *response, uint32_t *response_len) {
  memdbg_packet_header_t hdr = {0};
  hdr.magic      = MEMDBG_PACKET_MAGIC;
  hdr.version    = MEMDBG_PROTOCOL_VERSION;
  hdr.command    = cmd;
  hdr.request_id = e2e_next_id++;
  hdr.length     = body_len;

  if (send(fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr)) {
    perror("  send header"); return -1;
  }
  if (body_len > 0 && send(fd, body, body_len, 0) != (ssize_t)body_len) {
    perror("  send body"); return -1;
  }

  memdbg_response_header_t rhdr;
  if (e2e_read_all(fd, &rhdr, sizeof(rhdr)) != 0) return -1;
  if (rhdr.magic != MEMDBG_PACKET_MAGIC ||
      rhdr.version != MEMDBG_PROTOCOL_VERSION ||
      rhdr.command != cmd ||
      rhdr.request_id != hdr.request_id) {
    fprintf(stderr, "  response header mismatch\n");
    return -1;
  }
  if (rhdr.status != 0) {
    if (!e2e_quiet_errors)
      fprintf(stderr, "  payload error status: %d\n", (int)rhdr.status);
    return -1;
  }
  if (rhdr.length > *response_len) {
    fprintf(stderr, "  response too large: %u > %u\n",
            rhdr.length, *response_len);
    return -1;
  }
  if (rhdr.length > 0 && e2e_read_all(fd, response, rhdr.length) != 0)
    return -1;
  *response_len = rhdr.length;
  return 0;
}
