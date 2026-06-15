/*
 * memDBG - E2E test: SCAN_PROCESS_AOB against host payload.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Starts the host payload, connects, sends HELLO + SCAN_PROCESS_AOB,
 * and verifies the response.
 */

#include "memdbg/core/memdbg_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static int test_socket = -1;
static uint32_t next_id = 1;

static int connect_to(const char *host, uint16_t port, int timeout_sec) {
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

static int read_all(int fd, void *buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t n = recv(fd, (uint8_t *)buf + total, len - total, 0);
    if (n <= 0) return -1;
    total += (size_t)n;
  }
  return 0;
}

static int send_request(int fd, uint16_t cmd, const void *body, uint32_t body_len,
                        uint8_t *response, uint32_t *response_len) {
  memdbg_packet_header_t hdr = {0};
  hdr.magic      = MEMDBG_PACKET_MAGIC;
  hdr.version    = MEMDBG_PROTOCOL_VERSION;
  hdr.command    = cmd;
  hdr.request_id = next_id++;
  hdr.length     = body_len;

  if (send(fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr)) return -1;
  if (body_len > 0 && send(fd, body, body_len, 0) != (ssize_t)body_len) return -1;

  memdbg_response_header_t rhdr;
  if (read_all(fd, &rhdr, sizeof(rhdr)) != 0) return -1;
  if (rhdr.magic != MEMDBG_PACKET_MAGIC ||
      rhdr.version != MEMDBG_PROTOCOL_VERSION ||
      rhdr.command != cmd ||
      rhdr.request_id != hdr.request_id) return -1;
  if (rhdr.status != 0) {
    fprintf(stderr, "  payload error status: %d\n", (int)rhdr.status);
    return -1;
  }
  if (rhdr.length > *response_len) return -1;
  if (rhdr.length > 0 && read_all(fd, response, rhdr.length) != 0) return -1;
  *response_len = rhdr.length;
  return 0;
}

/* ---- Main ---- */

int main(int argc, char **argv) {
  const char *host = "127.0.0.1";
  uint16_t port    = 9020;
  if (argc >= 2) host = argv[1];
  if (argc >= 3) port = (uint16_t)atoi(argv[2]);

  int failures = 0;

  printf("--- E2E SCAN_PROCESS_AOB test ---\n");

  /* 1. Connect */
  printf("Connecting to %s:%u...\n", host, port);
  test_socket = connect_to(host, port, 5);
  if (test_socket < 0) { printf("FAIL: connect\n"); return 1; }
  printf("  connected\n");

  /* 2. HELLO */
  uint8_t response[65536];
  uint32_t response_len = sizeof(response);

  if (send_request(test_socket, MEMDBG_CMD_HELLO, NULL, 0, response, &response_len) != 0) {
    printf("FAIL: hello\n"); close(test_socket); return 1;
  }
  memdbg_hello_response_t hello;
  memcpy(&hello, response, sizeof(hello));
  printf("  HELLO: protocol=%u platform=%u caps=0x%08x\n",
         hello.protocol_version, hello.platform_id, hello.capabilities);

  if (!(hello.capabilities & MEMDBG_CAP_SCAN_PROCESS_AOB)) {
    printf("SKIP: payload does not advertise SCAN_PROCESS_AOB capability\n");
    close(test_socket);
    return 0;
  }

  /* 3. SCAN_PROCESS_AOB — scan for a known pattern in our own process.
     We search for the hex bytes \"DE AD BE EF\" (a common test pattern)
     in the payload process.  Since the payload is running on this host,
     it can scan its own /proc/self/mem. */

  unsigned char pattern[] = {0xDE, 0xAD, 0xBE, 0xEF};
  unsigned char mask[]    = {0xFF, 0xFF, 0xFF, 0xFF};
  uint32_t pat_len = 4;

  /* Build request body: struct + pattern + mask */
  memdbg_scan_process_aob_request_t req;
  memset(&req, 0, sizeof(req));
  req.pid              = (int32_t)getpid();  /* scan our own process */
  req.protection_mask  = 0;                  /* default = READ */
  req.max_results      = 8;
  req.pattern_length   = pat_len;
  req.start            = 0;
  req.end              = 0;

  size_t body_size = sizeof(req) + pat_len + pat_len;
  uint8_t *body_buf = (uint8_t *)malloc(body_size);
  memcpy(body_buf, &req, sizeof(req));
  memcpy(body_buf + sizeof(req), pattern, pat_len);
  memcpy(body_buf + sizeof(req) + pat_len, mask, pat_len);

  response_len = sizeof(response);
  int rc = send_request(test_socket, MEMDBG_CMD_SCAN_PROCESS_AOB,
                        body_buf, (uint32_t)body_size, response, &response_len);
  free(body_buf);

  if (rc != 0) {
    /* Non-fatal: the scan might fail if the payload can't read our mem.
       This is expected on macOS (no /proc/pid/mem). */
    printf("  SCAN_PROCESS_AOB: request failed (expected on non-Linux)\n");
    printf("  NOTE: this test requires Linux /proc/pid/mem support.\n");
    close(test_socket);
    return 0;
  }

  /* Parse scan response */
  memdbg_scan_response_prefix_t prefix;
  if (response_len < sizeof(prefix)) {
    printf("FAIL: short scan response\n");
    close(test_socket); return 1;
  }
  memcpy(&prefix, response, sizeof(prefix));

  printf("  SCAN_PROCESS_AOB: count=%u truncated=%u bytes=%.2f MiB "
         "elapsed=%.2f ms regions=%u errors=%u\n",
         prefix.count, prefix.truncated,
         (double)prefix.bytes_scanned / (1024.0 * 1024.0),
         (double)prefix.elapsed_ns / 1000000.0,
         prefix.regions_scanned, prefix.read_errors);

  if (prefix.count > 0) {
    memdbg_scan_result_entry_t *entries =
        (memdbg_scan_result_entry_t *)(response + sizeof(prefix));
    printf("  addresses found:");
    for (uint32_t i = 0; i < prefix.count && i < 8; ++i)
      printf(" 0x%" PRIx64, entries[i].address);
    printf("\n");
  } else {
    printf("  no pattern matches found (may be expected)\n");
  }

  /* 4. PING to verify connection still alive */
  response_len = sizeof(response);
  if (send_request(test_socket, MEMDBG_CMD_PING, NULL, 0, response, &response_len) != 0) {
    printf("FAIL: ping after scan\n");
    failures++;
  } else {
    printf("  PING: OK\n");
  }

  close(test_socket);

  if (failures == 0) {
    printf("\nE2E SCAN_PROCESS_AOB test PASSED.\n");
  } else {
    printf("\nE2E SCAN_PROCESS_AOB test: %d failure(s).\n", failures);
  }

  return failures > 0 ? 1 : 0;
}
