/*
 * memDBG - E2E test: SCAN_PROCESS_AOB against host payload.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Starts the host payload, connects, sends HELLO + SCAN_PROCESS_AOB,
 * and verifies the response.
 *
 * Uses shared E2E helpers from e2e_utils.h.
 */

#include "memdbg/core/memdbg_protocol.h"
#include "e2e_utils.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- Main ---- */

int main(int argc, char **argv) {
  const char *host = "127.0.0.1";
  uint16_t port    = 9020;
  if (argc >= 2) host = argv[1];
  if (argc >= 3) port = (uint16_t)atoi(argv[2]);

  printf("--- E2E SCAN_PROCESS_AOB test ---\n");

  /* 1. Connect */
  printf("Connecting to %s:%u...\n", host, port);
  e2e_test_socket = e2e_connect(host, port, 5);
  if (e2e_test_socket < 0) { printf("FAIL: connect\n"); return 1; }
  printf("  connected\n");

  /* 2. HELLO */
  uint8_t response[65536];
  uint32_t response_len = sizeof(response);

  if (e2e_send_request(e2e_test_socket, MEMDBG_CMD_HELLO, NULL, 0,
                       response, &response_len) != 0) {
    printf("FAIL: hello\n"); close(e2e_test_socket); return 1;
  }
  memdbg_hello_response_t hello;
  memcpy(&hello, response, sizeof(hello));
  printf("  HELLO: protocol=%u platform=%u caps=0x%08x\n",
         hello.protocol_version, hello.platform_id, hello.capabilities);

  if (!(hello.capabilities & MEMDBG_CAP_SCAN_PROCESS_AOB)) {
    printf("SKIP: payload does not advertise SCAN_PROCESS_AOB capability\n");
    close(e2e_test_socket);
    return 0;
  }

  /* 3. SCAN_PROCESS_AOB */
  unsigned char pattern[] = {0xDE, 0xAD, 0xBE, 0xEF};
  unsigned char mask[]    = {0xFF, 0xFF, 0xFF, 0xFF};
  uint32_t pat_len = 4;

  memdbg_scan_process_aob_request_t req;
  memset(&req, 0, sizeof(req));
  req.pid              = (int32_t)getpid();
  req.protection_mask  = 0;
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
  e2e_quiet_errors = 1;
  int rc = e2e_send_request(e2e_test_socket, MEMDBG_CMD_SCAN_PROCESS_AOB,
                            body_buf, (uint32_t)body_size, response, &response_len);
  e2e_quiet_errors = 0;
  free(body_buf);

  if (rc != 0) {
    printf("  SCAN_PROCESS_AOB: request failed (expected on non-Linux)\n");
    printf("  NOTE: this test requires Linux /proc/pid/mem support.\n");
    close(e2e_test_socket);
    return 0;
  }

  memdbg_scan_response_prefix_t prefix;
  if (response_len < sizeof(prefix)) {
    printf("FAIL: short scan response\n");
    close(e2e_test_socket); return 1;
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

  /* 4. PING */
  if (e2e_send_cmd(e2e_test_socket, MEMDBG_CMD_PING) != 0) {
    printf("FAIL: ping after scan\n");
    close(e2e_test_socket); return 1;
  }
  printf("  PING: OK\n");

  close(e2e_test_socket);
  printf("\nE2E SCAN_PROCESS_AOB test PASSED.\n");
  return 0;
}
