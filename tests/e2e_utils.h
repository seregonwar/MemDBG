/*
 * memDBG - Shared E2E test utilities.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Common socket helpers used by E2E tests (connect, read/write, request/response).
 */

#ifndef MEMDBG_TESTS_E2E_UTILS_H
#define MEMDBG_TESTS_E2E_UTILS_H

#include "memdbg/core/memdbg_protocol.h"

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Socket helpers ---- */

extern int   e2e_test_socket;
extern int   e2e_quiet_errors;

int  e2e_connect(const char *host, uint16_t port, int timeout_sec);
int  e2e_read_all(int fd, void *buf, size_t len);
int  e2e_send_request(int fd, uint16_t cmd,
                      const void *body, uint32_t body_len,
                      uint8_t *response, uint32_t *response_len);

/* Convenience: send a command with no body. */
static inline int e2e_send_cmd(int fd, uint16_t cmd) {
  uint8_t resp[256];
  uint32_t resp_len = sizeof(resp);
  return e2e_send_request(fd, cmd, NULL, 0, resp, &resp_len);
}

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_TESTS_E2E_UTILS_H */
