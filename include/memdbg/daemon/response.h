/*
 * memDBG - Protocol response helpers (framing, compression, buffer pool).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from memdbg.c so the monolith is easier to maintain.
 */

#ifndef MEMDBG_DAEMON_RESPONSE_H
#define MEMDBG_DAEMON_RESPONSE_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Framed payload (LZ4 compression) ---- */

memdbg_status_t build_framed_payload(const void *data, uint32_t data_len,
                                     unsigned char **out, uint32_t *out_len);

int send_framed_response(int fd, const memdbg_packet_header_t *req,
                         memdbg_status_t status, const void *data,
                         uint32_t data_len);

/* ---- Raw response ---- */

int send_response(int fd, const memdbg_packet_header_t *req,
                  memdbg_status_t status,
                  const void *payload, uint32_t payload_len);

/* ---- Zero-copy response buffer pool ---- */

void resp_pool_init(void);
void resp_pool_fini(void);
unsigned char *resp_pool_acquire(size_t needed, size_t *out_size);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DAEMON_RESPONSE_H */
