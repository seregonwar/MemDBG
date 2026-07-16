/*
 * memDBG - Scanner request compatibility helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_SCANNER_SCAN_REQUEST_H
#define MEMDBG_SCANNER_SCAN_REQUEST_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

memdbg_status_t memdbg_scan_unknown_request_decode(
    const void *body, uint32_t body_len, memdbg_scan_unknown_request_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SCANNER_SCAN_REQUEST_H */
