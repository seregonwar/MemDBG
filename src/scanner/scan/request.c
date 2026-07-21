/*
 * memDBG - Scanner request compatibility helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/scanner/scan_request.h"

#include <string.h>

memdbg_status_t memdbg_scan_unknown_request_decode(
    const void *body, uint32_t body_len, memdbg_scan_unknown_request_t *out) {
  if (body == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));

  if (body_len == sizeof(memdbg_scan_process_exact_request_t)) {
    memdbg_scan_process_exact_request_t legacy;
    memcpy(&legacy, body, sizeof(legacy));
    out->abi_magic = MEMDBG_SCAN_UNKNOWN_ABI_MAGIC;
    out->abi_version = MEMDBG_SCAN_UNKNOWN_ABI_VERSION;
    out->struct_size = (uint16_t)sizeof(*out);
    out->pid = legacy.pid;
    out->value_type = legacy.value_type;
    out->value_length = legacy.value_length;
    out->alignment = legacy.alignment;
    out->max_results = legacy.max_results;
    out->protection_mask = legacy.protection_mask;
    out->start = legacy.start;
    out->end = legacy.end;
    out->max_bytes = MEMDBG_SCAN_UNKNOWN_MAX_UNIT_BYTES;
    return MEMDBG_OK;
  }

  if (body_len < 8U) return MEMDBG_ERR_PROTOCOL;

  memdbg_scan_unknown_request_t decoded;
  memset(&decoded, 0, sizeof(decoded));
  size_t copy_len = body_len < sizeof(decoded) ? (size_t)body_len
                                               : sizeof(decoded);
  memcpy(&decoded, body, copy_len);
  if (decoded.abi_magic != MEMDBG_SCAN_UNKNOWN_ABI_MAGIC)
    return MEMDBG_ERR_PROTOCOL;
  if (decoded.abi_version != MEMDBG_SCAN_UNKNOWN_ABI_VERSION)
    return MEMDBG_ERR_UNSUPPORTED;
  if (decoded.struct_size != sizeof(decoded) ||
      body_len != (uint32_t)decoded.struct_size)
    return MEMDBG_ERR_PROTOCOL;
  if ((decoded.flags & ~MEMDBG_SCAN_UNKNOWN_KNOWN_FLAGS) != 0U)
    return MEMDBG_ERR_UNSUPPORTED;
  if (decoded.reserved != 0U) return MEMDBG_ERR_PROTOCOL;

  *out = decoded;
  return MEMDBG_OK;
}
