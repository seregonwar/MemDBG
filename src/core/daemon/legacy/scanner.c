/*
 * memDBG - ps5debug compat: scanner bridge.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "internal.h"
#include "memdbg/scanner/memdbg_scan.h"

legacy_scan_session_t g_scan_session;

void scan_session_reset(void) {
  if (g_scan_session.addresses != NULL) free(g_scan_session.addresses);
  memset(&g_scan_session, 0, sizeof(g_scan_session));
}

memdbg_status_t scan_session_from_result(memdbg_scan_result_t *result) {
  scan_session_reset();
  if (result->count == 0U) { g_scan_session.active = true; g_scan_session.total = 0U; return MEMDBG_OK; }
  size_t bytes = result->count * sizeof(uint64_t);
  g_scan_session.addresses = (uint64_t *)malloc(bytes);
  if (g_scan_session.addresses == NULL) return MEMDBG_ERR_NOMEM;
  for (size_t i = 0U; i < result->count; ++i) g_scan_session.addresses[i] = result->entries[i].address;
  g_scan_session.active = true; g_scan_session.total = (uint32_t)result->count; g_scan_session.cursor = 0U;
  return MEMDBG_OK;
}

bool scan_session_send_chunk(socket_t fd) {
  if (!g_scan_session.active) { uint32_t zero = 0U; (void)legacy_send_blob(fd, &zero, sizeof(zero)); return false; }
  uint32_t remaining = g_scan_session.total - g_scan_session.cursor;
  uint32_t chunk = remaining > LEGACY_SCAN_CHUNK_MAX ? LEGACY_SCAN_CHUNK_MAX : remaining;
  if (chunk == 0U) { uint32_t zero = 0U; (void)legacy_send_blob(fd, &zero, sizeof(zero)); scan_session_reset(); return false; }
  if (legacy_send_blob(fd, &chunk, sizeof(chunk)) != 0) return false;
  if (legacy_send_blob(fd, g_scan_session.addresses + g_scan_session.cursor, (size_t)chunk * sizeof(uint64_t)) != 0) return false;
  g_scan_session.cursor += chunk;
  if (g_scan_session.cursor >= g_scan_session.total) { uint32_t zero = 0U; (void)legacy_send_blob(fd, &zero, sizeof(zero)); scan_session_reset(); return false; }
  return true;
}

memdbg_status_t legacy_handle_scan_exact(socket_t fd, const void *body, uint32_t body_len) {
  if (body_len < sizeof(legacy_scan_request_t))
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  const legacy_scan_request_t *req = (const legacy_scan_request_t *)body;
  if (req->value_length == 0U || req->value_length > MEMDBG_SCAN_VALUE_MAX)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  if (body_len < sizeof(*req) + (uint32_t)req->value_length)
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;

  memdbg_scan_exact_request_t mreq; memset(&mreq, 0, sizeof(mreq));
  mreq.pid = -1; mreq.start = req->start;
  mreq.length = (req->end > req->start) ? (uint32_t)(req->end - req->start) : 0U;
  mreq.value_type = (uint32_t)req->value_type; mreq.value_length = (uint32_t)req->value_length;
  mreq.alignment = (uint32_t)req->alignment;
  mreq.max_results = req->max_results > 0U ? req->max_results : 200000U;
  if (mreq.max_results > g_legacy_cfg.max_scan_results) mreq.max_results = g_legacy_cfg.max_scan_results;
  memcpy(mreq.value, (const uint8_t *)body + sizeof(*req), req->value_length);

  memdbg_scan_result_t result; memset(&result, 0, sizeof(result));
  memdbg_status_t st = memdbg_scan_exact(&mreq, &result);
  if (st != MEMDBG_OK) { memdbg_scan_result_free(&result); return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }
  st = scan_session_from_result(&result); memdbg_scan_result_free(&result);
  if (st != MEMDBG_OK) return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  (void)scan_session_send_chunk(fd);
  return MEMDBG_OK;
}

memdbg_status_t legacy_handle_scan_aob_start(socket_t fd, const void *body, uint32_t body_len) {
  if (body_len < sizeof(legacy_scan_aob_request_t))
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  const legacy_scan_aob_request_t *req = (const legacy_scan_aob_request_t *)body;
  if (req->pattern_length == 0U || req->pattern_length > 256U)
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  if (body_len < sizeof(*req) + (uint32_t)req->pattern_length * 2U)
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;

  const uint8_t *pattern = (const uint8_t *)body + sizeof(*req);
  const uint8_t *mask = pattern + req->pattern_length;

  memdbg_scan_aob_request_t mreq; memset(&mreq, 0, sizeof(mreq));
  mreq.pid = -1; mreq.start = req->start;
  mreq.length = (req->end > req->start) ? (uint32_t)(req->end - req->start) : 0U;
  mreq.max_results = 200000U; mreq.pattern_length = req->pattern_length;
  if (mreq.max_results > g_legacy_cfg.max_scan_results) mreq.max_results = g_legacy_cfg.max_scan_results;

  memdbg_scan_result_t result; memset(&result, 0, sizeof(result));
  memdbg_status_t st = memdbg_scan_aob(&mreq, pattern, mask, &result);
  if (st != MEMDBG_OK) { memdbg_scan_result_free(&result); return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }
  st = scan_session_from_result(&result); memdbg_scan_result_free(&result);
  if (st != MEMDBG_OK) return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  (void)scan_session_send_chunk(fd);
  return MEMDBG_OK;
}

memdbg_status_t legacy_handle_scan_cont(socket_t fd) {
  if (!g_scan_session.active) { uint32_t zero = 0U; return legacy_send_blob(fd, &zero, sizeof(zero)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }
  (void)scan_session_send_chunk(fd);
  return MEMDBG_OK;
}
