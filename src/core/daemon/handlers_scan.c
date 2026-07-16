/*
 * memDBG - Scan protocol handlers (exact, AOB, pointer, unknown).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from src/core/daemon/memdbg.c.
 */

#include "daemon_internal.h"

#include "memdbg/core/memdbg.h"
#include "memdbg/scanner/memdbg_scan.h"
#include "memdbg/scanner/scan_request.h"
#include <stdlib.h>
#include <string.h>

/* ---- Scan result sender ---- */

static memdbg_status_t send_scan_result(int fd, const memdbg_packet_header_t *req,
                                        memdbg_scan_result_t *result) {
  size_t entry_size = sizeof(memdbg_scan_result_entry_t);
  size_t prefix_size = sizeof(memdbg_scan_response_prefix_t);

  size_t max_count = 0U;
  if (prefix_size < MEMDBG_PROTOCOL_MAX_PACKET) {
    max_count = (MEMDBG_PROTOCOL_MAX_PACKET - prefix_size) / entry_size;
  }
  uint32_t send_count = (uint32_t)result->count;
  bool truncated = result->truncated ? true : false;
  if ((size_t)send_count > max_count) {
    send_count = (uint32_t)max_count;
    truncated = true;
  }

  size_t payload_len = prefix_size + (size_t)send_count * entry_size;
  if (payload_len > UINT32_MAX) return MEMDBG_ERR_OVERFLOW;

  unsigned char *payload = (unsigned char *)malloc(payload_len);
  if (payload == NULL) return MEMDBG_ERR_NOMEM;

  memdbg_scan_response_prefix_t prefix;
  memset(&prefix, 0, sizeof(prefix));
  prefix.count           = send_count;
  prefix.truncated       = truncated ? 1U : 0U;
  prefix.bytes_scanned   = result->bytes_scanned;
  prefix.elapsed_ns      = result->elapsed_ns;
  prefix.read_calls      = result->read_calls;
  prefix.regions_scanned = result->regions_scanned;
  prefix.read_errors     = result->read_errors;

  memcpy(payload, &prefix, sizeof(prefix));
  if (send_count != 0U)
    memcpy(payload + sizeof(prefix), result->entries,
           send_count * sizeof(memdbg_scan_result_entry_t));

  int rc = send_response(fd, req, MEMDBG_OK, payload, (uint32_t)payload_len);
  free(payload);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/*
 * SCAN_HANDLER(name, scan_fn, req_type):
 * Boilerplate for a simple scan handler: validate body size, deserialize,
 * cap max_results, call scan function, send result, free, return status.
 */
#define SCAN_HANDLER(name, scan_fn, req_type)                                  \
  memdbg_status_t name(int fd, const memdbg_packet_header_t *req,             \
                       const memdbg_config_t *cfg, const void *body,           \
                       uint32_t body_len) {                                    \
    if (body_len != sizeof(req_type)) return MEMDBG_ERR_PROTOCOL;              \
    req_type scan_req;                                                         \
    memcpy(&scan_req, body, sizeof(scan_req));                                 \
    if (scan_req.max_results == 0U || scan_req.max_results > cfg->max_scan_results) \
      scan_req.max_results = cfg->max_scan_results;                            \
    memdbg_scan_result_t result;                                               \
    memdbg_status_t status = scan_fn(&scan_req, &result);                      \
    if (status == MEMDBG_OK) status = send_scan_result(fd, req, &result);      \
    memdbg_scan_result_free(&result);                                          \
    return status;                                                             \
  }

/* Exact / process-exact / pointer — simple body validation. */
SCAN_HANDLER(handle_scan_exact_v2,     memdbg_scan_exact,         memdbg_scan_exact_request_t)
SCAN_HANDLER(handle_scan_process_exact,memdbg_scan_process_exact, memdbg_scan_process_exact_request_t)

static memdbg_status_t handle_scan_unknown_body(
    int fd, const memdbg_packet_header_t *req, const memdbg_config_t *cfg,
    const void *body, uint32_t body_len) {
  memdbg_scan_unknown_request_t scan_req;
  memdbg_status_t status = memdbg_scan_unknown_request_decode(
      body, body_len, &scan_req);
  if (status != MEMDBG_OK) return status;

  size_t packet_limit =
      (MEMDBG_PROTOCOL_MAX_PACKET - sizeof(memdbg_scan_response_prefix_t)) /
      sizeof(memdbg_scan_result_entry_t);
  size_t memory_limit =
      MEMDBG_SCAN_UNKNOWN_RESULT_BUDGET / sizeof(memdbg_scan_result_entry_t);
  size_t result_limit = packet_limit < memory_limit ? packet_limit
                                                    : memory_limit;
  if (result_limit > cfg->max_scan_results)
    result_limit = cfg->max_scan_results;
  if (scan_req.max_results == 0U ||
      (size_t)scan_req.max_results > result_limit)
    scan_req.max_results = (uint32_t)result_limit;

  memdbg_scan_result_t result;
  status = memdbg_scan_unknown(&scan_req, &result);
  if (status == MEMDBG_OK) status = send_scan_result(fd, req, &result);
  memdbg_scan_result_free(&result);
  return status;
}

memdbg_status_t handle_scan_unknown(int fd,
                                    const memdbg_packet_header_t *req,
                                    const memdbg_config_t *cfg,
                                    const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_scan_process_exact_request_t))
    return MEMDBG_ERR_PROTOCOL;
  return handle_scan_unknown_body(fd, req, cfg, body, body_len);
}

memdbg_status_t handle_scan_unknown_v2(int fd,
                                       const memdbg_packet_header_t *req,
                                       const memdbg_config_t *cfg,
                                       const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_scan_unknown_request_t))
    return MEMDBG_ERR_PROTOCOL;
  return handle_scan_unknown_body(fd, req, cfg, body, body_len);
}

memdbg_status_t handle_scan_pointer(int fd, const memdbg_packet_header_t *req,
                                    const memdbg_config_t *cfg, const void *body,
                                    uint32_t body_len) {
  if (body_len != sizeof(memdbg_scan_pointer_request_t)) return MEMDBG_ERR_PROTOCOL;
  memdbg_scan_pointer_request_t scan_req;
  memcpy(&scan_req, body, sizeof(scan_req));
  if (scan_req.length == 0U || scan_req.length > UINT64_MAX - scan_req.start)
    return MEMDBG_ERR_PARAM;
  if (scan_req.max_results == 0U || scan_req.max_results > cfg->max_scan_results)
    scan_req.max_results = cfg->max_scan_results;
  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_pointer(&scan_req, &result);
  if (status == MEMDBG_OK) status = send_scan_result(fd, req, &result);
  memdbg_scan_result_free(&result);
  return status;
}

/*
 * AOB_HANDLER(name, scan_fn, req_type):
 * Boilerplate for AOB (array-of-bytes) scan handlers with pattern+mask parsing.
 */
#define AOB_HANDLER(name, scan_fn, req_type)                                   \
  memdbg_status_t name(int fd, const memdbg_packet_header_t *req,             \
                       const memdbg_config_t *cfg, const void *body,           \
                       uint32_t body_len) {                                    \
    if (body_len < sizeof(req_type)) return MEMDBG_ERR_PROTOCOL;               \
    const req_type *aob_req = (const req_type *)body;                          \
    uint32_t pat_len = aob_req->pattern_length;                                \
    if (pat_len == 0U || pat_len > 256U) return MEMDBG_ERR_PARAM;              \
    uint32_t expected = (uint32_t)sizeof(req_type) + pat_len + pat_len;                  \
    if (body_len < expected) return MEMDBG_ERR_PROTOCOL;                       \
    const uint8_t *pattern = (const uint8_t *)body + sizeof(req_type);         \
    const uint8_t *mask    = pattern + pat_len;                                \
    req_type req_copy = *aob_req;                                              \
    if (req_copy.max_results == 0U || req_copy.max_results > cfg->max_scan_results) \
      req_copy.max_results = cfg->max_scan_results;                            \
    memdbg_scan_result_t result;                                               \
    memdbg_status_t status = scan_fn(&req_copy, pattern, mask, &result);       \
    if (status == MEMDBG_OK) status = send_scan_result(fd, req, &result);      \
    memdbg_scan_result_free(&result);                                          \
    return status;                                                             \
  }

AOB_HANDLER(handle_scan_aob,         memdbg_scan_aob,         memdbg_scan_aob_request_t)
AOB_HANDLER(handle_scan_process_aob, memdbg_scan_process_aob, memdbg_scan_process_aob_request_t)

#undef SCAN_HANDLER
#undef AOB_HANDLER
