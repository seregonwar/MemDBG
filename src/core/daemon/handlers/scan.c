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
#include <pthread.h>

#define MEMDBG_SCAN_JOB_SLOTS 16U

typedef struct scan_job_slot {
  uint64_t job_id;
  bool occupied;
  uint32_t state;
  memdbg_scan_progress_t progress;
} scan_job_slot_t;

static pthread_mutex_t g_scan_jobs_mutex = PTHREAD_MUTEX_INITIALIZER;
static scan_job_slot_t g_scan_jobs[MEMDBG_SCAN_JOB_SLOTS];

static scan_job_slot_t *scan_job_find_locked(uint64_t job_id) {
  for (size_t i = 0U; i < MEMDBG_SCAN_JOB_SLOTS; ++i)
    if (g_scan_jobs[i].occupied && g_scan_jobs[i].job_id == job_id)
      return &g_scan_jobs[i];
  return NULL;
}

static scan_job_slot_t *scan_job_begin(uint64_t job_id) {
  if (job_id == 0U) return NULL;
  pthread_mutex_lock(&g_scan_jobs_mutex);
  if (scan_job_find_locked(job_id) != NULL) {
    pthread_mutex_unlock(&g_scan_jobs_mutex);
    return NULL;
  }
  scan_job_slot_t *slot = NULL;
  for (size_t i = 0U; i < MEMDBG_SCAN_JOB_SLOTS; ++i) {
    if (!g_scan_jobs[i].occupied ||
        g_scan_jobs[i].state == MEMDBG_SCAN_JOB_COMPLETED ||
        g_scan_jobs[i].state == MEMDBG_SCAN_JOB_CANCELLED ||
        g_scan_jobs[i].state == MEMDBG_SCAN_JOB_FAILED) {
      slot = &g_scan_jobs[i];
      break;
    }
  }
  if (slot != NULL) {
    memset(slot, 0, sizeof(*slot));
    slot->job_id = job_id;
    slot->occupied = true;
    slot->state = MEMDBG_SCAN_JOB_RUNNING;
    atomic_init(&slot->progress.bytes_done, 0U);
    atomic_init(&slot->progress.bytes_total, 0U);
    atomic_init(&slot->progress.results_found, 0U);
    atomic_init(&slot->progress.maps_done, 0U);
    atomic_init(&slot->progress.maps_total, 0U);
    atomic_init(&slot->progress.workers_active, 0U);
    atomic_init(&slot->progress.workers_total, 0U);
    atomic_init(&slot->progress.read_errors, 0U);
    atomic_init(&slot->progress.cancel_requested, false);
  }
  pthread_mutex_unlock(&g_scan_jobs_mutex);
  return slot;
}

static void scan_job_finish(scan_job_slot_t *slot, memdbg_status_t status) {
  pthread_mutex_lock(&g_scan_jobs_mutex);
  if (slot != NULL && slot->occupied) {
    if (atomic_load_explicit(&slot->progress.cancel_requested,
                             memory_order_relaxed))
      slot->state = MEMDBG_SCAN_JOB_CANCELLED;
    else
      slot->state = status == MEMDBG_OK ? MEMDBG_SCAN_JOB_COMPLETED
                                        : MEMDBG_SCAN_JOB_FAILED;
  }
  pthread_mutex_unlock(&g_scan_jobs_mutex);
}

/* ---- Scan result sender ---- */

static memdbg_status_t send_scan_result(int fd, const memdbg_packet_header_t *req,
                                        memdbg_scan_result_t *result) {
  size_t entry_size = sizeof(memdbg_scan_result_entry_t);
  size_t prefix_size = sizeof(memdbg_scan_response_prefix_t);

  size_t max_count = 0U;
  if (prefix_size < MEMDBG_PROTOCOL_MAX_PACKET) {
    max_count = (MEMDBG_PROTOCOL_MAX_PACKET - prefix_size) / entry_size;
  }
  /* Hard cap to avoid oversized single TCP writes on console payloads. */
  if (max_count > (size_t)MEMDBG_SCAN_MAX_RESULTS_PER_RESPONSE)
    max_count = (size_t)MEMDBG_SCAN_MAX_RESULTS_PER_RESPONSE;
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
  prefix.reserved        = result->cancelled
      ? MEMDBG_SCAN_RESULT_FLAG_CANCELLED : 0U;

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

memdbg_status_t handle_scan_process_exact_tracked(
    int fd, const memdbg_packet_header_t *req, const memdbg_config_t *cfg,
    const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_scan_process_exact_tracked_request_t))
    return MEMDBG_ERR_PROTOCOL;
  memdbg_scan_process_exact_tracked_request_t tracked;
  memcpy(&tracked, body, sizeof(tracked));
  if (tracked.job_id == 0U) return MEMDBG_ERR_PARAM;
  if (tracked.scan.max_results == 0U ||
      tracked.scan.max_results > cfg->max_scan_results)
    tracked.scan.max_results = cfg->max_scan_results;

  scan_job_slot_t *slot = scan_job_begin(tracked.job_id);
  if (slot == NULL) return MEMDBG_ERR_STATE;
  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_process_exact_tracked(
      &tracked.scan, &slot->progress, &result);
  scan_job_finish(slot, status);
  if (status == MEMDBG_OK) status = send_scan_result(fd, req, &result);
  memdbg_scan_result_free(&result);
  return status;
}

memdbg_status_t handle_scan_job_status(
    int fd, const memdbg_packet_header_t *req, const void *body,
    uint32_t body_len, bool cancel) {
  if (body_len != sizeof(memdbg_scan_job_request_t))
    return MEMDBG_ERR_PROTOCOL;
  memdbg_scan_job_request_t query;
  memcpy(&query, body, sizeof(query));
  if (query.job_id == 0U) return MEMDBG_ERR_PARAM;

  pthread_mutex_lock(&g_scan_jobs_mutex);
  scan_job_slot_t *slot = scan_job_find_locked(query.job_id);
  if (slot == NULL) {
    pthread_mutex_unlock(&g_scan_jobs_mutex);
    return MEMDBG_ERR_NOT_FOUND;
  }
  if (cancel && slot->state == MEMDBG_SCAN_JOB_RUNNING)
    atomic_store_explicit(&slot->progress.cancel_requested, true,
                          memory_order_relaxed);
  memdbg_scan_job_status_response_t response;
  memset(&response, 0, sizeof(response));
  response.job_id = slot->job_id;
  response.bytes_done = atomic_load_explicit(&slot->progress.bytes_done,
                                             memory_order_relaxed);
  response.bytes_total = atomic_load_explicit(&slot->progress.bytes_total,
                                              memory_order_relaxed);
  response.results_found = atomic_load_explicit(
      &slot->progress.results_found, memory_order_relaxed);
  response.maps_done = atomic_load_explicit(&slot->progress.maps_done,
                                            memory_order_relaxed);
  response.maps_total = atomic_load_explicit(&slot->progress.maps_total,
                                             memory_order_relaxed);
  response.workers_active = atomic_load_explicit(
      &slot->progress.workers_active, memory_order_relaxed);
  response.workers_total = atomic_load_explicit(
      &slot->progress.workers_total, memory_order_relaxed);
  response.read_errors = atomic_load_explicit(&slot->progress.read_errors,
                                              memory_order_relaxed);
  response.state = slot->state;
  pthread_mutex_unlock(&g_scan_jobs_mutex);
  return send_response(fd, req, MEMDBG_OK, &response, sizeof(response)) == 0
      ? MEMDBG_OK : MEMDBG_ERR_NET;
}

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
  if (packet_limit > (size_t)MEMDBG_SCAN_MAX_RESULTS_PER_RESPONSE)
    packet_limit = (size_t)MEMDBG_SCAN_MAX_RESULTS_PER_RESPONSE;
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
