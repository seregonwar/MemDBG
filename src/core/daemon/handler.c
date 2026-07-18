/*
 * Daemon – per-connection handler.
 *
 * This file is part of MemDBG.
 */

#include "memdbg/daemon/handler.h"
#include "memdbg/daemon/acceptor.h"
#include "daemon_internal.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/pal/pal_time.h"
#include "memdbg/privilege/privilege.h"
#include "memdbg/scanner/flashscan.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MEMDBG_REUSABLE_REQUEST_MAX (256U * 1024U)

static uint64_t handler_monotonic_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0U;
  return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static void *request_buffer_acquire(void **reusable, size_t *capacity,
                                    uint32_t length) {
  if (length == 0U) return NULL;
  if (length > MEMDBG_REUSABLE_REQUEST_MAX) return malloc(length);
  if (*capacity < length) {
    size_t next = *capacity != 0U ? *capacity : 4096U;
    while (next < length) next *= 2U;
    void *grown = realloc(*reusable, next);
    if (grown == NULL) return NULL;
    *reusable = grown;
    *capacity = next;
  }
  return *reusable;
}

/* ---- Handle a single client connection ---- */

void handle_client(socket_t fd, const memdbg_config_t *cfg) {
  void *reusable_body = NULL;
  size_t reusable_capacity = 0U;
  (void)pal_socket_set_nonblocking(fd, false);
  (void)pal_socket_configure(fd);
  /* pal_socket_configure intentionally leaves timeouts unset for accepted
   * sockets. Idle expiry is enforced by wait_for_client plus the real
   * last-activity timestamp below. */
  uint64_t last_activity_ms = handler_monotonic_ms();

  while (!memdbg_daemon_should_stop()) {
    memdbg_packet_header_t req;
    int timeout_ms = (cfg != NULL && cfg->idle_timeout_ms > 0U)
                         ? (int)cfg->idle_timeout_ms
                         : -1;
    int ready = wait_for_client(fd, timeout_ms);
    if (ready == 0) {
      const uint64_t now_ms = handler_monotonic_ms();
      /* Sony's select may consume a relative timeout cumulatively across
       * repeated calls. Treat it as a wake-up and verify real inactivity. */
      if (cfg != NULL && cfg->idle_timeout_ms != 0U &&
          now_ms >= last_activity_ms &&
          now_ms - last_activity_ms < cfg->idle_timeout_ms)
        continue;
      memdbg_log_write(MEMDBG_LOG_INFO, "client idle timeout (%u ms)",
                       cfg != NULL ? cfg->idle_timeout_ms : 0U);
      break;
    }
    if (ready < 0) {
      if (errno == EINTR) continue;
      const int wait_errno = errno;
      const uint64_t now_ms = handler_monotonic_ms();
      if (cfg != NULL && cfg->idle_timeout_ms != 0U &&
          wait_errno != EBADF && wait_errno != ENOTSOCK &&
          wait_errno != ECONNRESET && now_ms >= last_activity_ms &&
          now_ms - last_activity_ms < cfg->idle_timeout_ms) {
        memdbg_sleep_ms(1U);
        continue;
      }
      break;
    }
    if (memdbg_daemon_should_stop()) break;
    if (pal_socket_read_exact(fd, &req, sizeof(req)) < 0) break;
    last_activity_ms = handler_monotonic_ms();

    if (req.magic != MEMDBG_PACKET_MAGIC ||
        req.version != MEMDBG_PROTOCOL_VERSION ||
        req.length > cfg->max_packet_bytes) {
      (void)send_response(fd, &req, MEMDBG_ERR_PROTOCOL, NULL, 0U);
      break;
    }

    void *body = NULL;
    if (req.length != 0U) {
      body = request_buffer_acquire(&reusable_body, &reusable_capacity,
                                    req.length);
      if (body == NULL) {
        (void)send_response(fd, &req, MEMDBG_ERR_NOMEM, NULL, 0U);
        break;
      }
      if (pal_socket_read_exact(fd, body, req.length) < 0) {
        if (body != reusable_body) free(body);
        break;
      }
    }

    /*
     * Do not serialize the whole protocol behind the credential mutex.
     * Operations which temporarily alter credentials (notably ptrace attach)
     * acquire that lock in the privilege layer itself.  Keeping it here made
     * independent pooled connections strictly sequential and prevented scans,
     * reads and telemetry from progressing concurrently.
     */
    memdbg_status_t status = dispatch_packet(fd, cfg, &req, body);
    if (body != reusable_body) free(body);
    if (status != MEMDBG_OK)
      (void)send_response(fd, &req, status, NULL, 0U);

  }

  if (atomic_load_explicit(&g_active_connections, memory_order_relaxed) <= 1U &&
      memdbg_debugger_is_attached()) {
    memdbg_log_write(MEMDBG_LOG_INFO,
                     "debugger: detaching because the last client disconnected");
    (void)memdbg_debugger_detach();
  }

  free(reusable_body);
  flashscan_release_client(fd);
  acceptor_unregister_client(fd);
  (void)pal_socket_close(fd);
  atomic_fetch_sub_explicit(&g_active_connections, 1U, memory_order_relaxed);
}

/* ---- Connection handler thread (detached) ---- */

void *connection_handler_thread(void *arg) {
  connection_args_t *args = (connection_args_t *)arg;
  socket_t client_fd = args->client_fd;
  memdbg_config_t cfg = args->cfg;

  free(args);

  handle_client(client_fd, &cfg);
  return NULL;
}
