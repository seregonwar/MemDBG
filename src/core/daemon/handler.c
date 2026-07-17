/*
 * Daemon – per-connection handler.
 *
 * This file is part of MemDBG.
 */

#include "memdbg/daemon/handler.h"
#include "daemon_internal.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/privilege/privilege.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* ---- Handle a single client connection ---- */

void handle_client(socket_t fd, const memdbg_config_t *cfg) {
  atomic_fetch_add_explicit(&g_active_connections, 1U, memory_order_relaxed);
  (void)pal_socket_set_nonblocking(fd, false);
  (void)pal_socket_configure(fd);

  while (!memdbg_daemon_should_stop()) {
    memdbg_packet_header_t req;
    int timeout_ms = (cfg != NULL && cfg->idle_timeout_ms > 0U)
                         ? (int)cfg->idle_timeout_ms
                         : -1; /* block indefinitely */

    int ready = wait_for_client(fd, timeout_ms);

    if (ready == 0) {
      /* Idle timeout – disconnect the client. */
      memdbg_log_write(MEMDBG_LOG_INFO,
                       "client idle timeout (%u ms)", cfg->idle_timeout_ms);
      break;
    }
    if (ready < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (memdbg_daemon_should_stop()) break;

    if (pal_socket_read_exact(fd, &req, sizeof(req)) < 0) break;

    if (req.magic != MEMDBG_PACKET_MAGIC ||
        req.version != MEMDBG_PROTOCOL_VERSION ||
        req.length > cfg->max_packet_bytes) {
      (void)send_response(fd, &req, MEMDBG_ERR_PROTOCOL, NULL, 0U);
      break;
    }

    void *body = NULL;
    if (req.length != 0U) {
      body = malloc(req.length);
      if (body == NULL) {
        (void)send_response(fd, &req, MEMDBG_ERR_NOMEM, NULL, 0U);
        break;
      }
      if (pal_socket_read_exact(fd, body, req.length) < 0) {
        free(body);
        break;
      }
    }

    memdbg_status_t status;
    if (memdbg_privilege_operation_begin() != 0) {
      status = MEMDBG_ERR_STATE;
    } else {
      status = dispatch_packet(fd, cfg, &req, body);
      if (memdbg_privilege_operation_end() != 0 && status == MEMDBG_OK)
        status = MEMDBG_ERR_STATE;
    }
    free(body);
    if (status != MEMDBG_OK)
      (void)send_response(fd, &req, status, NULL, 0U);
  }

  if (atomic_load_explicit(&g_active_connections, memory_order_relaxed) <= 1U &&
      memdbg_debugger_is_attached()) {
    memdbg_log_write(MEMDBG_LOG_INFO,
                     "debugger: detaching because the last client disconnected");
    (void)memdbg_debugger_detach();
  }

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
