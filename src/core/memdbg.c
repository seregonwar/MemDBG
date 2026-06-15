/*
 * memDBG - Memory debugger payload for jailbroken consoles.
 * Copyright (C) 2026 SeregonWar
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/core/memdbg.h"

#include "memdbg/core/memdbg_log.h"
#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/debug/memdbg_process.h"
#include "memdbg/pal/pal_network.h"
#include "memdbg/scanner/memdbg_scan.h"
#include "memdbg/telemetry/udp_log.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct client_ctx {
  socket_t fd;
  memdbg_config_t cfg;
} client_ctx_t;

static atomic_bool g_stop_requested = ATOMIC_VAR_INIT(false);

void memdbg_config_defaults(memdbg_config_t *cfg) {
  if (cfg == NULL) {
    return;
  }
  memset(cfg, 0, sizeof(*cfg));
  (void)snprintf(cfg->bind_host, sizeof(cfg->bind_host), "0.0.0.0");
  (void)snprintf(cfg->udp_log_host, sizeof(cfg->udp_log_host), "%s",
                 MEMDBG_DEFAULT_UDP_LOG_HOST);
  (void)snprintf(cfg->data_root, sizeof(cfg->data_root), "%s",
                 MEMDBG_DEFAULT_DATA_ROOT);
  cfg->debug_port = MEMDBG_DEFAULT_DEBUG_PORT;
  cfg->udp_log_port = MEMDBG_DEFAULT_UDP_LOG_PORT;
  cfg->discovery_port = MEMDBG_DEFAULT_DISCOVERY_PORT;
  cfg->enable_udp_log = true;
  cfg->max_packet_bytes = MEMDBG_PROTOCOL_MAX_PACKET;
  cfg->max_read_bytes = MEMDBG_PROTOCOL_MAX_READ;
  cfg->max_scan_results = 200000U;
}

const char *memdbg_strerror(memdbg_status_t status) {
  switch (status) {
  case MEMDBG_OK:
    return "ok";
  case MEMDBG_ERR_PARAM:
    return "invalid parameter";
  case MEMDBG_ERR_NOMEM:
    return "out of memory";
  case MEMDBG_ERR_IO:
    return "i/o error";
  case MEMDBG_ERR_NET:
    return "network error";
  case MEMDBG_ERR_PROTOCOL:
    return "protocol error";
  case MEMDBG_ERR_UNSUPPORTED:
    return "unsupported";
  case MEMDBG_ERR_NOT_FOUND:
    return "not found";
  case MEMDBG_ERR_PERMISSION:
    return "permission denied";
  case MEMDBG_ERR_OVERFLOW:
    return "overflow";
  case MEMDBG_ERR_STATE:
    return "invalid state";
  default:
    return "unknown error";
  }
}

void memdbg_daemon_request_stop(void) {
  atomic_store_explicit(&g_stop_requested, true, memory_order_relaxed);
}

bool memdbg_daemon_should_stop(void) {
  return atomic_load_explicit(&g_stop_requested, memory_order_relaxed);
}

static uint16_t memdbg_platform_id(void) {
#if defined(PLATFORM_PS4) || defined(PS4)
  return (uint16_t)MEMDBG_PLATFORM_PS4;
#elif defined(PLATFORM_PS5) || defined(PS5)
  return (uint16_t)MEMDBG_PLATFORM_PS5;
#else
  return (uint16_t)MEMDBG_PLATFORM_HOST;
#endif
}

static uint32_t memdbg_capabilities(const memdbg_config_t *cfg) {
  uint32_t caps = MEMDBG_CAP_PROCESS_LIST | MEMDBG_CAP_PROCESS_MAPS |
                  MEMDBG_CAP_MEMORY_READ | MEMDBG_CAP_MEMORY_WRITE |
                  MEMDBG_CAP_SCAN_EXACT | MEMDBG_CAP_SCAN_PROCESS_EXACT |
                  MEMDBG_CAP_SCAN_TELEMETRY | MEMDBG_CAP_PROCESS_INFO;
  if (cfg != NULL && cfg->enable_udp_log) {
    caps |= MEMDBG_CAP_UDP_LOG;
  }
  return caps;
}

static int send_response(socket_t fd, const memdbg_packet_header_t *req,
                         memdbg_status_t status, const void *payload,
                         uint32_t payload_len) {
  memdbg_response_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = MEMDBG_PACKET_MAGIC;
  hdr.version = MEMDBG_PROTOCOL_VERSION;
  hdr.command = req != NULL ? req->command : 0U;
  hdr.request_id = req != NULL ? req->request_id : 0U;
  hdr.status = (int32_t)status;
  hdr.length = payload_len;

  if (pal_socket_write_all(fd, &hdr, sizeof(hdr)) < 0) {
    return -1;
  }
  if (payload_len != 0U &&
      pal_socket_write_all(fd, payload, payload_len) < 0) {
    return -1;
  }
  return 0;
}

static memdbg_status_t handle_hello(const memdbg_config_t *cfg,
                                    memdbg_hello_response_t *out) {
  if (cfg == NULL || out == NULL) {
    return MEMDBG_ERR_PARAM;
  }
  memset(out, 0, sizeof(*out));
  out->protocol_version = MEMDBG_PROTOCOL_VERSION;
  out->platform_id = memdbg_platform_id();
  out->capabilities = memdbg_capabilities(cfg);
  out->debug_port = cfg->debug_port;
  out->udp_log_port = cfg->enable_udp_log ? cfg->udp_log_port : 0U;
  (void)snprintf(out->version, sizeof(out->version), "%s",
                 MEMDBG_VERSION_STRING);
  (void)snprintf(out->name, sizeof(out->name), "memDBG");
  return MEMDBG_OK;
}

static memdbg_status_t handle_process_list(socket_t fd,
                                           const memdbg_packet_header_t *req) {
  memdbg_process_list_t list;
  memdbg_status_t status = memdbg_process_list(&list);
  if (status != MEMDBG_OK) {
    return status;
  }

  size_t payload_len =
      sizeof(uint32_t) + list.count * sizeof(memdbg_process_entry_t);
  if (payload_len > UINT32_MAX) {
    memdbg_process_list_free(&list);
    return MEMDBG_ERR_OVERFLOW;
  }

  unsigned char *payload = (unsigned char *)malloc(payload_len);
  if (payload == NULL) {
    memdbg_process_list_free(&list);
    return MEMDBG_ERR_NOMEM;
  }

  uint32_t count = (uint32_t)list.count;
  memcpy(payload, &count, sizeof(count));
  if (list.count != 0U) {
    memcpy(payload + sizeof(count), list.entries,
           list.count * sizeof(memdbg_process_entry_t));
  }

  int rc = send_response(fd, req, MEMDBG_OK, payload, (uint32_t)payload_len);
  free(payload);
  memdbg_process_list_free(&list);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static memdbg_status_t handle_process_maps(socket_t fd,
                                           const memdbg_packet_header_t *req,
                                           const void *body,
                                           uint32_t body_len) {
  if (body_len != sizeof(memdbg_process_maps_request_t)) {
    return MEMDBG_ERR_PROTOCOL;
  }

  const memdbg_process_maps_request_t *maps_req =
      (const memdbg_process_maps_request_t *)body;
  memdbg_map_list_t maps;
  memdbg_status_t status = memdbg_process_maps(maps_req->pid, &maps);
  if (status != MEMDBG_OK) {
    return status;
  }

  size_t payload_len = sizeof(uint32_t) + maps.count * sizeof(memdbg_map_entry_t);
  if (payload_len > UINT32_MAX) {
    memdbg_process_maps_free(&maps);
    return MEMDBG_ERR_OVERFLOW;
  }

  unsigned char *payload = (unsigned char *)malloc(payload_len);
  if (payload == NULL) {
    memdbg_process_maps_free(&maps);
    return MEMDBG_ERR_NOMEM;
  }

  uint32_t count = (uint32_t)maps.count;
  memcpy(payload, &count, sizeof(count));
  if (maps.count != 0U) {
    memcpy(payload + sizeof(count), maps.entries,
           maps.count * sizeof(memdbg_map_entry_t));
  }

  int rc = send_response(fd, req, MEMDBG_OK, payload, (uint32_t)payload_len);
  free(payload);
  memdbg_process_maps_free(&maps);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static memdbg_status_t handle_process_info(socket_t fd,
                                           const memdbg_packet_header_t *req,
                                           const void *body,
                                           uint32_t body_len) {
  if (body_len != sizeof(memdbg_process_info_request_t)) {
    return MEMDBG_ERR_PROTOCOL;
  }

  const memdbg_process_info_request_t *info_req =
      (const memdbg_process_info_request_t *)body;
  memdbg_process_info_response_t info;
  memdbg_status_t status = memdbg_process_info(info_req->pid, &info);
  if (status != MEMDBG_OK) {
    return status;
  }

  return send_response(fd, req, MEMDBG_OK, &info, sizeof(info)) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}

static memdbg_status_t handle_memory_read(socket_t fd,
                                          const memdbg_packet_header_t *req,
                                          const memdbg_config_t *cfg,
                                          const void *body,
                                          uint32_t body_len) {
  if (body_len != sizeof(memdbg_memory_request_t)) {
    return MEMDBG_ERR_PROTOCOL;
  }

  const memdbg_memory_request_t *read_req =
      (const memdbg_memory_request_t *)body;
  if (read_req->length > cfg->max_read_bytes) {
    return MEMDBG_ERR_OVERFLOW;
  }

  unsigned char *buffer = (unsigned char *)malloc(read_req->length);
  if (buffer == NULL && read_req->length != 0U) {
    return MEMDBG_ERR_NOMEM;
  }

  size_t read_len = 0U;
  memdbg_status_t status =
      memdbg_memory_read(read_req->pid, read_req->address, buffer,
                         read_req->length, &read_len);
  if (status == MEMDBG_OK) {
    if (send_response(fd, req, MEMDBG_OK, buffer, (uint32_t)read_len) != 0) {
      status = MEMDBG_ERR_NET;
    }
  }
  free(buffer);
  return status;
}

static memdbg_status_t handle_memory_write(socket_t fd,
                                           const memdbg_packet_header_t *req,
                                           const memdbg_config_t *cfg,
                                           const void *body,
                                           uint32_t body_len) {
  if (body_len < sizeof(memdbg_memory_request_t)) {
    return MEMDBG_ERR_PROTOCOL;
  }

  const memdbg_memory_request_t *write_req =
      (const memdbg_memory_request_t *)body;
  if (write_req->length > cfg->max_read_bytes ||
      body_len != sizeof(*write_req) + write_req->length) {
    return MEMDBG_ERR_PROTOCOL;
  }

  const unsigned char *data =
      (const unsigned char *)body + sizeof(memdbg_memory_request_t);
  size_t written = 0U;
  memdbg_status_t status =
      memdbg_memory_write(write_req->pid, write_req->address, data,
                          write_req->length, &written);
  if (status != MEMDBG_OK) {
    return status;
  }

  uint32_t written32 = (uint32_t)written;
  return send_response(fd, req, MEMDBG_OK, &written32, sizeof(written32)) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}

static memdbg_status_t send_scan_result(socket_t fd,
                                        const memdbg_packet_header_t *req,
                                        memdbg_scan_result_t *result) {
  size_t payload_len = sizeof(memdbg_scan_response_prefix_t) +
                       result->count * sizeof(memdbg_scan_result_entry_t);
  if (payload_len > UINT32_MAX) {
    return MEMDBG_ERR_OVERFLOW;
  }

  unsigned char *payload = (unsigned char *)malloc(payload_len);
  if (payload == NULL) {
    return MEMDBG_ERR_NOMEM;
  }

  memdbg_scan_response_prefix_t prefix;
  memset(&prefix, 0, sizeof(prefix));
  prefix.count = (uint32_t)result->count;
  prefix.truncated = result->truncated ? 1U : 0U;
  prefix.bytes_scanned = result->bytes_scanned;
  prefix.elapsed_ns = result->elapsed_ns;
  prefix.read_calls = result->read_calls;
  prefix.regions_scanned = result->regions_scanned;
  prefix.read_errors = result->read_errors;

  memcpy(payload, &prefix, sizeof(prefix));
  if (result->count != 0U) {
    memcpy(payload + sizeof(prefix), result->entries,
           result->count * sizeof(memdbg_scan_result_entry_t));
  }

  int rc = send_response(fd, req, MEMDBG_OK, payload, (uint32_t)payload_len);
  free(payload);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static memdbg_status_t handle_scan_exact_v2(socket_t fd,
                                            const memdbg_packet_header_t *req,
                                            const memdbg_config_t *cfg,
                                            const void *body,
                                            uint32_t body_len) {
  if (body_len != sizeof(memdbg_scan_exact_request_t)) {
    return MEMDBG_ERR_PROTOCOL;
  }

  memdbg_scan_exact_request_t scan_req;
  memcpy(&scan_req, body, sizeof(scan_req));
  if (scan_req.max_results == 0U ||
      scan_req.max_results > cfg->max_scan_results) {
    scan_req.max_results = cfg->max_scan_results;
  }

  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_exact(&scan_req, &result);
  if (status == MEMDBG_OK) {
    status = send_scan_result(fd, req, &result);
  }
  memdbg_scan_result_free(&result);
  return status;
}

static memdbg_status_t
handle_scan_process_exact(socket_t fd, const memdbg_packet_header_t *req,
                          const memdbg_config_t *cfg, const void *body,
                          uint32_t body_len) {
  if (body_len != sizeof(memdbg_scan_process_exact_request_t)) {
    return MEMDBG_ERR_PROTOCOL;
  }

  memdbg_scan_process_exact_request_t scan_req;
  memcpy(&scan_req, body, sizeof(scan_req));
  if (scan_req.max_results == 0U ||
      scan_req.max_results > cfg->max_scan_results) {
    scan_req.max_results = cfg->max_scan_results;
  }

  memdbg_scan_result_t result;
  memdbg_status_t status = memdbg_scan_process_exact(&scan_req, &result);
  if (status == MEMDBG_OK) {
    status = send_scan_result(fd, req, &result);
  }
  memdbg_scan_result_free(&result);
  return status;
}

static memdbg_status_t dispatch_packet(socket_t fd, const memdbg_config_t *cfg,
                                       const memdbg_packet_header_t *req,
                                       const void *body) {
  switch ((memdbg_command_t)req->command) {
  case MEMDBG_CMD_HELLO: {
    memdbg_hello_response_t hello;
    memdbg_status_t status = handle_hello(cfg, &hello);
    if (status != MEMDBG_OK) {
      return status;
    }
    return send_response(fd, req, MEMDBG_OK, &hello, sizeof(hello)) == 0
               ? MEMDBG_OK
               : MEMDBG_ERR_NET;
  }
  case MEMDBG_CMD_PING:
    return send_response(fd, req, MEMDBG_OK, NULL, 0U) == 0 ? MEMDBG_OK
                                                            : MEMDBG_ERR_NET;
  case MEMDBG_CMD_PROCESS_LIST:
    return handle_process_list(fd, req);
  case MEMDBG_CMD_PROCESS_MAPS:
    return handle_process_maps(fd, req, body, req->length);
  case MEMDBG_CMD_PROCESS_INFO:
    return handle_process_info(fd, req, body, req->length);
  case MEMDBG_CMD_MEMORY_READ:
    return handle_memory_read(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_MEMORY_WRITE:
    return handle_memory_write(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_EXACT:
    return handle_scan_exact_v2(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_PROCESS_EXACT:
    return handle_scan_process_exact(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SHUTDOWN:
    memdbg_daemon_request_stop();
    return send_response(fd, req, MEMDBG_OK, NULL, 0U) == 0 ? MEMDBG_OK
                                                            : MEMDBG_ERR_NET;
  default:
    return MEMDBG_ERR_PROTOCOL;
  }
}

static void *client_thread(void *arg) {
  client_ctx_t *ctx = (client_ctx_t *)arg;
  socket_t fd = ctx->fd;
  memdbg_config_t cfg = ctx->cfg;
  free(ctx);

  (void)pal_socket_configure(fd);

  while (!memdbg_daemon_should_stop()) {
    memdbg_packet_header_t req;
    if (pal_socket_read_exact(fd, &req, sizeof(req)) < 0) {
      break;
    }

    if (req.magic != MEMDBG_PACKET_MAGIC ||
        req.version != MEMDBG_PROTOCOL_VERSION ||
        req.length > cfg.max_packet_bytes) {
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

    memdbg_status_t status = dispatch_packet(fd, &cfg, &req, body);
    free(body);
    if (status != MEMDBG_OK) {
      (void)send_response(fd, &req, status, NULL, 0U);
    }
  }

  (void)pal_socket_close(fd);
  return NULL;
}

static void signal_handler(int signum) {
  (void)signum;
  memdbg_daemon_request_stop();
}

static void install_signal_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  (void)sigemptyset(&sa.sa_mask);
  (void)sigaction(SIGINT, &sa, NULL);
  (void)sigaction(SIGTERM, &sa, NULL);
#ifdef SIGHUP
  (void)sigaction(SIGHUP, &sa, NULL);
#endif
#ifdef SIGPIPE
  sa.sa_handler = SIG_IGN;
  (void)sigaction(SIGPIPE, &sa, NULL);
#endif
}

int memdbg_daemon_run(const memdbg_config_t *cfg_in) {
  memdbg_config_t cfg;
  socket_t listen_fd = PAL_INVALID_SOCKET;

  if (cfg_in == NULL) {
    memdbg_config_defaults(&cfg);
  } else {
    cfg = *cfg_in;
  }

  atomic_store_explicit(&g_stop_requested, false, memory_order_relaxed);

  if (pal_network_init() != 0) {
    return MEMDBG_ERR_NET;
  }

  if (memdbg_log_init(cfg.data_root) != 0) {
    (void)pal_network_fini();
    return MEMDBG_ERR_IO;
  }

  install_signal_handlers();

  if (cfg.enable_udp_log) {
    memdbg_udp_log_config_t ucfg;
    memdbg_udp_log_config_defaults(&ucfg);
    (void)snprintf(ucfg.host, sizeof(ucfg.host), "%s", cfg.udp_log_host);
    ucfg.port = cfg.udp_log_port;
    ucfg.broadcast = strcmp(cfg.udp_log_host, "255.255.255.255") == 0;
    memdbg_status_t ustatus = memdbg_udp_log_start(&ucfg);
    if (ustatus != MEMDBG_OK) {
      memdbg_log_write(MEMDBG_LOG_WARN, "UDP log disabled: %s",
                       memdbg_strerror(ustatus));
    }
  }

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "memDBG %s starting debug=%s:%u udp_log=%s:%u",
                   MEMDBG_VERSION_STRING, cfg.bind_host, cfg.debug_port,
                   cfg.enable_udp_log ? cfg.udp_log_host : "off",
                   cfg.enable_udp_log ? cfg.udp_log_port : 0U);

  if (pal_tcp_listen(cfg.bind_host, cfg.debug_port, 16, &listen_fd) != 0) {
    memdbg_log_write(MEMDBG_LOG_ERROR, "debug listener failed: %s",
                     pal_socket_last_error());
    memdbg_udp_log_stop();
    memdbg_log_close();
    pal_network_fini();
    return MEMDBG_ERR_NET;
  }

  while (!memdbg_daemon_should_stop()) {
    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)sizeof(ss);
    socket_t client_fd = accept(listen_fd, (struct sockaddr *)&ss, &slen);
    if (client_fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (memdbg_daemon_should_stop()) {
        break;
      }
      memdbg_log_write(MEMDBG_LOG_WARN, "accept failed: %s",
                       pal_socket_last_error());
      continue;
    }

    client_ctx_t *ctx = (client_ctx_t *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
      (void)pal_socket_close(client_fd);
      continue;
    }
    ctx->fd = client_fd;
    ctx->cfg = cfg;

    pthread_t thread;
    if (pthread_create(&thread, NULL, client_thread, ctx) != 0) {
      free(ctx);
      (void)pal_socket_close(client_fd);
      continue;
    }
    (void)pthread_detach(thread);
  }

  (void)pal_socket_close(listen_fd);
  memdbg_log_write(MEMDBG_LOG_INFO, "memDBG stopped");
  memdbg_udp_log_stop();
  memdbg_log_close();
  pal_network_fini();
  return MEMDBG_OK;
}
