/*
 * memDBG - ps5debug wire-compatibility listener.
 * Copyright (C) 2026 SeregonWar
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon_internal.h"

#include "memdbg/core/memdbg_log.h"
#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/debug/memdbg_process.h"
#include "memdbg/pal/pal_memory.h"
#include "memdbg/pal/pal_network.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define LEGACY_PACKET_MAGIC 0xFFAABBCCU

#define LEGACY_CMD_SUCCESS 0x40000000U
#define LEGACY_CMD_DATA_NULL 0xF0000003U
#define LEGACY_CMD_ERROR 0xF0000002U

#define LEGACY_CMD_VERSION 0xBD000001U
#define LEGACY_CMD_FW_VERSION 0xBD000500U
#define LEGACY_CMD_BRANDING 0xBD000501U
#define LEGACY_CMD_PLATFORM_ID 0xBD000502U
#define LEGACY_CMD_PROC_NOP 0xBDAACC06U

#define LEGACY_CMD_PROC_LIST 0xBDAA0001U
#define LEGACY_CMD_PROC_READ 0xBDAA0002U
#define LEGACY_CMD_PROC_WRITE 0xBDAA0003U
#define LEGACY_CMD_PROC_MAPS 0xBDAA0004U
#define LEGACY_CMD_PROC_INSTALL 0xBDAA0005U
#define LEGACY_CMD_PROC_PROTECT 0xBDAA0008U
#define LEGACY_CMD_PROC_INFO 0xBDAA000AU
#define LEGACY_CMD_PROC_ALLOC 0xBDAA000BU
#define LEGACY_CMD_PROC_FREE 0xBDAA000CU
#define LEGACY_CMD_PROC_FIRST_MAP 0xBDAA000DU
#define LEGACY_CMD_PROC_ALLOC_HINTED 0xBDAA000EU
#define LEGACY_CMD_PROC_WRITE_MULTI 0xBDAACC04U
#define LEGACY_CMD_PROC_AUTH 0xBDAACCFFU

#define LEGACY_RW_CHUNK 0x10000U
#define LEGACY_WRITE_MULTI_STATUS 0x1U
#define LEGACY_WRITE_MULTI_MAX_COUNT 0xFFFFU
#define LEGACY_WRITE_MULTI_MAX_ENTRY 0x100000U

#if defined(__GNUC__) || defined(__clang__)
#define LEGACY_PACKED __attribute__((packed))
#else
#define LEGACY_PACKED
#endif

typedef struct legacy_packet_header {
  uint32_t magic;
  uint32_t command;
  uint32_t data_len;
} LEGACY_PACKED legacy_packet_header_t;

typedef struct legacy_proc_list_entry {
  char name[32];
  int32_t pid;
} LEGACY_PACKED legacy_proc_list_entry_t;

typedef struct legacy_proc_maps_entry {
  char name[32];
  uint64_t start;
  uint64_t end;
  uint64_t offset;
  uint16_t protection;
} LEGACY_PACKED legacy_proc_maps_entry_t;

typedef struct legacy_memory_packet {
  uint32_t pid;
  uint64_t address;
  uint32_t length;
} LEGACY_PACKED legacy_memory_packet_t;

typedef struct legacy_proc_info_packet {
  uint32_t pid;
} LEGACY_PACKED legacy_proc_info_packet_t;

typedef struct legacy_proc_info_response {
  uint32_t pid;
  char name[40];
  char path[64];
  char title_id[16];
  char content_id[64];
} LEGACY_PACKED legacy_proc_info_response_t;

typedef struct legacy_proc_alloc_packet {
  uint32_t pid;
  uint32_t length;
} LEGACY_PACKED legacy_proc_alloc_packet_t;

typedef struct legacy_proc_alloc_hinted_packet {
  uint32_t pid;
  uint64_t hint;
  uint32_t length;
} LEGACY_PACKED legacy_proc_alloc_hinted_packet_t;

typedef struct legacy_proc_alloc_response {
  uint64_t address;
} LEGACY_PACKED legacy_proc_alloc_response_t;

typedef struct legacy_proc_free_packet {
  uint32_t pid;
  uint64_t address;
  uint32_t length;
} LEGACY_PACKED legacy_proc_free_packet_t;

typedef struct legacy_proc_protect_packet {
  uint32_t pid;
  uint64_t address;
  uint32_t length;
  uint32_t protection;
} LEGACY_PACKED legacy_proc_protect_packet_t;

typedef struct legacy_proc_write_multi_packet {
  uint32_t pid;
  uint32_t count;
  uint32_t flags;
} LEGACY_PACKED legacy_proc_write_multi_packet_t;

typedef struct legacy_proc_write_multi_entry {
  uint64_t address;
  uint32_t length;
} LEGACY_PACKED legacy_proc_write_multi_entry_t;

_Static_assert(sizeof(legacy_packet_header_t) == 12U,
               "legacy packet header must stay wire-compatible");
_Static_assert(sizeof(legacy_proc_list_entry_t) == 36U,
               "legacy process entries must stay wire-compatible");
_Static_assert(sizeof(legacy_proc_maps_entry_t) == 58U,
               "legacy map entries must stay wire-compatible");
_Static_assert(sizeof(legacy_memory_packet_t) == 16U,
               "legacy memory packet must stay wire-compatible");
_Static_assert(sizeof(legacy_proc_info_response_t) == 188U,
               "legacy process info response must stay wire-compatible");
_Static_assert(sizeof(legacy_proc_protect_packet_t) == 20U,
               "legacy protect packet must stay wire-compatible");

typedef struct legacy_client_args {
  socket_t fd;
  memdbg_config_t cfg;
} legacy_client_args_t;

static atomic_bool g_legacy_running = ATOMIC_VAR_INIT(false);
static socket_t g_legacy_listen_fd = PAL_INVALID_SOCKET;
static pthread_t g_legacy_thread;
static bool g_legacy_thread_started = false;
static memdbg_config_t g_legacy_cfg;

static uint32_t legacy_bitswap32(uint32_t value) {
  return ((value >> 1) & 0x55555555U) | ((value << 1) & 0xAAAAAAAAU);
}

static uint32_t legacy_status_from_memdbg(memdbg_status_t status) {
  if (status == MEMDBG_OK) {
    return LEGACY_CMD_SUCCESS;
  }
  if (status == MEMDBG_ERR_NOMEM || status == MEMDBG_ERR_NOT_FOUND) {
    return LEGACY_CMD_DATA_NULL;
  }
  return LEGACY_CMD_ERROR;
}

static int legacy_send_status(socket_t fd, uint32_t status) {
  uint32_t wire = legacy_bitswap32(status);
  return pal_socket_write_all(fd, &wire, sizeof(wire)) < 0 ? -1 : 0;
}

static int legacy_send_memdbg_status(socket_t fd, memdbg_status_t status) {
  return legacy_send_status(fd, legacy_status_from_memdbg(status));
}

static int legacy_send_blob(socket_t fd, const void *data, size_t length) {
  if (length == 0U) {
    return 0;
  }
  return pal_socket_write_all(fd, data, length) < 0 ? -1 : 0;
}

static int legacy_send_sized_string(socket_t fd, const char *data,
                                    uint32_t length) {
  if (pal_socket_write_all(fd, &length, sizeof(length)) < 0) {
    return -1;
  }
  return legacy_send_blob(fd, data, length);
}

static void legacy_copy_fixed(char *dst, size_t dst_len, const char *src) {
  if (dst == NULL || dst_len == 0U) {
    return;
  }
  memset(dst, 0, dst_len);
  if (src != NULL && src[0] != '\0') {
    (void)snprintf(dst, dst_len, "%s", src);
  }
}

static bool legacy_is_valid_command(uint32_t command) {
  return (command >> 24U) == 0xBDU;
}

static bool legacy_has_body(const void *body, uint32_t body_len,
                            size_t expected) {
  return body != NULL && body_len == expected;
}

static uint32_t legacy_platform_id(void) {
#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
  return 5U;
#elif defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
  return 4U;
#else
  return 0U;
#endif
}

static int legacy_wait_for_fd(socket_t fd) {
  fd_set rfds;
  struct timeval tv;
  int rc;

  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = 250000;

  do {
    rc = select(fd + 1, &rfds, NULL, NULL, &tv);
  } while (rc < 0 && errno == EINTR);

  if (rc <= 0) {
    return rc;
  }
  return FD_ISSET(fd, &rfds) ? 1 : 0;
}

static bool legacy_sockaddr_ipv4_host(const struct sockaddr_storage *ss,
                                      char *host, size_t host_len) {
  const struct sockaddr_in *sin;

  if (ss == NULL || host == NULL || host_len == 0U ||
      ss->ss_family != AF_INET) {
    return false;
  }

  sin = (const struct sockaddr_in *)ss;
  return inet_ntop(AF_INET, &sin->sin_addr, host, host_len) != NULL;
}

static bool legacy_peer_allowed(const memdbg_config_t *cfg,
                                const struct sockaddr_storage *ss) {
  char peer_host[INET_ADDRSTRLEN];

  if (cfg == NULL || cfg->allow_host[0] == '\0') {
    return true;
  }
  if (!legacy_sockaddr_ipv4_host(ss, peer_host, sizeof(peer_host))) {
    return false;
  }
  return strcmp(cfg->allow_host, peer_host) == 0;
}

static memdbg_status_t legacy_handle_version(socket_t fd) {
  static const char version[] = "1.3";
  return legacy_send_sized_string(fd, version,
                                  (uint32_t)(sizeof(version) - 1U)) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}

static memdbg_status_t legacy_handle_branding(socket_t fd) {
  static const char brand[] = "MemDBG ps5debug-compat\0MDBG-1";
  return legacy_send_sized_string(fd, brand,
                                  (uint32_t)(sizeof(brand) - 1U)) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}

static memdbg_status_t legacy_handle_platform_id(socket_t fd) {
  uint16_t platform = (uint16_t)legacy_platform_id();
  return legacy_send_blob(fd, &platform, sizeof(platform)) == 0 ? MEMDBG_OK
                                                               : MEMDBG_ERR_NET;
}

static memdbg_status_t legacy_handle_fw_version(socket_t fd) {
  uint16_t fw_version = 0U;
  return legacy_send_blob(fd, &fw_version, sizeof(fw_version)) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}

static memdbg_status_t legacy_handle_process_list(socket_t fd) {
  memdbg_process_list_t list;
  memdbg_status_t status;
  legacy_proc_list_entry_t *entries;
  uint32_t count;
  size_t payload_len;

  memset(&list, 0, sizeof(list));
  status = memdbg_process_list(&list);
  if (status != MEMDBG_OK || list.count == 0U || list.count > UINT32_MAX) {
    memdbg_process_list_free(&list);
    return legacy_send_memdbg_status(fd, status == MEMDBG_OK ? MEMDBG_ERR_NOT_FOUND
                                                             : status) == 0
               ? MEMDBG_OK
               : MEMDBG_ERR_NET;
  }

  count = (uint32_t)list.count;
  if (count > UINT32_MAX / (uint32_t)sizeof(*entries)) {
    memdbg_process_list_free(&list);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK
                                                         : MEMDBG_ERR_NET;
  }

  payload_len = (size_t)count * sizeof(*entries);
  entries = (legacy_proc_list_entry_t *)calloc(count, sizeof(*entries));
  if (entries == NULL) {
    memdbg_process_list_free(&list);
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  for (uint32_t i = 0U; i < count; ++i) {
    legacy_copy_fixed(entries[i].name, sizeof(entries[i].name),
                      list.entries[i].name);
    entries[i].pid = list.entries[i].pid;
  }

  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0 ||
      legacy_send_blob(fd, &count, sizeof(count)) != 0 ||
      legacy_send_blob(fd, entries, payload_len) != 0) {
    free(entries);
    memdbg_process_list_free(&list);
    return MEMDBG_ERR_NET;
  }

  free(entries);
  memdbg_process_list_free(&list);
  return MEMDBG_OK;
}

static memdbg_status_t legacy_handle_process_maps(socket_t fd,
                                                  const void *body,
                                                  uint32_t body_len) {
  const legacy_proc_info_packet_t *req;
  memdbg_map_list_t list;
  legacy_proc_maps_entry_t *entries;
  uint32_t count;
  memdbg_status_t status;
  size_t payload_len;

  if (!legacy_has_body(body, body_len, sizeof(*req))) {
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  req = (const legacy_proc_info_packet_t *)body;
  memset(&list, 0, sizeof(list));
  status = memdbg_process_maps((int)req->pid, &list);
  if (status != MEMDBG_OK || list.count == 0U || list.count > UINT32_MAX) {
    memdbg_process_maps_free(&list);
    return legacy_send_memdbg_status(fd, status == MEMDBG_OK ? MEMDBG_ERR_NOT_FOUND
                                                             : status) == 0
               ? MEMDBG_OK
               : MEMDBG_ERR_NET;
  }

  count = (uint32_t)list.count;
  if (count > UINT32_MAX / (uint32_t)sizeof(*entries)) {
    memdbg_process_maps_free(&list);
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK
                                                         : MEMDBG_ERR_NET;
  }

  payload_len = (size_t)count * sizeof(*entries);
  entries = (legacy_proc_maps_entry_t *)calloc(count, sizeof(*entries));
  if (entries == NULL) {
    memdbg_process_maps_free(&list);
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  for (uint32_t i = 0U; i < count; ++i) {
    legacy_copy_fixed(entries[i].name, sizeof(entries[i].name),
                      list.entries[i].name);
    entries[i].start = list.entries[i].start;
    entries[i].end = list.entries[i].end;
    entries[i].offset = 0U;
    entries[i].protection = (uint16_t)(list.entries[i].protection & 0xFFFFU);
  }

  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0 ||
      legacy_send_blob(fd, &count, sizeof(count)) != 0 ||
      legacy_send_blob(fd, entries, payload_len) != 0) {
    free(entries);
    memdbg_process_maps_free(&list);
    return MEMDBG_ERR_NET;
  }

  free(entries);
  memdbg_process_maps_free(&list);
  return MEMDBG_OK;
}

static memdbg_status_t legacy_handle_process_info(socket_t fd,
                                                  const void *body,
                                                  uint32_t body_len) {
  const legacy_proc_info_packet_t *req;
  memdbg_process_info_response_t info;
  legacy_proc_info_response_t out;
  memdbg_status_t status;

  if (!legacy_has_body(body, body_len, sizeof(*req))) {
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  req = (const legacy_proc_info_packet_t *)body;
  memset(&info, 0, sizeof(info));
  status = memdbg_process_info((int)req->pid, &info);
  if (status != MEMDBG_OK) {
    return legacy_send_memdbg_status(fd, status) == 0 ? MEMDBG_OK
                                                      : MEMDBG_ERR_NET;
  }

  memset(&out, 0, sizeof(out));
  out.pid = (uint32_t)info.pid;
  legacy_copy_fixed(out.name, sizeof(out.name), info.name);
  legacy_copy_fixed(out.path, sizeof(out.path), info.path);
  legacy_copy_fixed(out.title_id, sizeof(out.title_id), info.title_id);
  legacy_copy_fixed(out.content_id, sizeof(out.content_id), info.content_id);

  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0 ||
      legacy_send_blob(fd, &out, sizeof(out)) != 0) {
    return MEMDBG_ERR_NET;
  }
  return MEMDBG_OK;
}

static bool legacy_rw_allowed(const memdbg_config_t *cfg, uint32_t length) {
  uint32_t max_read = cfg != NULL ? cfg->max_read_bytes : MEMDBG_PROTOCOL_MAX_READ;
  return length <= max_read;
}

static memdbg_status_t legacy_handle_memory_read(socket_t fd,
                                                 const memdbg_config_t *cfg,
                                                 const void *body,
                                                 uint32_t body_len) {
  const legacy_memory_packet_t *req;
  uint8_t *buffer;
  uint64_t address;
  uint32_t remaining;

  if (!legacy_has_body(body, body_len, sizeof(*req))) {
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  req = (const legacy_memory_packet_t *)body;
  if (!legacy_rw_allowed(cfg, req->length)) {
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK
                                                         : MEMDBG_ERR_NET;
  }

  buffer = (uint8_t *)malloc(LEGACY_RW_CHUNK);
  if (buffer == NULL) {
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0) {
    free(buffer);
    return MEMDBG_ERR_NET;
  }

  address = req->address;
  remaining = req->length;
  while (remaining != 0U) {
    uint32_t chunk = remaining > LEGACY_RW_CHUNK ? LEGACY_RW_CHUNK : remaining;
    size_t got = 0U;
    memset(buffer, 0, chunk);
    (void)memdbg_memory_read((int)req->pid, address, buffer, chunk, &got);
    if (got < chunk) {
      memset(buffer + got, 0, (size_t)chunk - got);
    }
    if (legacy_send_blob(fd, buffer, chunk) != 0) {
      free(buffer);
      return MEMDBG_ERR_NET;
    }
    address += chunk;
    remaining -= chunk;
  }

  free(buffer);
  return MEMDBG_OK;
}

static memdbg_status_t legacy_handle_memory_write(socket_t fd,
                                                  const memdbg_config_t *cfg,
                                                  const void *body,
                                                  uint32_t body_len) {
  const legacy_memory_packet_t *req;
  uint8_t *buffer;
  uint64_t address;
  uint32_t remaining;
  bool failed = false;

  if (!legacy_has_body(body, body_len, sizeof(*req))) {
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  req = (const legacy_memory_packet_t *)body;
  if (!legacy_rw_allowed(cfg, req->length)) {
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK
                                                         : MEMDBG_ERR_NET;
  }

  buffer = (uint8_t *)malloc(LEGACY_RW_CHUNK);
  if (buffer == NULL) {
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0) {
    free(buffer);
    return MEMDBG_ERR_NET;
  }

  address = req->address;
  remaining = req->length;
  while (remaining != 0U) {
    uint32_t chunk = remaining > LEGACY_RW_CHUNK ? LEGACY_RW_CHUNK : remaining;
    size_t written = 0U;

    if (pal_socket_read_exact(fd, buffer, chunk) < 0) {
      free(buffer);
      return MEMDBG_ERR_NET;
    }

    if (memdbg_memory_write((int)req->pid, address, buffer, chunk, &written) !=
            MEMDBG_OK ||
        written != chunk) {
      failed = true;
    }
    address += chunk;
    remaining -= chunk;
  }

  free(buffer);
  return legacy_send_status(fd, failed ? LEGACY_CMD_ERROR : LEGACY_CMD_SUCCESS) ==
                 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}

static memdbg_status_t legacy_handle_write_multi(socket_t fd,
                                                 const memdbg_config_t *cfg,
                                                 const void *body,
                                                 uint32_t body_len) {
  const legacy_proc_write_multi_packet_t *req;
  uint8_t *buffer;
  uint8_t *status_bytes = NULL;
  bool want_status;

  if (!legacy_has_body(body, body_len, sizeof(*req))) {
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  req = (const legacy_proc_write_multi_packet_t *)body;
  if (req->count > LEGACY_WRITE_MULTI_MAX_COUNT) {
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK
                                                         : MEMDBG_ERR_NET;
  }

  buffer = (uint8_t *)malloc(LEGACY_RW_CHUNK);
  if (buffer == NULL) {
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  want_status = (req->flags & LEGACY_WRITE_MULTI_STATUS) != 0U;
  if (want_status && req->count != 0U) {
    status_bytes = (uint8_t *)calloc(req->count, sizeof(*status_bytes));
    if (status_bytes == NULL) {
      free(buffer);
      return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                               : MEMDBG_ERR_NET;
    }
  }

  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0) {
    free(status_bytes);
    free(buffer);
    return MEMDBG_ERR_NET;
  }

  for (uint32_t i = 0U; i < req->count; ++i) {
    legacy_proc_write_multi_entry_t entry;
    uint64_t address;
    uint32_t remaining;
    bool failed = false;

    if (pal_socket_read_exact(fd, &entry, sizeof(entry)) < 0) {
      free(status_bytes);
      free(buffer);
      return MEMDBG_ERR_NET;
    }
    if (entry.length > LEGACY_WRITE_MULTI_MAX_ENTRY ||
        !legacy_rw_allowed(cfg, entry.length)) {
      free(status_bytes);
      free(buffer);
      return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK
                                                           : MEMDBG_ERR_NET;
    }

    address = entry.address;
    remaining = entry.length;
    while (remaining != 0U) {
      uint32_t chunk = remaining > LEGACY_RW_CHUNK ? LEGACY_RW_CHUNK : remaining;
      size_t written = 0U;

      if (pal_socket_read_exact(fd, buffer, chunk) < 0) {
        free(status_bytes);
        free(buffer);
        return MEMDBG_ERR_NET;
      }

      if (memdbg_memory_write((int)req->pid, address, buffer, chunk, &written) !=
              MEMDBG_OK ||
          written != chunk) {
        failed = true;
      }
      address += chunk;
      remaining -= chunk;
    }

    if (status_bytes != NULL) {
      status_bytes[i] = failed ? 1U : 0U;
    }
  }

  if (status_bytes != NULL &&
      legacy_send_blob(fd, status_bytes, req->count) != 0) {
    free(status_bytes);
    free(buffer);
    return MEMDBG_ERR_NET;
  }

  free(status_bytes);
  free(buffer);
  return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 ? MEMDBG_OK
                                                         : MEMDBG_ERR_NET;
}

static memdbg_status_t legacy_handle_process_alloc(socket_t fd,
                                                   const void *body,
                                                   uint32_t body_len,
                                                   bool hinted) {
  legacy_proc_alloc_response_t out;
  memdbg_status_t status;
  uint32_t pid;
  uint32_t length;
  uint64_t hint = 0U;
  uint64_t address = 0U;

  if (hinted) {
    const legacy_proc_alloc_hinted_packet_t *req;
    if (!legacy_has_body(body, body_len, sizeof(*req))) {
      return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                               : MEMDBG_ERR_NET;
    }
    req = (const legacy_proc_alloc_hinted_packet_t *)body;
    pid = req->pid;
    length = req->length;
    hint = req->hint;
  } else {
    const legacy_proc_alloc_packet_t *req;
    if (!legacy_has_body(body, body_len, sizeof(*req))) {
      return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                               : MEMDBG_ERR_NET;
    }
    req = (const legacy_proc_alloc_packet_t *)body;
    pid = req->pid;
    length = req->length;
  }

  if (pid == 0U || length == 0U) {
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK
                                                         : MEMDBG_ERR_NET;
  }

  status = pal_memory_alloc((int)pid, hint, length,
                            MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_WRITE |
                                MEMDBG_MAP_PROT_EXEC,
                            hinted ? 1U : 0U, &address);
  memset(&out, 0, sizeof(out));
  out.address = address;

  if (legacy_send_memdbg_status(fd, status) != 0) {
    return MEMDBG_ERR_NET;
  }
  if ((status == MEMDBG_OK || hinted) &&
      legacy_send_blob(fd, &out, sizeof(out)) != 0) {
    return MEMDBG_ERR_NET;
  }
  return MEMDBG_OK;
}

static memdbg_status_t legacy_handle_process_free(socket_t fd,
                                                  const void *body,
                                                  uint32_t body_len) {
  const legacy_proc_free_packet_t *req;
  memdbg_status_t status;

  if (!legacy_has_body(body, body_len, sizeof(*req))) {
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  req = (const legacy_proc_free_packet_t *)body;
  if (req->pid == 0U || req->address == 0U || req->length == 0U) {
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK
                                                         : MEMDBG_ERR_NET;
  }

  status = pal_memory_free((int)req->pid, req->address, req->length);
  return legacy_send_memdbg_status(fd, status) == 0 ? MEMDBG_OK
                                                    : MEMDBG_ERR_NET;
}

static memdbg_status_t legacy_handle_process_protect(socket_t fd,
                                                     const void *body,
                                                     uint32_t body_len) {
  const legacy_proc_protect_packet_t *req;
  memdbg_status_t status;

  if (!legacy_has_body(body, body_len, sizeof(*req))) {
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  req = (const legacy_proc_protect_packet_t *)body;
  if (req->pid == 0U || req->address == 0U || req->length == 0U ||
      (req->protection & ~(MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_WRITE |
                           MEMDBG_MAP_PROT_EXEC)) != 0U) {
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK
                                                         : MEMDBG_ERR_NET;
  }

  status = pal_memory_protect((int)req->pid, req->address, req->length,
                              req->protection, NULL);
  return legacy_send_memdbg_status(fd, status) == 0 ? MEMDBG_OK
                                                    : MEMDBG_ERR_NET;
}

static memdbg_status_t legacy_handle_first_map(socket_t fd, const void *body,
                                               uint32_t body_len) {
  const legacy_proc_info_packet_t *req;
  memdbg_map_list_t list;
  int64_t first = 0;
  memdbg_status_t status;

  if (!legacy_has_body(body, body_len, sizeof(*req))) {
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK
                                                             : MEMDBG_ERR_NET;
  }

  req = (const legacy_proc_info_packet_t *)body;
  memset(&list, 0, sizeof(list));
  status = memdbg_process_maps((int)req->pid, &list);
  if (status != MEMDBG_OK || list.count == 0U) {
    memdbg_process_maps_free(&list);
    return legacy_send_memdbg_status(fd, status == MEMDBG_OK ? MEMDBG_ERR_NOT_FOUND
                                                             : status) == 0
               ? MEMDBG_OK
               : MEMDBG_ERR_NET;
  }

  first = (int64_t)list.entries[0].start;
  memdbg_process_maps_free(&list);

  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0 ||
      legacy_send_blob(fd, &first, sizeof(first)) != 0) {
    return MEMDBG_ERR_NET;
  }
  return MEMDBG_OK;
}

static memdbg_status_t legacy_handle_install(socket_t fd) {
  uint64_t rpc_stub = 0U;
  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0 ||
      legacy_send_blob(fd, &rpc_stub, sizeof(rpc_stub)) != 0) {
    return MEMDBG_ERR_NET;
  }
  return MEMDBG_OK;
}

static memdbg_status_t legacy_dispatch(socket_t fd, const memdbg_config_t *cfg,
                                       const legacy_packet_header_t *header,
                                       const void *body) {
  if (header == NULL || !legacy_is_valid_command(header->command)) {
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK
                                                         : MEMDBG_ERR_NET;
  }

  switch (header->command) {
  case LEGACY_CMD_VERSION:
    return legacy_handle_version(fd);
  case LEGACY_CMD_FW_VERSION:
    return legacy_handle_fw_version(fd);
  case LEGACY_CMD_BRANDING:
    return legacy_handle_branding(fd);
  case LEGACY_CMD_PLATFORM_ID:
    return legacy_handle_platform_id(fd);
  case LEGACY_CMD_PROC_NOP:
  case LEGACY_CMD_PROC_AUTH:
    return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 ? MEMDBG_OK
                                                           : MEMDBG_ERR_NET;
  case LEGACY_CMD_PROC_LIST:
    return legacy_handle_process_list(fd);
  case LEGACY_CMD_PROC_READ:
    return legacy_handle_memory_read(fd, cfg, body, header->data_len);
  case LEGACY_CMD_PROC_WRITE:
    return legacy_handle_memory_write(fd, cfg, body, header->data_len);
  case LEGACY_CMD_PROC_WRITE_MULTI:
    return legacy_handle_write_multi(fd, cfg, body, header->data_len);
  case LEGACY_CMD_PROC_MAPS:
    return legacy_handle_process_maps(fd, body, header->data_len);
  case LEGACY_CMD_PROC_INSTALL:
    return legacy_handle_install(fd);
  case LEGACY_CMD_PROC_PROTECT:
    return legacy_handle_process_protect(fd, body, header->data_len);
  case LEGACY_CMD_PROC_INFO:
    return legacy_handle_process_info(fd, body, header->data_len);
  case LEGACY_CMD_PROC_ALLOC:
    return legacy_handle_process_alloc(fd, body, header->data_len, false);
  case LEGACY_CMD_PROC_FREE:
    return legacy_handle_process_free(fd, body, header->data_len);
  case LEGACY_CMD_PROC_FIRST_MAP:
    return legacy_handle_first_map(fd, body, header->data_len);
  case LEGACY_CMD_PROC_ALLOC_HINTED:
    return legacy_handle_process_alloc(fd, body, header->data_len, true);
  default:
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK
                                                         : MEMDBG_ERR_NET;
  }
}

static void legacy_handle_client(socket_t fd, const memdbg_config_t *cfg) {
  (void)pal_socket_set_nonblocking(fd, false);
  (void)pal_socket_configure(fd);

  while (atomic_load_explicit(&g_legacy_running, memory_order_relaxed) &&
         !memdbg_daemon_should_stop()) {
    legacy_packet_header_t header;
    void *body = NULL;
    int ready = legacy_wait_for_fd(fd);

    if (ready == 0) {
      continue;
    }
    if (ready < 0) {
      break;
    }
    if (pal_socket_read_exact(fd, &header, sizeof(header)) < 0) {
      break;
    }
    if (header.magic != LEGACY_PACKET_MAGIC) {
      (void)legacy_send_status(fd, LEGACY_CMD_ERROR);
      break;
    }
    if (header.data_len > cfg->max_packet_bytes) {
      (void)legacy_send_status(fd, LEGACY_CMD_ERROR);
      break;
    }
    if (header.data_len != 0U) {
      body = malloc(header.data_len);
      if (body == NULL) {
        (void)legacy_send_status(fd, LEGACY_CMD_DATA_NULL);
        break;
      }
      if (pal_socket_read_exact(fd, body, header.data_len) < 0) {
        free(body);
        break;
      }
    }

    if (legacy_dispatch(fd, cfg, &header, body) == MEMDBG_ERR_NET) {
      free(body);
      break;
    }
    free(body);
  }

  (void)pal_socket_close(fd);
}

static void *legacy_client_thread(void *arg) {
  legacy_client_args_t *client = (legacy_client_args_t *)arg;
  socket_t fd = client->fd;
  memdbg_config_t cfg = client->cfg;

  free(client);
  legacy_handle_client(fd, &cfg);
  return NULL;
}

static void legacy_spawn_client(socket_t fd, const memdbg_config_t *cfg) {
  legacy_client_args_t *args;
  pthread_t tid;
  pthread_attr_t attr;
  int rc;

  args = (legacy_client_args_t *)malloc(sizeof(*args));
  if (args == NULL) {
    (void)pal_socket_close(fd);
    return;
  }
  args->fd = fd;
  args->cfg = *cfg;

  (void)pthread_attr_init(&attr);
  (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  rc = pthread_create(&tid, &attr, legacy_client_thread, args);
  (void)pthread_attr_destroy(&attr);
  if (rc != 0) {
    free(args);
    (void)pal_socket_close(fd);
  }
}

static void *legacy_listener_thread(void *arg) {
  (void)arg;

  while (atomic_load_explicit(&g_legacy_running, memory_order_relaxed) &&
         !memdbg_daemon_should_stop()) {
    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)sizeof(ss);
    socket_t client_fd;
    int ready = legacy_wait_for_fd(g_legacy_listen_fd);

    if (ready == 0) {
      continue;
    }
    if (ready < 0) {
      if (atomic_load_explicit(&g_legacy_running, memory_order_relaxed) &&
          !memdbg_daemon_should_stop()) {
        memdbg_log_write(MEMDBG_LOG_WARN,
                         "ps5debug-compat: listener wait failed: %s",
                         pal_socket_last_error());
      }
      break;
    }

    client_fd = accept(g_legacy_listen_fd, (struct sockaddr *)&ss, &slen);
    if (client_fd < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      if (atomic_load_explicit(&g_legacy_running, memory_order_relaxed) &&
          !memdbg_daemon_should_stop()) {
        memdbg_log_write(MEMDBG_LOG_WARN,
                         "ps5debug-compat: accept failed: %s",
                         pal_socket_last_error());
      }
      continue;
    }

    if (!legacy_peer_allowed(&g_legacy_cfg, &ss)) {
      char peer_host[INET_ADDRSTRLEN];
      const char *peer = "unknown";
      if (legacy_sockaddr_ipv4_host(&ss, peer_host, sizeof(peer_host))) {
        peer = peer_host;
      }
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "ps5debug-compat: client rejected: peer=%s allow=%s",
                       peer, g_legacy_cfg.allow_host);
      (void)pal_socket_close(client_fd);
      continue;
    }

    legacy_spawn_client(client_fd, &g_legacy_cfg);
  }

  return NULL;
}

memdbg_status_t memdbg_ps5debug_compat_start(const memdbg_config_t *cfg) {
  socket_t listen_fd = PAL_INVALID_SOCKET;

  if (cfg == NULL || cfg->legacy_port == 0U) {
    return MEMDBG_ERR_PARAM;
  }
  if (atomic_exchange_explicit(&g_legacy_running, true, memory_order_relaxed)) {
    return MEMDBG_OK;
  }

  if (pal_tcp_listen(cfg->bind_host, cfg->legacy_port, 12, &listen_fd) != 0) {
    atomic_store_explicit(&g_legacy_running, false, memory_order_relaxed);
    return MEMDBG_ERR_NET;
  }

  g_legacy_cfg = *cfg;
  g_legacy_listen_fd = listen_fd;
  if (pthread_create(&g_legacy_thread, NULL, legacy_listener_thread, NULL) !=
      0) {
    (void)pal_socket_close(g_legacy_listen_fd);
    g_legacy_listen_fd = PAL_INVALID_SOCKET;
    atomic_store_explicit(&g_legacy_running, false, memory_order_relaxed);
    return MEMDBG_ERR_NET;
  }

  g_legacy_thread_started = true;
  return MEMDBG_OK;
}

void memdbg_ps5debug_compat_stop(void) {
  if (!atomic_exchange_explicit(&g_legacy_running, false,
                                memory_order_relaxed)) {
    return;
  }

  if (g_legacy_listen_fd != PAL_INVALID_SOCKET) {
    (void)shutdown(g_legacy_listen_fd, SHUT_RDWR);
    (void)pal_socket_close(g_legacy_listen_fd);
    g_legacy_listen_fd = PAL_INVALID_SOCKET;
  }

  if (g_legacy_thread_started) {
    (void)pthread_join(g_legacy_thread, NULL);
    g_legacy_thread_started = false;
  }
}

#undef LEGACY_PACKED
