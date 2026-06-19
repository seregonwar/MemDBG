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

#ifndef MEMDBG_CORE_MEMDBG_H
#define MEMDBG_CORE_MEMDBG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEMDBG_VERSION_MAJOR 0U
#define MEMDBG_VERSION_MINOR 1U
#define MEMDBG_VERSION_PATCH 0U
#define MEMDBG_VERSION_STRING "0.1.0"

#define MEMDBG_BIND_HOST_MAX 64U
#define MEMDBG_ALLOW_HOST_MAX 64U
#define MEMDBG_UDP_HOST_MAX 64U
#define MEMDBG_PATH_MAX 512U

#define MEMDBG_DEFAULT_DEBUG_PORT 9020U
#define MEMDBG_DEFAULT_UDP_LOG_HOST "255.255.255.255"
#define MEMDBG_DEFAULT_UDP_LOG_PORT 9023U
#define MEMDBG_DEFAULT_DISCOVERY_PORT 9022U
#define MEMDBG_DEFAULT_DATA_ROOT "/data/memdbg"

typedef enum memdbg_status {
  MEMDBG_OK = 0,
  MEMDBG_ERR_PARAM = -1,
  MEMDBG_ERR_NOMEM = -2,
  MEMDBG_ERR_IO = -3,
  MEMDBG_ERR_NET = -4,
  MEMDBG_ERR_PROTOCOL = -5,
  MEMDBG_ERR_UNSUPPORTED = -6,
  MEMDBG_ERR_NOT_FOUND = -7,
  MEMDBG_ERR_PERMISSION = -8,
  MEMDBG_ERR_OVERFLOW = -9,
  MEMDBG_ERR_STATE = -10
} memdbg_status_t;

typedef struct memdbg_config {
  char bind_host[MEMDBG_BIND_HOST_MAX];
  char allow_host[MEMDBG_ALLOW_HOST_MAX];
  char udp_log_host[MEMDBG_UDP_HOST_MAX];
  char data_root[MEMDBG_PATH_MAX];
  uint16_t debug_port;
  uint16_t udp_log_port;
  uint16_t discovery_port;
  bool enable_udp_log;
  bool replace_existing;
  uint32_t max_packet_bytes;
  uint32_t max_read_bytes;
  uint32_t max_scan_results;
} memdbg_config_t;

void memdbg_config_defaults(memdbg_config_t *cfg);
const char *memdbg_strerror(memdbg_status_t status);
uint32_t memdbg_capabilities(const memdbg_config_t *cfg);
int memdbg_daemon_run(const memdbg_config_t *cfg);
void memdbg_daemon_request_stop(void);
bool memdbg_daemon_should_stop(void);

#if defined(PLATFORM_PS4) || defined(PLATFORM_PS5) || defined(PS4) ||          \
    defined(PS5) || defined(__ORBIS__) || defined(__PROSPERO__)
int memdbg_main(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_H */
