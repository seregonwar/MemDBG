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

#ifndef MEMDBG_TELEMETRY_UDP_LOG_H
#define MEMDBG_TELEMETRY_UDP_LOG_H

#include "memdbg/core/memdbg.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct memdbg_udp_log_config {
  char host[MEMDBG_UDP_HOST_MAX];
  uint16_t port;
  bool broadcast;
} memdbg_udp_log_config_t;

void memdbg_udp_log_config_defaults(memdbg_udp_log_config_t *cfg);
memdbg_status_t memdbg_udp_log_start(const memdbg_udp_log_config_t *cfg);
memdbg_status_t memdbg_udp_log_set_destination(const char *host,
                                               uint16_t port,
                                               bool broadcast);
void memdbg_udp_log_stop(void);
bool memdbg_udp_log_enabled(void);
void memdbg_udp_log_send(const char *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_TELEMETRY_UDP_LOG_H */
