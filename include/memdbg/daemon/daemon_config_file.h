/*
 * MemDBG - Persistent daemon.conf under data_root.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_DAEMON_CONFIG_FILE_H
#define MEMDBG_DAEMON_CONFIG_FILE_H

#include "memdbg/core/memdbg.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEMDBG_DAEMON_CONF_NAME "daemon.conf"

/* Build ${data_root}/daemon.conf into out. Returns 0 on success. */
int memdbg_daemon_config_path(const char *data_root, char *out, size_t out_size);

/* Apply keys from daemon.conf into cfg. Missing file is success (returns 0).
 * Only known keys are applied; other cfg fields are left unchanged. */
int memdbg_daemon_config_load(const char *data_root, memdbg_config_t *cfg);

/* Rewrite daemon.conf from cfg (currently persists legacy_compat). */
int memdbg_daemon_config_save(const char *data_root, const memdbg_config_t *cfg);

/* Parse a single "key=value" line (comments/blank ignored). Used by tests. */
int memdbg_daemon_config_parse_line(const char *line, memdbg_config_t *cfg);

/* Runtime published config (updated by SET_SERVICES). */
void memdbg_daemon_config_publish(const memdbg_config_t *cfg);
void memdbg_daemon_config_snapshot(memdbg_config_t *out);
bool memdbg_daemon_config_legacy_enabled(void);
void memdbg_daemon_config_set_legacy_enabled(bool enabled);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_DAEMON_CONFIG_FILE_H */
