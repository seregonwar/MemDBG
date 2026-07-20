/*
 * MemDBG - Single-instance helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_CORE_MEMDBG_INSTANCE_H
#define MEMDBG_CORE_MEMDBG_INSTANCE_H

#include "memdbg/core/memdbg.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

memdbg_status_t memdbg_instance_stop_previous(const memdbg_config_t *cfg);
bool memdbg_instance_is_current_process(const memdbg_config_t *cfg);
int memdbg_instance_write_pid_file(const memdbg_config_t *cfg);
void memdbg_instance_remove_pid_file(const memdbg_config_t *cfg);

/* Returns the daemon's unique instance ID, generating it on first call. */
uint64_t memdbg_daemon_instance_id(void);

/* Returns the monotonic clock value captured when the instance ID was
 * generated, or 0 if it has not been generated yet. */
uint64_t memdbg_daemon_start_ns(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_INSTANCE_H */
