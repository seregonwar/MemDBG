/*
 * MemDBG - Single-instance helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_CORE_MEMDBG_INSTANCE_H
#define MEMDBG_CORE_MEMDBG_INSTANCE_H

#include "memdbg/core/memdbg.h"

#ifdef __cplusplus
extern "C" {
#endif

memdbg_status_t memdbg_instance_stop_previous(const memdbg_config_t *cfg);
int memdbg_instance_write_pid_file(const memdbg_config_t *cfg);
void memdbg_instance_remove_pid_file(const memdbg_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_INSTANCE_H */
