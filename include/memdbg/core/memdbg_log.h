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

#ifndef MEMDBG_CORE_MEMDBG_LOG_H
#define MEMDBG_CORE_MEMDBG_LOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum memdbg_log_level {
  MEMDBG_LOG_DEBUG = 0,
  MEMDBG_LOG_INFO = 1,
  MEMDBG_LOG_WARN = 2,
  MEMDBG_LOG_ERROR = 3
} memdbg_log_level_t;

int memdbg_log_init(const char *data_root);
void memdbg_log_close(void);
void memdbg_log_set_stderr(bool enabled);
void memdbg_log_write(memdbg_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void memdbg_log_vwrite(memdbg_log_level_t level, const char *fmt, va_list ap);
const char *memdbg_log_path(void);
const char *memdbg_log_mirror_path(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_CORE_MEMDBG_LOG_H */
