/*
 * memDBG - Platform-agnostic time/sleep utilities.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Unified sleep_ms helper used by daemon, debugger, and PAL code.
 * Replaces the duplicated daemon_sleep_ms / debugger_sleep_ms /
 * pal_debug_sleep_ms variants.
 */

#ifndef MEMDBG_PAL_TIME_H
#define MEMDBG_PAL_TIME_H

#include <errno.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sleep for at least `ms` milliseconds, retrying on EINTR. */
static inline void memdbg_sleep_ms(uint32_t ms) {
  struct timespec ts;
  ts.tv_sec  = (time_t)(ms / 1000U);
  ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

/* Monotonic wall-clock in seconds. */
uint64_t memdbg_monotonic_seconds(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PAL_TIME_H */
