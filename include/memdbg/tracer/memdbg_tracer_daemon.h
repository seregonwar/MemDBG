/*
 * memDBG - Tracer daemon module.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Wraps the syscall tracer in a thread-safe service that runs in a dedicated
 * background thread and feeds events into a ring buffer readable from the
 * protocol dispatch (which runs inside the thread-pool worker threads).
 *
 * Thread-safety model:
 *   - The tracer thread writes to the ring buffer (single producer).
 *   - Protocol handlers read from the ring buffer via poll (single consumer).
 *   - State transitions (start/stop/status) are guarded by a mutex.
 */

#ifndef MEMDBG_TRACER_DAEMON_H
#define MEMDBG_TRACER_DAEMON_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns true if the daemon-side tracer service is available
 * (the platform supports pal_debug attach). */
bool memdbg_tracer_daemon_available(void);

/* Start tracing a process in a background thread.
 * Copies the dump_path.  Returns MEMDBG_OK on success, MEMDBG_ERR_STATE if
 * already running, MEMDBG_ERR_PERMISSION if attach failed. */
memdbg_status_t memdbg_tracer_daemon_start(int32_t pid, const char *dump_path);

/* Request the tracer thread to stop and join it.
 * Safe to call regardless of state. */
void memdbg_tracer_daemon_stop(void);

/* Returns true if the tracer thread is currently active. */
bool memdbg_tracer_daemon_is_running(void);

/* Copy pending events from the ring buffer into the caller's array.
 * Returns the number of events written (up to max_count). */
uint32_t memdbg_tracer_daemon_poll_events(memdbg_tracer_event_t *out,
                                          uint32_t max_count);

/* Fill a status response with the current tracer state. */
void memdbg_tracer_daemon_status(memdbg_tracer_status_response_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_TRACER_DAEMON_H */
