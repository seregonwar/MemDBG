/*
 * memDBG - Syscall tracer & crash dump module.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Provides a ptrace-based syscall tracer that attaches to an existing process,
 * records every system call, and on crash dumps the full trace together with
 * register state, memory maps and a stack unwind to a JSON file.
 */

#ifndef MEMDBG_TRACER_MEMDBG_TRACER_H
#define MEMDBG_TRACER_MEMDBG_TRACER_H

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Constants --------------------------------------------------------- */

/* Event types written into the ring buffer. */
#define MEMDBG_TRACER_EVENT_SYSCALL_ENTRY  1U
#define MEMDBG_TRACER_EVENT_SYSCALL_EXIT   2U
#define MEMDBG_TRACER_EVENT_SIGNAL         3U
#define MEMDBG_TRACER_EVENT_CRASH          4U

/* Maximum number of syscall arguments the tracer captures. */
#define MEMDBG_TRACER_MAX_ARGS 6U

/* Default ring-buffer capacity (must be a power of 2). */
#define MEMDBG_TRACER_DEFAULT_RING_SIZE 4096U

/* Note: memdbg_tracer_event_t is defined in memdbg_protocol.h (included above)
 * and is used for both wire format and in-memory ring buffers. */

/* ---- Tracer configuration --------------------------------------------- */

typedef struct memdbg_tracer_config {
  int32_t pid;                                 /* target process ID          */
  char    dump_path[512];                      /* output file path           */
  uint32_t ring_size;                          /* ring buffer capacity       */
  bool    trace_syscalls;                      /* attempt full syscall trace */
  bool    follow_fork;                         /* trace child processes      */
} memdbg_tracer_config_t;

#define MEMDBG_TRACER_CONFIG_INIT { 0, "", MEMDBG_TRACER_DEFAULT_RING_SIZE, true, false }

/* ---- Opaque tracer handle --------------------------------------------- */

typedef struct memdbg_tracer memdbg_tracer_t;

/* ---- Public API ------------------------------------------------------- */

/* Returns true if tracer operations have at least minimal support on this
 * platform (attach + crash detection).  Full syscall tracing additionally
 * requires pal_debug_syscall() to succeed. */
bool memdbg_tracer_supported(void);

/* Returns true if the platform supports full syscall entry/exit tracing
 * (i.e. PT_SYSCALL is available).  When false, the tracer falls back to
 * crash-only mode. */
bool memdbg_tracer_syscall_supported(void);

/* Create a tracer instance with the given configuration.
 * Returns NULL and sets errno on failure. */
memdbg_tracer_t *memdbg_tracer_create(const memdbg_tracer_config_t *cfg);

/* Destroy a tracer instance and free all associated resources. */
void memdbg_tracer_destroy(memdbg_tracer_t *tracer);

/* Run the tracer loop.  Blocks until one of:
 *   - the target process crashes (returns MEMDBG_OK)
 *   - the target process exits normally  (returns MEMDBG_ERR_NOT_FOUND)
 *   - tracer_request_stop() is called    (returns MEMDBG_ERR_STATE)
 *   - an unrecoverable error occurs
 *
 * On MEMDBG_OK the crash dump has been written to the configured path. */
memdbg_status_t memdbg_tracer_run(memdbg_tracer_t *tracer);

/* Signal-safe: request the tracer loop to stop at the next opportunity. */
void memdbg_tracer_request_stop(memdbg_tracer_t *tracer);

/* After run() completes, copy the ring-buffer events into the caller's
 * buffer.  Returns the number of events written (up to max_count). */
uint32_t memdbg_tracer_events(memdbg_tracer_t *tracer,
                              memdbg_tracer_event_t *out,
                              uint32_t max_count);

/* Return the path of the crash dump file (empty if no crash occurred). */
const char *memdbg_tracer_dump_path(const memdbg_tracer_t *tracer);

/* ---- Syscall frequency statistics ------------------------------------- */

typedef struct memdbg_tracer_syscall_stat {
  uint32_t syscall_no;
  uint64_t call_count;
  uint64_t total_duration_ns;
} memdbg_tracer_syscall_stat_t;

/* Fill *out with the top-max_count syscalls sorted by call_count descending.
 * Returns the number of distinct syscalls written. */
uint32_t memdbg_tracer_syscall_stats(memdbg_tracer_t *tracer,
                                     memdbg_tracer_syscall_stat_t *out,
                                     uint32_t max_count);

/* ---- Syscall name helpers --------------------------------------------- */

/* Look up a syscall number on the current platform.
 * Returns a static string; never returns NULL ("unknown" for unrecognised
 * numbers). */
const char *memdbg_tracer_syscall_name(int syscall_no);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_TRACER_MEMDBG_TRACER_H */
