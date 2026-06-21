/*
 * memDBG Tracer — CLI tool.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Usage:
 *   sudo ./tracer --pid=1234
 *   sudo ./tracer --pid=1234 --dump=crash.json
 *   sudo ./tracer --pid=1234 --crash-only
 */

#include "memdbg/tracer/memdbg_tracer.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static memdbg_tracer_t *g_tracer = NULL;

static void handle_sigint(int sig) {
  (void)sig;
  fprintf(stderr, "\n[!] Shutdown requested, stopping tracer...\n");
  if (g_tracer) memdbg_tracer_request_stop(g_tracer);
}

static void print_usage(const char *prog) {
  fprintf(stderr,
      "Usage: %s --pid=N [options]\n"
      "\n"
      "Options:\n"
      "  --pid=PID           Target process ID (required)\n"
      "  --dump=FILE         Crash dump output path (default: auto)\n"
      "  --crash-only        Force crash-only mode (disable syscall trace)\n"
      "  --ring-size=N       Ring buffer capacity, power of 2 (default: 4096)\n"
      "  --help              Show this help\n"
      "\n"
      "Note: ptrace attach requires appropriate privileges (root on macOS).\n",
      prog);
}

int main(int argc, char **argv) {
  int pid = 0;
  char dump_path[512] = "";
  bool crash_only = false;
  uint32_t ring_size = MEMDBG_TRACER_DEFAULT_RING_SIZE;

  /* Parse arguments */
  for (int i = 1; i < argc; i++) {
    if (strncmp(argv[i], "--pid=", 6) == 0) {
      pid = atoi(argv[i] + 6);
    } else if (strncmp(argv[i], "--dump=", 7) == 0) {
      size_t n = strlen(argv[i] + 7);
      if (n >= sizeof(dump_path)) n = sizeof(dump_path) - 1;
      memcpy(dump_path, argv[i] + 7, n);
      dump_path[n] = '\0';
    } else if (strcmp(argv[i], "--crash-only") == 0) {
      crash_only = true;
    } else if (strncmp(argv[i], "--ring-size=", 12) == 0) {
      ring_size = (uint32_t)atoi(argv[i] + 12);
    } else if (strcmp(argv[i], "--help") == 0) {
      print_usage(argv[0]);
      return 0;
    } else {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      print_usage(argv[0]);
      return 1;
    }
  }

  if (pid <= 0) {
    fprintf(stderr, "Error: --pid=PID is required\n");
    print_usage(argv[0]);
    return 1;
  }

  if (!memdbg_tracer_supported()) {
    fprintf(stderr, "Error: tracer not supported on this platform\n");
    return 1;
  }

  /* Check if full syscall tracing is available */
  bool syscall_avail = memdbg_tracer_syscall_supported();
  if (crash_only) {
    syscall_avail = false;
  }

  fprintf(stderr,
      "[*] Attaching to PID %d\n"
      "[*] Mode: %s\n"
      "[*] Ring buffer: %u events\n",
      pid,
      syscall_avail ? "full syscall trace" : "crash-only",
      ring_size);

  if (!syscall_avail && !crash_only) {
    fprintf(stderr, "[*] Full syscall tracing not available, falling back to crash-only\n");
  }

  memdbg_tracer_config_t cfg = MEMDBG_TRACER_CONFIG_INIT;
  cfg.pid = (int32_t)pid;
  cfg.ring_size = ring_size;
  cfg.trace_syscalls = syscall_avail;
  if (dump_path[0]) {
    size_t n = strlen(dump_path);
    if (n >= sizeof(cfg.dump_path)) n = sizeof(cfg.dump_path) - 1;
    memcpy(cfg.dump_path, dump_path, n);
    cfg.dump_path[n] = '\0';
  }

  g_tracer = memdbg_tracer_create(&cfg);
  if (!g_tracer) {
    fprintf(stderr, "Error: failed to create tracer: %s\n", strerror(errno));
    return 1;
  }

  signal(SIGINT, handle_sigint);

  fprintf(stderr, "[*] Running... (Ctrl+C to stop)\n");

  memdbg_status_t st = memdbg_tracer_run(g_tracer);

  switch (st) {
    case MEMDBG_OK:
      fprintf(stderr, "\n[*] Crash detected! Dump written to: %s\n",
              memdbg_tracer_dump_path(g_tracer));
      break;
    case MEMDBG_ERR_NOT_FOUND:
      fprintf(stderr, "\n[*] Process exited normally, no crash\n");
      break;
    case MEMDBG_ERR_STATE:
      fprintf(stderr, "\n[*] Tracer stopped by user\n");
      break;
    case MEMDBG_ERR_PERMISSION:
      fprintf(stderr, "\n[!] Permission denied — run as root?\n");
      break;
    default:
      fprintf(stderr, "\n[!] Tracer returned error %d\n", (int)st);
      break;
  }

  memdbg_tracer_destroy(g_tracer);
  g_tracer = NULL;
  return (st == MEMDBG_OK) ? 0 : 1;
}
