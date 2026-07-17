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

#include "memdbg/core/memdbg.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool parse_u16(const char *text, uint16_t *out) {
  char *end = NULL;
  unsigned long value;

  if (text == NULL || text[0] == '\0' || out == NULL) {
    return false;
  }

  value = strtoul(text, &end, 10);
  if (end == text || *end != '\0' || value == 0UL || value > 65535UL) {
    return false;
  }

  *out = (uint16_t)value;
  return true;
}

static bool parse_u32(const char *text, uint32_t *out) {
  char *end = NULL;
  unsigned long value;

  if (text == NULL || text[0] == '\0' || out == NULL) {
    return false;
  }

  value = strtoul(text, &end, 10);
  if (end == text || *end != '\0' || value == 0UL || value > 0xffffffffUL) {
    return false;
  }

  *out = (uint32_t)value;
  return true;
}

static void print_usage(const char *argv0) {
  const char *prog = (argv0 != NULL && argv0[0] != '\0') ? argv0 : "memdbg";
  printf("Usage: %s [options]\n", prog);
  printf("  --bind=ADDR              TCP bind address (default 127.0.0.1 on host,\n");
  printf("                           0.0.0.0 on console)\n");
  printf("  --allow=ADDR             Only accept a single IPv4 client address\n");
  printf("  --debug-port=PORT        TCP command port (default %u)\n",
         MEMDBG_DEFAULT_DEBUG_PORT);
  printf("  --legacy-compat          Enable legacy-compatible TCP listener\n");
  printf("  --no-legacy-compat       Disable legacy-compatible TCP listener\n");
  printf("  --legacy-port=PORT       Legacy-compatible port (default %u)\n",
         MEMDBG_DEFAULT_LEGACY_PORT);
  printf("  --udp-host=ADDR          UDP log destination (default %s)\n",
         MEMDBG_DEFAULT_UDP_LOG_HOST);
  printf("  --udp-port=PORT          UDP log port (default %u)\n",
         MEMDBG_DEFAULT_UDP_LOG_PORT);
  printf("  --data-root=PATH         Data/log directory (default %s)\n",
         MEMDBG_DEFAULT_DATA_ROOT);
  printf("  --max-read=BYTES         Maximum single read size\n");
  printf("  --max-packet=BYTES       Maximum request packet size\n");
  printf("  --max-scan-results=N     Maximum scanner result count\n");
  printf("  --max-connections=N      Maximum concurrent TCP clients (default 64)\n");
  printf("  --idle-timeout=MS        Disconnect idle clients after MS ms (default 30000)\n");
  printf("  --replace-existing       Ask a previous payload on the same port to stop (default)\n");
  printf("  --no-replace-existing    Do not stop a previous payload automatically\n");
  printf("  --no-udp-log             Disable UDP log delivery\n");
}

static int apply_arg(memdbg_config_t *cfg, const char *arg) {
  if (cfg == NULL || arg == NULL) {
    return -1;
  }
  if (strncmp(arg, "--bind=", 7) == 0) {
    (void)snprintf(cfg->bind_host, sizeof(cfg->bind_host), "%s", arg + 7);
  } else if (strncmp(arg, "--allow=", 8) == 0) {
    (void)snprintf(cfg->allow_host, sizeof(cfg->allow_host), "%s", arg + 8);
  } else if (strncmp(arg, "--debug-port=", 13) == 0) {
    if (!parse_u16(arg + 13, &cfg->debug_port)) return -1;
  } else if (strncmp(arg, "--legacy-port=", 14) == 0) {
    if (!parse_u16(arg + 14, &cfg->legacy_port)) return -1;
  } else if (strncmp(arg, "--udp-host=", 11) == 0) {
    (void)snprintf(cfg->udp_log_host, sizeof(cfg->udp_log_host), "%s",
                   arg + 11);
  } else if (strncmp(arg, "--udp-port=", 11) == 0) {
    if (!parse_u16(arg + 11, &cfg->udp_log_port)) return -1;
  } else if (strncmp(arg, "--data-root=", 12) == 0) {
    (void)snprintf(cfg->data_root, sizeof(cfg->data_root), "%s", arg + 12);
  } else if (strncmp(arg, "--max-read=", 11) == 0) {
    if (!parse_u32(arg + 11, &cfg->max_read_bytes)) return -1;
  } else if (strncmp(arg, "--max-packet=", 13) == 0) {
    if (!parse_u32(arg + 13, &cfg->max_packet_bytes)) return -1;
  } else if (strncmp(arg, "--max-scan-results=", 19) == 0) {
    if (!parse_u32(arg + 19, &cfg->max_scan_results)) return -1;
  } else if (strncmp(arg, "--max-connections=", 18) == 0) {
    if (!parse_u32(arg + 18, &cfg->max_connections)) return -1;
  } else if (strncmp(arg, "--idle-timeout=", 15) == 0) {
    if (!parse_u32(arg + 15, &cfg->idle_timeout_ms)) return -1;
  } else if (strcmp(arg, "--replace-existing") == 0) {
    cfg->replace_existing = true;
  } else if (strcmp(arg, "--no-replace-existing") == 0) {
    cfg->replace_existing = false;
  } else if (strcmp(arg, "--legacy-compat") == 0) {
    cfg->enable_legacy_compat = true;
  } else if (strcmp(arg, "--no-legacy-compat") == 0) {
    cfg->enable_legacy_compat = false;
  } else if (strcmp(arg, "--no-udp-log") == 0) {
    cfg->enable_udp_log = false;
  } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
    return 1;
  } else {
    return -1;
  }
  return 0;
}

static int run_default(int argc, char **argv) {
  memdbg_config_t cfg;
  memdbg_config_defaults(&cfg);
  for (int i = 1; i < argc; ++i) {
    int rc = apply_arg(&cfg, argv[i]);
    if (rc > 0) {
      print_usage(argv[0]);
      return 0;
    }
    if (rc < 0) {
      fprintf(stderr, "Invalid argument: %s\n", argv[i]);
      print_usage(argv[0]);
      return 2;
    }
  }
  return memdbg_daemon_run(&cfg);
}

int memdbg_main(void) { return run_default(0, NULL); }

#ifndef MEMDBG_NO_MAIN
int main(int argc, char **argv) { return run_default(argc, argv); }
#endif
