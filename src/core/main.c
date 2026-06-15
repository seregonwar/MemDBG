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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void apply_arg(memdbg_config_t *cfg, const char *arg) {
  if (cfg == NULL || arg == NULL) {
    return;
  }
  if (strncmp(arg, "--bind=", 7) == 0) {
    (void)snprintf(cfg->bind_host, sizeof(cfg->bind_host), "%s", arg + 7);
  } else if (strncmp(arg, "--debug-port=", 13) == 0) {
    cfg->debug_port = (uint16_t)strtoul(arg + 13, NULL, 10);
  } else if (strncmp(arg, "--udp-host=", 11) == 0) {
    (void)snprintf(cfg->udp_log_host, sizeof(cfg->udp_log_host), "%s",
                   arg + 11);
  } else if (strncmp(arg, "--udp-port=", 11) == 0) {
    cfg->udp_log_port = (uint16_t)strtoul(arg + 11, NULL, 10);
  } else if (strncmp(arg, "--data-root=", 12) == 0) {
    (void)snprintf(cfg->data_root, sizeof(cfg->data_root), "%s", arg + 12);
  } else if (strcmp(arg, "--no-udp-log") == 0) {
    cfg->enable_udp_log = false;
  }
}

static int run_default(int argc, char **argv) {
  memdbg_config_t cfg;
  memdbg_config_defaults(&cfg);
  for (int i = 1; i < argc; ++i) {
    apply_arg(&cfg, argv[i]);
  }
  return memdbg_daemon_run(&cfg);
}

int memdbg_main(void) { return run_default(0, NULL); }

#ifndef MEMDBG_NO_MAIN
int main(int argc, char **argv) { return run_default(argc, argv); }
#endif
