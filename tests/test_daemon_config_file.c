/*
 * MemDBG - Unit tests for daemon.conf load/save/parse.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/daemon/daemon_config_file.h"
#include "memdbg/pal/pal_fileio.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(path) _mkdir(path)
#else
#include <sys/stat.h>
#define MKDIR(path) mkdir((path), 0700)
#endif

/* Stubs so this test links without the full daemon. */
void memdbg_config_defaults(memdbg_config_t *cfg) {
  if (cfg == NULL) return;
  memset(cfg, 0, sizeof(*cfg));
  (void)snprintf(cfg->data_root, sizeof(cfg->data_root), "%s",
                 MEMDBG_DEFAULT_DATA_ROOT);
  cfg->debug_port = MEMDBG_DEFAULT_DEBUG_PORT;
  cfg->legacy_port = MEMDBG_DEFAULT_LEGACY_PORT;
  cfg->enable_legacy_compat = true;
}

void memdbg_log_write(memdbg_log_level_t level, const char *fmt, ...) {
  (void)level;
  (void)fmt;
}

int pal_mkdir_p(const char *path, mode_t mode) {
  (void)mode;
  if (path == NULL || path[0] == '\0') return -1;
  if (MKDIR(path) == 0) return 0;
  return errno == EEXIST ? 0 : -1;
}

static int failures;

#define CHECK(name, expr)                                                       \
  do {                                                                          \
    if (!(expr)) {                                                              \
      fprintf(stderr, "FAIL: %s\n", name);                                      \
      failures++;                                                               \
    }                                                                           \
  } while (0)

int main(void) {
  memdbg_config_t cfg;
  memdbg_config_defaults(&cfg);

  CHECK("parse empty", memdbg_daemon_config_parse_line("", &cfg) == 0);
  CHECK("parse comment", memdbg_daemon_config_parse_line("# hi", &cfg) == 0);
  CHECK("parse legacy off",
        memdbg_daemon_config_parse_line("legacy_compat=0", &cfg) == 0 &&
            !cfg.enable_legacy_compat);
  CHECK("parse legacy on",
        memdbg_daemon_config_parse_line("legacy_compat=1", &cfg) == 0 &&
            cfg.enable_legacy_compat);
  CHECK("parse legacy false",
        memdbg_daemon_config_parse_line(" legacy_compat = false ", &cfg) == 0 &&
            !cfg.enable_legacy_compat);
  CHECK("parse unknown key",
        memdbg_daemon_config_parse_line("future_knob=1", &cfg) == 0);
  CHECK("parse bad value",
        memdbg_daemon_config_parse_line("legacy_compat=maybe", &cfg) != 0);

  char path[MEMDBG_PATH_MAX];
  CHECK("path build",
        memdbg_daemon_config_path("/tmp/memdbg-conf-test", path, sizeof(path)) ==
            0);
  CHECK("path suffix", strstr(path, "daemon.conf") != NULL);

  const char *root = "build/test-daemon-conf";
  (void)MKDIR("build");
  (void)MKDIR(root);

  memdbg_config_t round;
  memdbg_config_defaults(&round);
  (void)snprintf(round.data_root, sizeof(round.data_root), "%s", root);
  round.enable_legacy_compat = false;
  CHECK("save off", memdbg_daemon_config_save(root, &round) == 0);

  memdbg_config_t loaded;
  memdbg_config_defaults(&loaded);
  loaded.enable_legacy_compat = true; /* should be overwritten by file */
  CHECK("load off", memdbg_daemon_config_load(root, &loaded) == 0 &&
                        !loaded.enable_legacy_compat);

  round.enable_legacy_compat = true;
  CHECK("save on", memdbg_daemon_config_save(root, &round) == 0);
  loaded.enable_legacy_compat = false;
  CHECK("load on", memdbg_daemon_config_load(root, &loaded) == 0 &&
                       loaded.enable_legacy_compat);

  memdbg_daemon_config_publish(&round);
  CHECK("runtime legacy", memdbg_daemon_config_legacy_enabled());
  memdbg_daemon_config_set_legacy_enabled(false);
  CHECK("runtime set off", !memdbg_daemon_config_legacy_enabled());

  memdbg_config_t snap;
  memdbg_daemon_config_snapshot(&snap);
  CHECK("snapshot root", strcmp(snap.data_root, root) == 0);
  CHECK("snapshot legacy", !snap.enable_legacy_compat);

  if (failures == 0) {
    printf("All daemon.conf tests passed\n");
    return 0;
  }
  fprintf(stderr, "%d test(s) failed\n", failures);
  return 1;
}
