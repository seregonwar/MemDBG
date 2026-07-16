/*
 * MemDBG - Process map metadata regression tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/pal/pal_process.h"

#include <stdio.h>
#include <string.h>

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s\n", name);                                            \
    }                                                                          \
  } while (0)

int main(void) {
  char name[64];
  const uint32_t flags =
      pal_map_pack_flags(0x45U, MEMDBG_MAP_TYPE_DEFAULT);

  printf("=== Process Map Metadata Tests ===\n");
  TEST("native flags are preserved",
       (flags & MEMDBG_MAP_FLAG_NATIVE_MASK) == 0x45U);
  TEST("map type is packed",
       ((flags & MEMDBG_MAP_FLAG_TYPE_MASK) >>
        MEMDBG_MAP_FLAG_TYPE_SHIFT) == MEMDBG_MAP_TYPE_DEFAULT);

  pal_map_format_name(name, sizeof(name), "/app0/eboot.bin",
                      MEMDBG_MAP_TYPE_VNODE);
  TEST("kernel path remains the map name",
       strcmp(name, "/app0/eboot.bin") == 0);

  pal_map_format_name(name, sizeof(name), "", MEMDBG_MAP_TYPE_DEFAULT);
  TEST("unnamed map receives deterministic truthful fallback",
       strcmp(name, "[default]") == 0);
  TEST("unknown native type stays truthful",
       strcmp(pal_map_type_name(99U), "unknown") == 0);

  printf("\nPassed: %d\nFailed: %d\n", g_passed, g_failed);
  return g_failed == 0 ? 0 : 1;
}
