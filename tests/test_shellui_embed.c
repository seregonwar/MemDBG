/*
 * MemDBG - ShellUI SPRX embedding unit tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Verifies that shellui_embed_extract() writes the SPRX to disk with valid
 * ELF content and the correct size.  The embedded data is accessed only
 * through the extraction function (compiled with -DSHELLUI_EMBED_HOST_TEST),
 * avoiding duplicate-symbol issues from the xxd-generated header.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Bring in the real extraction function (compiled with -DSHELLUI_EMBED_HOST_TEST) */
extern int shellui_embed_extract(void);

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

#define OUTPUT_PATH "/tmp/memdbg_embed_test/memdbg_shellui.sprx"
#define OUTPUT_DIR  "/tmp/memdbg_embed_test"

/* Helper: remove test output from a previous run */
static void rm_test_output(void) {
  unlink(OUTPUT_PATH);
  rmdir(OUTPUT_DIR);
}

/* Helper: verify a buffer starts with ELF magic */
static int is_elf(const unsigned char *buf, size_t len) {
  return len >= 4 &&
         buf[0] == 0x7F && buf[1] == 'E' &&
         buf[2] == 'L'  && buf[3] == 'F';
}

static void test_extract_creates_file(void) {
  printf("\n--- shellui_embed_extract() creates file ---\n");

  /* Clean up from any previous run */
  rm_test_output();

  /* Extract should succeed */
  int ret = shellui_embed_extract();
  TEST("extract returns 0 (success)", ret == 0);

  if (ret != 0) {
    /* Can't continue meaningfully if extraction failed */
    rm_test_output();
    return;
  }

  /* Verify file exists */
  struct stat st;
  int stat_ret = stat(OUTPUT_PATH, &st);
  TEST("output file exists after extract", stat_ret == 0);

  if (stat_ret != 0) {
    rm_test_output();
    return;
  }

  /* Verify reasonable size: must be >4KB (ELF header + code), <8MB */
  TEST("output file size is reasonable (>4KB, <8MB)",
       st.st_size > 4096 && st.st_size < 8 * 1024 * 1024);

  /* Verify file has executable permission */
  TEST("output file is executable (mode & 0111)",
       (st.st_mode & 0111) != 0);

  /* Read back the file and verify content */
  FILE *f = fopen(OUTPUT_PATH, "rb");
  TEST("can open output file for reading", f != NULL);

  if (f == NULL) {
    rm_test_output();
    return;
  }

  /* Read first 256 bytes for content verification */
  unsigned char first_bytes[256];
  size_t nr = fread(first_bytes, 1, sizeof(first_bytes), f);

  /* Read the rest to get total size */
  size_t total = nr;
  unsigned char discard[4096];
  while (!feof(f)) {
    size_t chunk = fread(discard, 1, sizeof(discard), f);
    total += chunk;
  }
  fclose(f);

  TEST("can read from output file", nr > 0);
  TEST("output file starts with ELF magic (\\x7FELF)",
       is_elf(first_bytes, nr));
  TEST("output file is 64-bit ELF (EI_CLASS = 2)",
       nr >= 5 && first_bytes[4] == 2);
  TEST("output file size matches stat size",
       total == (size_t)st.st_size);

  /* Verify file is not empty */
  TEST("output file is not empty", st.st_size > 0);

  /* Verify first 4 bytes are exactly the ELF magic */
  TEST("first 4 bytes are ELF magic",
       nr >= 4 &&
       first_bytes[0] == 0x7F &&
       first_bytes[1] == 'E' &&
       first_bytes[2] == 'L' &&
       first_bytes[3] == 'F');

  /* Verify it's a shared object (ET_DYN = 3 at offset 16 in little-endian) */
  TEST("ELF type is shared object (ET_DYN)",
       nr >= 18 && first_bytes[16] == 0x03 && first_bytes[17] == 0x00);
}

static void test_extract_idempotent(void) {
  printf("\n--- shellui_embed_extract() idempotent ---\n");

  /* First call already done by test_extract_creates_file.
   * Second call should also succeed (file exists with correct size). */
  struct stat st_before;
  stat(OUTPUT_PATH, &st_before);

  int ret = shellui_embed_extract();
  TEST("second extract also returns 0 (idempotent)", ret == 0);

  /* Verify size unchanged */
  struct stat st_after;
  stat(OUTPUT_PATH, &st_after);
  TEST("file size unchanged after second extract",
       st_before.st_size == st_after.st_size);

  /* Clean up */
  rm_test_output();
}

int main(void) {
  printf("=== MemDBG ShellUI SPRX Embedding Tests ===\n");

  test_extract_creates_file();
  test_extract_idempotent();

  printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  printf("Total:  %d\n", total);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}
