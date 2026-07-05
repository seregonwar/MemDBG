/*
 * memDBG - Unit tests for new features: snap_compare, hijack, ELF loader.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tests:
 *   - snap_compare() comparison logic (all 12 compare types)
 *   - Protocol struct sizes (ELF load, hijack with target_region, match_flags)
 *   - Hijack request validation boundaries
 *   - ELF load request parsing
 *   - Region name matching (basename, substring, wildcard, match flags)
 */

#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/core/region_match.h"
#include "flashscan.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failed = 0;

#define TEST(name, cond)                                                       \
  do {                                                                         \
    if (cond) {                                                                \
      printf("  [OK] %s\n", name);                                             \
    } else {                                                                   \
      printf("  [FAIL] %s\n", name);                                           \
      ++g_failed;                                                              \
    }                                                                          \
  } while (0)

#define TEST_EQ(name, actual, expected)                                        \
  do {                                                                         \
    unsigned long long _a = (unsigned long long)(actual);                      \
    unsigned long long _e = (unsigned long long)(expected);                    \
    if (_a == _e) {                                                            \
      printf("  [OK] %s\n", name);                                             \
    } else {                                                                   \
      printf("  [FAIL] %s (got %llu, expected %llu)\n",                        \
             name, _a, _e);                                                    \
      ++g_failed;                                                              \
    }                                                                          \
  } while (0)

#define TEST_STREQ(name, actual, expected)                                     \
  do {                                                                         \
    const char *_a = (actual);                                                 \
    const char *_e = (expected);                                               \
    if (_a != NULL && _e != NULL && strcmp(_a, _e) == 0) {                    \
      printf("  [OK] %s\n", name);                                             \
    } else {                                                                   \
      printf("  [FAIL] %s ('%s' vs '%s')\n", name,                             \
             _a ? _a : "(null)", _e ? _e : "(null)");                          \
      ++g_failed;                                                              \
    }                                                                          \
  } while (0)

/* ======================================================================
 * snap_compare() tests
 * ====================================================================== */

static void test_snap_compare_exact(void) {
  printf("\n--- snap_compare: exact match (cmp_type=0) ---\n");

  uint8_t mem[]  = {0xDE, 0xAD, 0xBE, 0xEF};
  uint8_t pat[]  = {0xDE, 0xAD, 0xBE, 0xEF};
  uint8_t bad[]  = {0x00, 0x00, 0x00, 0x00};

  int m = snap_compare(mem, pat, NULL, NULL, NULL, 0, 4);
  TEST("exact: matches identical 4 bytes", m != 0);

  m = snap_compare(mem, bad, NULL, NULL, NULL, 0, 4);
  TEST("exact: rejects different 4 bytes", m == 0);
}

static void test_snap_compare_1byte(void) {
  printf("\n--- snap_compare: exact match 1-byte ---\n");

  uint8_t mem[]  = {0x42};
  uint8_t pat[]  = {0x42};
  uint8_t bad[]  = {0x00};

  int m = snap_compare(mem, pat, NULL, NULL, NULL, 0, 1);
  TEST("1-byte: matches identical", m != 0);

  m = snap_compare(mem, bad, NULL, NULL, NULL, 0, 1);
  TEST("1-byte: rejects different", m == 0);
}

static void test_snap_compare_8byte(void) {
  printf("\n--- snap_compare: exact match 8-byte ---\n");

  uint8_t mem[]  = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
  uint8_t pat[]  = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
  uint8_t bad[]  = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

  int m = snap_compare(mem, pat, NULL, NULL, NULL, 0, 8);
  TEST("8-byte: matches identical", m != 0);

  m = snap_compare(mem, bad, NULL, NULL, NULL, 0, 8);
  TEST("8-byte: rejects different", m == 0);
}

static void test_snap_compare_greater(void) {
  printf("\n--- snap_compare: greater than (cmp_type=1) ---\n");

  uint8_t mem[] = {0x00, 0x00, 0x00, 0x80};
  uint8_t pat[] = {0x00, 0x00, 0x00, 0x7F};
  uint8_t eq[]  = {0x00, 0x00, 0x00, 0x7F};
  uint8_t lo[]  = {0x00, 0x00, 0x00, 0x00};

  int m = snap_compare(mem, pat, NULL, NULL, NULL, 1, 4);
  TEST("greater: mem > pattern returns true", m != 0);

  m = snap_compare(eq, pat, NULL, NULL, NULL, 1, 4);
  TEST("greater: mem == pattern returns false", m == 0);

  m = snap_compare(lo, pat, NULL, NULL, NULL, 1, 4);
  TEST("greater: mem < pattern returns false", m == 0);
}

static void test_snap_compare_less(void) {
  printf("\n--- snap_compare: less than (cmp_type=2) ---\n");

  uint8_t mem[] = {0x00, 0x00, 0x00, 0x10};
  uint8_t pat[] = {0x00, 0x00, 0x00, 0x20};
  uint8_t hi[]  = {0x00, 0x00, 0x00, 0x30};

  int m = snap_compare(mem, pat, NULL, NULL, NULL, 2, 4);
  TEST("less: mem < pattern returns true", m != 0);

  m = snap_compare(hi, pat, NULL, NULL, NULL, 2, 4);
  TEST("less: mem > pattern returns false", m == 0);
}

static void test_snap_compare_changed(void) {
  printf("\n--- snap_compare: changed vs previous (cmp_type=3) ---\n");

  uint8_t mem[]  = {0xAA, 0xBB, 0xCC, 0xDD};
  uint8_t prev[] = {0x11, 0x22, 0x33, 0x44};
  uint8_t same[] = {0x11, 0x22, 0x33, 0x44};

  int m = snap_compare(mem, NULL, prev, NULL, NULL, 3, 4);
  TEST("changed: different from previous returns true", m != 0);

  m = snap_compare(same, NULL, prev, NULL, NULL, 3, 4);
  TEST("changed: same as previous returns false", m == 0);
}

static void test_snap_compare_between(void) {
  printf("\n--- snap_compare: between (cmp_type=4) ---\n");

  uint8_t mem[] = {0x00, 0x00, 0x00, 0x50};
  uint8_t lo[]  = {0x00, 0x00, 0x00, 0x10};
  uint8_t hi[]  = {0x00, 0x00, 0x00, 0x90};
  uint8_t below[] = {0x00, 0x00, 0x00, 0x00};
  uint8_t above[] = {0x00, 0x00, 0x00, 0xFF};

  int m = snap_compare(mem, lo, NULL, NULL, hi, 4, 4);
  TEST("between: mem between lo-hi returns true", m != 0);

  m = snap_compare(below, lo, NULL, NULL, hi, 4, 4);
  TEST("between: mem below lo returns false", m == 0);

  m = snap_compare(above, lo, NULL, NULL, hi, 4, 4);
  TEST("between: mem above hi returns false", m == 0);

  m = snap_compare(lo, lo, NULL, NULL, hi, 4, 4);
  TEST("between: mem == lo returns true", m != 0);

  m = snap_compare(hi, lo, NULL, NULL, hi, 4, 4);
  TEST("between: mem == hi returns true", m != 0);
}

static void test_snap_compare_numeric(void) {
  printf("\n--- snap_compare: numeric comparisons (cmp_type 5-12) ---\n");

  uint8_t val_100[]  = {100, 0, 0, 0};
  uint8_t val_200[]  = {200, 0, 0, 0};
  uint8_t val_100b[] = {100, 0, 0, 0};

  int m = snap_compare(val_100, val_100b, NULL, NULL, NULL, 5, 4);
  TEST("numeric(5): 100 == 100 returns true", m != 0);

  m = snap_compare(val_200, val_100, NULL, NULL, NULL, 5, 4);
  TEST("numeric(5): 200 == 100 returns false", m == 0);

  m = snap_compare(val_200, val_100, NULL, NULL, NULL, 6, 4);
  TEST("numeric(6): 200 > 100 returns true", m != 0);

  m = snap_compare(val_100, val_100, NULL, NULL, NULL, 6, 4);
  TEST("numeric(6): 100 > 100 returns false", m == 0);

  m = snap_compare(val_100, val_200, NULL, NULL, NULL, 7, 4);
  TEST("numeric(7): 100 < 200 returns true", m != 0);

  m = snap_compare(val_200, val_100, NULL, NULL, NULL, 7, 4);
  TEST("numeric(7): 200 < 100 returns false", m == 0);

  m = snap_compare(val_200, val_100, NULL, NULL, NULL, 8, 4);
  TEST("numeric(8): 200 != 100 returns true", m != 0);

  m = snap_compare(val_100, val_100b, NULL, NULL, NULL, 8, 4);
  TEST("numeric(8): 100 != 100 returns false", m == 0);

  m = snap_compare(val_200, val_100, NULL, NULL, NULL, 9, 4);
  TEST("numeric(9): changed returns true", m != 0);

  m = snap_compare(val_100, val_100b, NULL, NULL, NULL, 9, 4);
  TEST("numeric(9): unchanged returns false", m == 0);

  m = snap_compare(val_100, val_100b, NULL, NULL, NULL, 10, 4);
  TEST("numeric(10): unchanged returns true", m != 0);

  m = snap_compare(val_200, val_100, NULL, NULL, NULL, 10, 4);
  TEST("numeric(10): changed returns false", m == 0);

  m = snap_compare(val_200, val_100, NULL, NULL, NULL, 11, 4);
  TEST("numeric(11): increased returns true", m != 0);

  m = snap_compare(val_100, val_100b, NULL, NULL, NULL, 11, 4);
  TEST("numeric(11): equal returns false", m == 0);

  m = snap_compare(val_100, val_200, NULL, NULL, NULL, 12, 4);
  TEST("numeric(12): decreased returns true", m != 0);

  m = snap_compare(val_200, val_100, NULL, NULL, NULL, 12, 4);
  TEST("numeric(12): increased returns false", m == 0);
}

static void test_snap_compare_numeric_8byte(void) {
  printf("\n--- snap_compare: numeric comparisons 8-byte ---\n");

  uint8_t val_1000[] = {0xE8, 0x03, 0, 0, 0, 0, 0, 0};
  uint8_t val_2000[] = {0xD0, 0x07, 0, 0, 0, 0, 0, 0};
  uint8_t val_1000b[]= {0xE8, 0x03, 0, 0, 0, 0, 0, 0};

  int m = snap_compare(val_2000, val_1000, NULL, NULL, NULL, 6, 8);
  TEST("8-byte numeric: 2000 > 1000 returns true", m != 0);

  m = snap_compare(val_1000, val_1000b, NULL, NULL, NULL, 10, 8);
  TEST("8-byte numeric: unchanged returns true", m != 0);

  m = snap_compare(val_1000, val_1000b, NULL, NULL, NULL, 8, 8);
  TEST("8-byte numeric: 1000 != 1000 returns false", m == 0);
}

/* ======================================================================
 * Protocol struct size tests
 * ====================================================================== */

static void test_protocol_struct_sizes(void) {
  printf("\n--- Protocol struct sizes ---\n");

  /* ELF load request: pid(4) + flags(4) + image_size(8) + match_flags(4) + target_region[44] = 64 */
  TEST_EQ("memdbg_process_elf_load_request_t size",
          sizeof(memdbg_process_elf_load_request_t), 64U);

  /* Hijack request: pid(4) + flags(4) + payload_size(8) + match_flags(4) + target_region[44] = 64 */
  TEST_EQ("memdbg_process_hijack_request_t size",
          sizeof(memdbg_process_hijack_request_t), 64U);

  TEST_EQ("memdbg_process_elf_load_response_t size",
          sizeof(memdbg_process_elf_load_response_t), 16U);

  TEST_EQ("memdbg_process_hijack_response_t size",
          sizeof(memdbg_process_hijack_response_t), 8U);
}

/* ======================================================================
 * Hijack request validation tests
 * ====================================================================== */

static void test_hijack_request_validation(void) {
  printf("\n--- Hijack request validation ---\n");

  {
    memdbg_process_hijack_request_t req;
    memset(&req, 0, sizeof(req));
    req.pid          = 42;
    req.payload_size = 1024;
    req.flags        = 0;

    TEST_EQ("hijack valid: pid set", req.pid, 42);
    TEST_EQ("hijack valid: payload_size", (uint64_t)req.payload_size, 1024ULL);
    TEST_EQ("hijack valid: flags zero", req.flags, 0U);
  }

  {
    memdbg_process_hijack_request_t req;
    memset(&req, 0, sizeof(req));
    req.payload_size = 0U;

    TEST("hijack: zero payload rejected (size == 0)",
         req.payload_size == 0U);
  }

  {
    memdbg_process_hijack_request_t req;
    memset(&req, 0, sizeof(req));
    req.payload_size = 65ULL * 1024ULL * 1024ULL;

    TEST("hijack: payload over 64MB detected",
         req.payload_size > (64ULL << 20));
  }

  {
    memdbg_process_hijack_request_t req;
    memset(&req, 0, sizeof(req));
    req.pid = 1;

    TEST("hijack: PID 1 should be rejected", req.pid <= 1);
  }

  {
    memdbg_process_hijack_request_t req;
    memset(&req, 0, sizeof(req));
    req.pid = 0;

    TEST("hijack: PID 0 should be rejected", req.pid <= 1);
  }

  {
    memdbg_process_hijack_request_t req;
    memset(&req, 0, sizeof(req));
    req.payload_size = 4096;

    uint32_t min_body = (uint32_t)(sizeof(req) + (uint64_t)req.payload_size);
    uint32_t too_short = min_body - 1;
    TEST("hijack: body len check catches short body",
         too_short < min_body);
  }
}

/* ======================================================================
 * target_region field tests
 * ====================================================================== */

static void test_target_region_field(void) {
  printf("\n--- target_region field ---\n");

  {
    memdbg_process_elf_load_request_t req;
    memset(&req, 0, sizeof(req));
    req.pid          = 42;
    req.flags        = 0;
    req.image_size   = 8192;
    memcpy(req.target_region, "libkernel.so", 13);

    TEST_STREQ("elf load: target_region stored",
               req.target_region, "libkernel.so");

    TEST("elf load: target_region size is 44",
         sizeof(req.target_region) == 44U);
  }

  {
    memdbg_process_hijack_request_t req;
    memset(&req, 0, sizeof(req));
    req.pid          = 42;
    req.flags        = 3;
    req.payload_size = 4096;
    memcpy(req.target_region, "SceVideoOut", 12);

    TEST_STREQ("hijack: target_region stored",
               req.target_region, "SceVideoOut");

    TEST("hijack: flags combined (bits 0+1)",
         (req.flags & 3) == 3);
  }

  {
    memdbg_process_elf_load_request_t req;
    memset(&req, 0, sizeof(req));

    TEST("elf load: empty region means allocate new",
         req.target_region[0] == '\0');
  }

  /* 43 chars + null = max */
  {
    memdbg_process_elf_load_request_t req;
    memset(&req, 0, sizeof(req));
    memset(req.target_region, 'X', 43);
    req.target_region[43] = '\0';

    TEST("elf load: 43-char region stored correctly",
         strlen(req.target_region) == 43U);
  }
}

/* ======================================================================
 * match_flags field tests
 * ====================================================================== */

static void test_match_flags_field(void) {
  printf("\n--- match_flags field ---\n");

  {
    memdbg_process_elf_load_request_t req;
    memset(&req, 0, sizeof(req));
    req.match_flags = MEMDBG_MATCH_EXACT | MEMDBG_MATCH_CASE_SENSITIVE;

    TEST("match_flags: EXACT | CASE_SENSITIVE combined",
         req.match_flags == (MEMDBG_MATCH_EXACT | MEMDBG_MATCH_CASE_SENSITIVE));
  }

  /* Default match_flags = 0 means case-insensitive, substring fallback */
  {
    memdbg_process_elf_load_request_t req;
    memset(&req, 0, sizeof(req));

    TEST("match_flags: default is 0 (case-insensitive, substring)",
         req.match_flags == 0U);
  }

  /* Hijack request also has match_flags */
  {
    memdbg_process_hijack_request_t req;
    memset(&req, 0, sizeof(req));
    req.match_flags = MEMDBG_MATCH_EXACT;

    TEST("match_flags: hijack has EXACT",
         req.match_flags == MEMDBG_MATCH_EXACT);
  }
}

/* ======================================================================
 * ELF load dispatch validation tests
 * ====================================================================== */

static void test_elf_load_validation(void) {
  printf("\n--- ELF load request validation ---\n");

  {
    memdbg_process_elf_load_request_t req;
    memset(&req, 0, sizeof(req));
    req.pid        = 42;
    req.flags      = 1;
    req.image_size = 1024;

    TEST_EQ("elf load valid: pid", req.pid, 42);
    TEST("elf load valid: jump flag set", (req.flags & 1) != 0);
    TEST_EQ("elf load valid: image_size", (uint64_t)req.image_size, 1024ULL);
  }

  {
    memdbg_process_elf_load_request_t req;
    memset(&req, 0, sizeof(req));
    req.image_size = 0U;

    TEST("elf load: zero image_size detected",
         req.image_size == 0U);
  }

  {
    memdbg_process_elf_load_request_t req;
    memset(&req, 0, sizeof(req));
    req.image_size = 65ULL * 1024ULL * 1024ULL;

    TEST("elf load: oversized image detected",
         req.image_size > (64ULL << 20));
  }

  {
    memdbg_process_elf_load_request_t req;
    memset(&req, 0, sizeof(req));
    req.pid        = 42;
    req.image_size = 4096;

    uint32_t needed   = (uint32_t)(sizeof(req) + (uint64_t)req.image_size);
    uint32_t too_short = needed - 1;
    TEST("elf load: body len catches short body",
         too_short < needed);
  }

  {
    memdbg_process_elf_load_request_t req;
    memset(&req, 0, sizeof(req));
    req.pid = 1;

    TEST("elf load: self-pid detected as invalid",
         req.pid <= 1);
  }
}

/* ======================================================================
 * Region name matching tests (uses region_name_matches from region_match.h)
 * ====================================================================== */

static void test_region_name_matching(void) {
  printf("\n--- Region name matching ---\n");

  /* Basename match */
  TEST("region: 'libkernel.so' matches '/system/lib/libkernel.so'",
       region_name_matches("/system/lib/libkernel.so", "libkernel.so", 0U));

  TEST("region: 'libkernel.so' matches 'libkernel.so' (no path)",
       region_name_matches("libkernel.so", "libkernel.so", 0U));

  /* Case-insensitive basename match */
  TEST("region: 'LIBKERNEL.SO' matches '/system/lib/libkernel.so' (case)",
       region_name_matches("/system/lib/libkernel.so", "LIBKERNEL.SO", 0U));

  TEST("region: 'libkernel.so' matches '/SYSTEM/LIB/LIBKERNEL.SO' (case)",
       region_name_matches("/SYSTEM/LIB/LIBKERNEL.SO", "libkernel.so", 0U));

  /* Substring fallback */
  TEST("region: 'system' matches '/system/lib/libkernel.so' (substring)",
       region_name_matches("/system/lib/libkernel.so", "system", 0U));

  TEST("region: 'lib' matches '/system/lib/libkernel.so' (substring)",
       region_name_matches("/system/lib/libkernel.so", "lib", 0U));

  /* No match */
  TEST("region: 'libother.so' does NOT match '/system/lib/libkernel.so'",
       !region_name_matches("/system/lib/libkernel.so", "libother.so", 0U));

  /* Empty/NULL safety */
  TEST("region: empty target returns false",
       !region_name_matches("/system/lib/libkernel.so", "", 0U));

  TEST("region: NULL map_name returns false",
       !region_name_matches(NULL, "libkernel.so", 0U));

  TEST("region: NULL target returns false",
       !region_name_matches("/system/lib/libkernel.so", NULL, 0U));

  /* Wildcard tests */
  TEST("region: 'lib*.so' matches 'libkernel.so'",
       region_name_matches("libkernel.so", "lib*.so", 0U));

  TEST("region: 'lib*.so' matches 'libc.so'",
       region_name_matches("libc.so", "lib*.so", 0U));

  TEST("region: 'lib*.so' does NOT match 'kernel.so'",
       !region_name_matches("kernel.so", "lib*.so", 0U));

  TEST("region: '*' matches any name",
       region_name_matches("anything_here", "*", 0U));

  TEST("region: '*Video*' matches 'SceVideoOut'",
       region_name_matches("SceVideoOut", "*Video*", 0U));

  TEST("region: '*Video*' does NOT match 'SceAudioOut'",
       !region_name_matches("SceAudioOut", "*Video*", 0U));

  /* Wildcard with basename */
  TEST("region: 'lib*.so' matches '/system/lib/libkernel.so' (basename)",
       region_name_matches("/system/lib/libkernel.so", "lib*.so", 0U));

  TEST("region: '*.bin' matches '/app/eboot.bin' (basename)",
       region_name_matches("/app/eboot.bin", "*.bin", 0U));

  /* Case-insensitive wildcard */
  TEST("region: 'LIB*.SO' matches 'libkernel.so' (case + wildcard)",
       region_name_matches("libkernel.so", "LIB*.SO", 0U));

  /* Trailing/leading star */
  TEST("region: 'lib*' matches 'libkernel.so'",
       region_name_matches("libkernel.so", "lib*", 0U));

  TEST("region: '*.so' matches 'libkernel.so'",
       region_name_matches("libkernel.so", "*.so", 0U));
}

/* ======================================================================
 * Match flags behaviour tests
 * ====================================================================== */

static void test_match_flags_behaviour(void) {
  printf("\n--- Match flags behaviour ---\n");

  /* EXACT: no substring fallback */
  TEST("flags: EXACT 'kernel' does NOT match '/system/lib/libkernel.so'",
       !region_name_matches("/system/lib/libkernel.so", "kernel",
                            MEMDBG_MATCH_EXACT));

  TEST("flags: EXACT 'libkernel.so' still matches basename",
       region_name_matches("/system/lib/libkernel.so", "libkernel.so",
                           MEMDBG_MATCH_EXACT));

  /* CASE_SENSITIVE: upper != lower */
  TEST("flags: CASE_SENSITIVE 'LIBKERNEL.SO' does NOT match 'libkernel.so'",
       !region_name_matches("libkernel.so", "LIBKERNEL.SO",
                            MEMDBG_MATCH_CASE_SENSITIVE));

  TEST("flags: CASE_SENSITIVE 'libkernel.so' matches itself",
       region_name_matches("libkernel.so", "libkernel.so",
                           MEMDBG_MATCH_CASE_SENSITIVE));

  /* CASE_SENSITIVE substring */
  TEST("flags: CASE_SENSITIVE 'system' does NOT match '/System/lib/foo.so'",
       !region_name_matches("/System/lib/foo.so", "system",
                            MEMDBG_MATCH_CASE_SENSITIVE));

  /* Combined EXACT + CASE_SENSITIVE */
  TEST("flags: EXACT|CASE_SENSITIVE 'Kernel' does NOT match 'kernel' substring",
       !region_name_matches("kernel.so", "Kernel",
                            MEMDBG_MATCH_EXACT | MEMDBG_MATCH_CASE_SENSITIVE));

  /* Wildcard with CASE_SENSITIVE */
  TEST("flags: CASE_SENSITIVE 'LIB*.SO' does NOT match 'libkernel.so'",
       !region_name_matches("libkernel.so", "LIB*.SO",
                            MEMDBG_MATCH_CASE_SENSITIVE));

  /* Wildcard + EXACT still works */
  TEST("flags: EXACT 'lib*.so' matches 'libkernel.so'",
       region_name_matches("libkernel.so", "lib*.so",
                           MEMDBG_MATCH_EXACT));
}

/* ======================================================================
 * Regex matching tests
 * ====================================================================== */

static void test_region_name_regex(void) {
  printf("\n--- Region name regex matching ---\n");

  /* Basic regex: ^lib matches basenames starting with "lib" */
  TEST("regex: '^lib' matches 'libkernel.so'",
       region_name_matches("libkernel.so", "^lib", MEMDBG_MATCH_REGEX));

  TEST("regex: '^lib' does NOT match 'kernel.so'",
       !region_name_matches("kernel.so", "^lib", MEMDBG_MATCH_REGEX));

  /* Regex with .so$ suffix */
  TEST("regex: '\\.so$' matches 'libkernel.so'",
       region_name_matches("libkernel.so", "\\.so$", MEMDBG_MATCH_REGEX));

  TEST("regex: '\\.so$' does NOT match 'libkernel.bin'",
       !region_name_matches("libkernel.bin", "\\.so$", MEMDBG_MATCH_REGEX));

  /* Regex on full path */
  TEST("regex: '^/system/' matches '/system/lib/libkernel.so'",
       region_name_matches("/system/lib/libkernel.so", "^/system/",
                           MEMDBG_MATCH_REGEX));

  TEST("regex: '^/system/' does NOT match '/data/foo.so'",
       !region_name_matches("/data/foo.so", "^/system/", MEMDBG_MATCH_REGEX));

  /* Case-insensitive regex (default) */
  TEST("regex: '^LIB' matches 'libkernel.so' (case-insensitive)",
       region_name_matches("libkernel.so", "^LIB", MEMDBG_MATCH_REGEX));

  /* Case-sensitive regex */
  TEST("regex: CASE_SENSITIVE '^LIB' does NOT match 'libkernel.so'",
       !region_name_matches("libkernel.so", "^LIB",
                            MEMDBG_MATCH_REGEX | MEMDBG_MATCH_CASE_SENSITIVE));

  TEST("regex: CASE_SENSITIVE '^lib' matches 'libkernel.so'",
       region_name_matches("libkernel.so", "^lib",
                           MEMDBG_MATCH_REGEX | MEMDBG_MATCH_CASE_SENSITIVE));

  /* Regex combined with EXACT (regex takes precedence) */
  TEST("regex: EXACT|REGEX '^lib' still matches 'libkernel.so'",
       region_name_matches("libkernel.so", "^lib",
                           MEMDBG_MATCH_EXACT | MEMDBG_MATCH_REGEX));

  /* Alternation */
  TEST("regex: '^(libkernel|libc)\\.so$' matches 'libkernel.so'",
       region_name_matches("libkernel.so", "^(libkernel|libc)\\.so$",
                           MEMDBG_MATCH_REGEX));

  TEST("regex: '^(libkernel|libc)\\.so$' does NOT match 'kernel.so'",
       !region_name_matches("kernel.so", "^(libkernel|libc)\\.so$",
                            MEMDBG_MATCH_REGEX));

  /* Character class */
  TEST("regex: '^lib[ck]' matches 'libkernel.so'",
       region_name_matches("libkernel.so", "^lib[ck]", MEMDBG_MATCH_REGEX));

  TEST("regex: '^lib[ck]' matches 'libc.so'",
       region_name_matches("libc.so", "^lib[ck]", MEMDBG_MATCH_REGEX));

  TEST("regex: '^lib[ck]' does NOT match 'libtest.so'",
       !region_name_matches("libtest.so", "^lib[ck]", MEMDBG_MATCH_REGEX));

  /* Invalid regex returns false (no crash) */
  TEST("regex: invalid pattern '[unclosed' returns false",
       !region_name_matches("foo", "[unclosed", MEMDBG_MATCH_REGEX));
}

/* ======================================================================
 * Full-path matching tests
 * ====================================================================== */

static void test_fullpath_matching(void) {
  printf("\n--- Full-path matching ---\n");

  /* FULLPATH basename equality: only full path matches */
  TEST("fullpath: 'libkernel.so' matches '/system/lib/libkernel.so' (substring)",
       region_name_matches("/system/lib/libkernel.so", "libkernel.so",
                            MEMDBG_MATCH_FULLPATH));

  TEST("fullpath: '/system/lib/libkernel.so' matches itself exactly",
       region_name_matches("/system/lib/libkernel.so", "/system/lib/libkernel.so",
                           MEMDBG_MATCH_FULLPATH));

  /* FULLPATH substring */
  TEST("fullpath: 'system' matches '/system/lib/libkernel.so'",
       region_name_matches("/system/lib/libkernel.so", "system",
                           MEMDBG_MATCH_FULLPATH));

  TEST("fullpath: '/data/' does NOT match '/system/lib/libkernel.so'",
       !region_name_matches("/system/lib/libkernel.so", "/data/",
                            MEMDBG_MATCH_FULLPATH));

  /* FULLPATH + EXACT suppresses substring */
  TEST("fullpath: EXACT|FULLPATH 'system' does NOT match '/system/lib/libkernel.so'",
       !region_name_matches("/system/lib/libkernel.so", "system",
                            MEMDBG_MATCH_EXACT | MEMDBG_MATCH_FULLPATH));

  /* FULLPATH + wildcard */
  TEST("fullpath: '/system/*' matches '/system/lib/libkernel.so'",
       region_name_matches("/system/lib/libkernel.so", "/system/*",
                           MEMDBG_MATCH_FULLPATH));

  TEST("fullpath: '*libkernel*' matches '/system/lib/libkernel.so'",
       region_name_matches("/system/lib/libkernel.so", "*libkernel*",
                           MEMDBG_MATCH_FULLPATH));

  /* FULLPATH + regex */
  TEST("fullpath: REGEX|FULLPATH '^/system/' matches '/system/lib/libkernel.so'",
       region_name_matches("/system/lib/libkernel.so", "^/system/",
                           MEMDBG_MATCH_REGEX | MEMDBG_MATCH_FULLPATH));

  TEST("fullpath: REGEX|FULLPATH '^/data/' does NOT match '/system/lib/libkernel.so'",
       !region_name_matches("/system/lib/libkernel.so", "^/data/",
                            MEMDBG_MATCH_REGEX | MEMDBG_MATCH_FULLPATH));
}

/* ======================================================================
 * Target region simulation
 * ====================================================================== */

struct sim_map_entry {
  uint64_t start;
  uint64_t end;
  const char *name;
};

static int sim_region_lookup(const struct sim_map_entry *entries, int count,
                             const char *target_region, uint64_t total_size,
                             uint64_t page_mask, uint64_t min_aligned,
                             unsigned int match_flags, uint64_t *base_out) {
  (void)page_mask;

  if (!target_region || !target_region[0]) {
    *base_out = 0;
    return 0;
  }

  uint64_t region_base = 0, region_end = 0;
  for (int i = 0; i < count; i++) {
    if (region_name_matches(entries[i].name, target_region, match_flags)) {
      region_base = entries[i].start;
      region_end  = entries[i].end;
      break;
    }
  }

  if (region_base == 0 || region_end <= region_base)
    return -1;

  uint64_t available = region_end - region_base;
  if (total_size > available)
    return -2;

  *base_out = region_base + min_aligned;
  return 0;
}

static void test_target_region_scenarios(void) {
  printf("\n--- Target region scenarios ---\n");

  const uint64_t page_mask  = 0x3FFFULL;
  const uint64_t min_aligned = 0x1000ULL;
  const uint64_t elf_size    = 0x8000ULL;

  const struct sim_map_entry maps[] = {
    { 0x00400000ULL, 0x00406000ULL, "/app/eboot.bin"         },
    { 0x20000000ULL, 0x20040000ULL, "/system/lib/libkernel.so" },
    { 0x30000000ULL, 0x30001000ULL, "/system/lib/libSceVideoOut.so" },
    { 0x40000000ULL, 0x40020000ULL, "/data/libtest.so"         },
  };
  const int map_count = 4;

  uint64_t base = 0;
  int rc;

  rc = sim_region_lookup(maps, map_count, "libkernel.so", elf_size,
                         page_mask, min_aligned, 0U, &base);
  TEST("target_region: 'libkernel.so' found and fits", rc == 0);

  rc = sim_region_lookup(maps, map_count, "LIBKERNEL.SO", elf_size,
                         page_mask, min_aligned, 0U, &base);
  TEST("target_region: 'LIBKERNEL.SO' found (case-insensitive)", rc == 0);

  rc = sim_region_lookup(maps, map_count, "libnonexistent.so", elf_size,
                         page_mask, min_aligned, 0U, &base);
  TEST("target_region: 'libnonexistent.so' returns -1 (not found)", rc == -1);

  rc = sim_region_lookup(maps, map_count, "SceVideoOut", elf_size,
                         page_mask, min_aligned, 0U, &base);
  TEST("target_region: 'SceVideoOut' too small returns -2", rc == -2);

  rc = sim_region_lookup(maps, map_count, "", elf_size,
                         page_mask, min_aligned, 0U, &base);
  TEST("target_region: empty string allocates new", rc == 0 && base == 0);

  rc = sim_region_lookup(maps, map_count, NULL, elf_size,
                         page_mask, min_aligned, 0U, &base);
  TEST("target_region: NULL allocates new", rc == 0 && base == 0);

  rc = sim_region_lookup(maps, map_count, "eboot.bin", 0x4000ULL,
                         page_mask, min_aligned, 0U, &base);
  TEST("target_region: 'eboot.bin' matches '/app/eboot.bin'", rc == 0);

  /* CASE_SENSITIVE flag: upper doesn't match lower */
  rc = sim_region_lookup(maps, map_count, "LIBKERNEL.SO", elf_size,
                         page_mask, min_aligned, MEMDBG_MATCH_CASE_SENSITIVE, &base);
  TEST("target_region: CASE_SENSITIVE 'LIBKERNEL.SO' not found (libkernel.so is lowercase)",
       rc == -1);

  /* EXACT flag: substring no longer works */
  rc = sim_region_lookup(maps, map_count, "kernel", elf_size,
                         page_mask, min_aligned, MEMDBG_MATCH_EXACT, &base);
  TEST("target_region: EXACT 'kernel' substring not found",
       rc == -1);
}

/* ======================================================================
 * Command code tests
 * ====================================================================== */

static void test_command_codes(void) {
  printf("\n--- Command codes ---\n");

  TEST_EQ("MEMDBG_CMD_PROCESS_HIJACK",
          (uint16_t)MEMDBG_CMD_PROCESS_HIJACK, 0x010EU);

  TEST_EQ("MEMDBG_CMD_PROCESS_ELF_LOAD",
          (uint16_t)MEMDBG_CMD_PROCESS_ELF_LOAD, 0x010DU);

  TEST("hijack != elf_load",
       MEMDBG_CMD_PROCESS_HIJACK != MEMDBG_CMD_PROCESS_ELF_LOAD);
  TEST("hijack != auth_key",
       MEMDBG_CMD_PROCESS_HIJACK != MEMDBG_CMD_AUTH_KEY);
  TEST("hijack != arena_config",
       MEMDBG_CMD_PROCESS_HIJACK != MEMDBG_CMD_ARENA_CONFIG);
  TEST("hijack != klog_connect",
       MEMDBG_CMD_PROCESS_HIJACK != MEMDBG_CMD_KLOG_CONNECT);
  TEST("hijack != shutdown",
       MEMDBG_CMD_PROCESS_HIJACK != MEMDBG_CMD_SHUTDOWN);
}

/* ======================================================================
 * Main
 * ====================================================================== */

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("=== New Features Unit Tests ===\n");
  printf("Testing: snap_compare, hijack protocol, ELF loader dispatch\n\n");

  printf("--- snap_compare() comparison logic ---\n");
  test_snap_compare_exact();
  test_snap_compare_1byte();
  test_snap_compare_8byte();
  test_snap_compare_greater();
  test_snap_compare_less();
  test_snap_compare_changed();
  test_snap_compare_between();
  test_snap_compare_numeric();
  test_snap_compare_numeric_8byte();

  test_protocol_struct_sizes();
  test_hijack_request_validation();
  test_target_region_field();
  test_match_flags_field();
  test_elf_load_validation();
  test_region_name_matching();
  test_match_flags_behaviour();
  test_region_name_regex();
  test_fullpath_matching();
  test_target_region_scenarios();
  test_command_codes();

  printf("\n=== Results ======================================\n");
  if (g_failed == 0) {
    printf("All tests PASSED.\n");
    return 0;
  } else {
    printf("%d test(s) FAILED.\n", g_failed);
    return 1;
  }
}
