/*
 * MemDBG - Protocol ABI consistency and golden-packet tests.
 *
 * Validates:
 *   1. Wire struct sizes via runtime checks (C11 _Static_assert in the
 *      header already covers compile-time; these runtime checks provide
 *      human-readable output in test logs).
 *   2. Golden packet round-trip: construct a known-good byte buffer for
 *      packet_header, response_header, hello_request/response and verify
 *      that memcpy to/from the struct reproduces the exact bytes.
 *   3. Command ID uniqueness — no two enum values are identical.
 *   4. Capability bit uniqueness — no two cap values share a bit.
 *   5. Basic endianness / magic-number sanity.
 *
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/core/memdbg.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      ++g_passed;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      ++g_failed;                                                              \
      printf("  FAIL  %s\n", name);                                            \
    }                                                                          \
  } while (0)

/* ===================================================================
 *  1. Golden packet round-trip
 * =================================================================== */

/* Known-good packet_header for a HELLO request with request_id=1, length=16 */
static const uint8_t kGoldenPacketHeader[16] = {
    0x4d, 0x44, 0x42, 0x47, /* magic = "MDBG" LE = 0x4742444d */
    0x01, 0x00,             /* version = 1 LE */
    0x01, 0x00,             /* command = MEMDBG_CMD_HELLO = 0x0001 LE */
    0x01, 0x00, 0x00, 0x00, /* request_id = 1 LE */
    0x10, 0x00, 0x00, 0x00  /* length = 16 LE */
};

/* Known-good response_header for HELLO_OK with request_id=1, status=0, len=64 */
static const uint8_t kGoldenResponseHeader[20] = {
    0x4d, 0x44, 0x42, 0x47, /* magic */
    0x01, 0x00,             /* version */
    0x01, 0x00,             /* command = HELLO */
    0x01, 0x00, 0x00, 0x00, /* request_id */
    0x00, 0x00, 0x00, 0x00, /* status = MEMDBG_OK */
    0x40, 0x00, 0x00, 0x00  /* length = 64 */
};

static void test_golden_packet_header(void) {
  printf("\n--- Golden packet: packet_header ---\n");

  memdbg_packet_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic     = MEMDBG_PACKET_MAGIC;
  hdr.version   = MEMDBG_PROTOCOL_VERSION;
  hdr.command   = MEMDBG_CMD_HELLO;
  hdr.request_id = 1U;
  hdr.length    = sizeof(memdbg_hello_request_t);

  TEST("packet_header size matches",
       sizeof(hdr) == sizeof(kGoldenPacketHeader));

  int match = memcmp(&hdr, kGoldenPacketHeader, sizeof(hdr)) == 0;
  TEST("packet_header golden bytes match", match != 0);

  /* Verify magic number byte-order */
  TEST("packet magic is 'MDBG'",
       hdr.magic == MEMDBG_PACKET_MAGIC &&
       MEMDBG_PACKET_MAGIC == 0x4742444dU);
}

static void test_golden_response_header(void) {
  printf("\n--- Golden packet: response_header ---\n");

  memdbg_response_header_t rhdr;
  memset(&rhdr, 0, sizeof(rhdr));
  rhdr.magic     = MEMDBG_PACKET_MAGIC;
  rhdr.version   = MEMDBG_PROTOCOL_VERSION;
  rhdr.command   = MEMDBG_CMD_HELLO;
  rhdr.request_id = 1U;
  rhdr.status    = MEMDBG_OK;
  rhdr.length    = sizeof(memdbg_hello_response_t);

  TEST("response_header size matches",
       sizeof(rhdr) == sizeof(kGoldenResponseHeader));

  int match = memcmp(&rhdr, kGoldenResponseHeader, sizeof(rhdr)) == 0;
  TEST("response_header golden bytes match", match != 0);

  TEST("MEMDBG_OK is zero", MEMDBG_OK == 0);
}

static void test_golden_hello_request(void) {
  printf("\n--- Golden packet: hello_request (role=CONTROL) ---\n");

  memdbg_hello_request_t req;
  memset(&req, 0, sizeof(req));
  req.magic     = MEMDBG_HELLO_REQUEST_MAGIC;
  req.version   = MEMDBG_HELLO_REQUEST_VERSION;
  req.role      = MEMDBG_CLIENT_ROLE_CONTROL;
  req.session_id = 0x123456789ABCDEF0ULL;

  /* Construct expected bytes manually */
  uint8_t expected[16];
  memset(expected, 0, sizeof(expected));
  expected[0]  = 0x53; expected[1] = 0x45; /* 'SE' */
  expected[2]  = 0x53; expected[3] = 0x31; /* 'S1' = 0x31534553 LE */
  expected[4]  = 0x01; expected[5] = 0x00; /* version = 1 */
  expected[6]  = 0x00; expected[7] = 0x00; /* role = CONTROL = 0 */
  expected[8]  = 0xF0; expected[9]  = 0xDE;
  expected[10] = 0xBC; expected[11] = 0x9A;
  expected[12] = 0x78; expected[13] = 0x56;
  expected[14] = 0x34; expected[15] = 0x12; /* session_id LE */

  TEST("hello_request size matches",
       sizeof(req) == sizeof(expected));

  int match = memcmp(&req, expected, sizeof(req)) == 0;
  TEST("hello_request golden bytes match", match != 0);
}

/* ===================================================================
 *  2. Command ID uniqueness
 * =================================================================== */

/*
 * Every MEMDBG_CMD_* value must be unique.  The enum is spread across
 * several groups but no two identifiers should collide.
 *
 * This test lists every command and checks pairwise uniqueness using
 * a brute-force O(n^2) approach (n ≈ 60, so 3600 comparisons = fast).
 */
static void test_command_id_uniqueness(void) {
  printf("\n--- Command ID uniqueness ---\n");

  /* All MEMDBG_CMD_* values indexed by their C identifier.
   * Keep this list exhaustive — add new commands here. */
  struct { const char *name; uint16_t id; } const cmds[] = {
    {"HELLO",                    MEMDBG_CMD_HELLO},
    {"PING",                     MEMDBG_CMD_PING},
    {"GOODBYE",                  MEMDBG_CMD_GOODBYE},
    {"PROCESS_LIST",             MEMDBG_CMD_PROCESS_LIST},
    {"PROCESS_MAPS",             MEMDBG_CMD_PROCESS_MAPS},
    {"PROCESS_INFO",             MEMDBG_CMD_PROCESS_INFO},
    {"MEMORY_READ",              MEMDBG_CMD_MEMORY_READ},
    {"MEMORY_WRITE",             MEMDBG_CMD_MEMORY_WRITE},
    {"SCAN_EXACT",               MEMDBG_CMD_SCAN_EXACT},
    {"SCAN_PROCESS_EXACT",       MEMDBG_CMD_SCAN_PROCESS_EXACT},
    {"SCAN_AOB",                 MEMDBG_CMD_SCAN_AOB},
    {"SCAN_POINTER",             MEMDBG_CMD_SCAN_POINTER},
    {"SCAN_UNKNOWN",             MEMDBG_CMD_SCAN_UNKNOWN},
    {"SCAN_PROCESS_AOB",         MEMDBG_CMD_SCAN_PROCESS_AOB},
    {"SCAN_UNKNOWN_V2",          MEMDBG_CMD_SCAN_UNKNOWN_V2},
    {"SCAN_PROCESS_EXACT_TRACKED", MEMDBG_CMD_SCAN_PROCESS_EXACT_TRACKED},
    {"SCAN_JOB_STATUS",          MEMDBG_CMD_SCAN_JOB_STATUS},
    {"SCAN_JOB_CANCEL",          MEMDBG_CMD_SCAN_JOB_CANCEL},
    {"FOREGROUND_APP",           MEMDBG_CMD_FOREGROUND_APP},
    {"PROCESS_STOP",             MEMDBG_CMD_PROCESS_STOP},
    {"PROCESS_CONTINUE",         MEMDBG_CMD_PROCESS_CONTINUE},
    {"PROCESS_KILL",             MEMDBG_CMD_PROCESS_KILL},
    {"BATCH_READ",               MEMDBG_CMD_BATCH_READ},
    {"BATCH_WRITE",              MEMDBG_CMD_BATCH_WRITE},
    {"BATCH_PROCESS_INFO",       MEMDBG_CMD_BATCH_PROCESS_INFO},
    {"PROCESS_PROTECT",          MEMDBG_CMD_PROCESS_PROTECT},
    {"PROCESS_ALLOC",            MEMDBG_CMD_PROCESS_ALLOC},
    {"PROCESS_FREE",             MEMDBG_CMD_PROCESS_FREE},
    {"PROCESS_STACK",            MEMDBG_CMD_PROCESS_STACK},
    {"PROCESS_CALL",             MEMDBG_CMD_PROCESS_CALL},
    {"PROCESS_ELF_LOAD",         MEMDBG_CMD_PROCESS_ELF_LOAD},
    {"PROCESS_HIJACK",           MEMDBG_CMD_PROCESS_HIJACK},
    {"PROCESS_DUMP",             MEMDBG_CMD_PROCESS_DUMP},
    {"PROCESS_MAPS_V2",          MEMDBG_CMD_PROCESS_MAPS_V2},
    {"TELEMETRY",                MEMDBG_CMD_TELEMETRY},
    {"DISCOVERY",                MEMDBG_CMD_DISCOVERY},
    {"DEBUG_ATTACH",             MEMDBG_CMD_DEBUG_ATTACH},
    {"DEBUG_DETACH",             MEMDBG_CMD_DEBUG_DETACH},
    {"DEBUG_STOP",               MEMDBG_CMD_DEBUG_STOP},
    {"DEBUG_CONTINUE",           MEMDBG_CMD_DEBUG_CONTINUE},
    {"DEBUG_STEP",               MEMDBG_CMD_DEBUG_STEP},
    {"DEBUG_GET_THREADS",        MEMDBG_CMD_DEBUG_GET_THREADS},
    {"DEBUG_GET_REGS",           MEMDBG_CMD_DEBUG_GET_REGS},
    {"DEBUG_SET_REGS",           MEMDBG_CMD_DEBUG_SET_REGS},
    {"DEBUG_GET_DBREGS",         MEMDBG_CMD_DEBUG_GET_DBREGS},
    {"DEBUG_SET_DBREGS",         MEMDBG_CMD_DEBUG_SET_DBREGS},
    {"DEBUG_SET_BREAKPOINT",     MEMDBG_CMD_DEBUG_SET_BREAKPOINT},
    {"DEBUG_CLEAR_BREAKPOINT",   MEMDBG_CMD_DEBUG_CLEAR_BREAKPOINT},
    {"DEBUG_SET_WATCHPOINT",     MEMDBG_CMD_DEBUG_SET_WATCHPOINT},
    {"DEBUG_CLEAR_WATCHPOINT",   MEMDBG_CMD_DEBUG_CLEAR_WATCHPOINT},
    {"DEBUG_SUSPEND_THREAD",     MEMDBG_CMD_DEBUG_SUSPEND_THREAD},
    {"DEBUG_RESUME_THREAD",      MEMDBG_CMD_DEBUG_RESUME_THREAD},
    {"DEBUG_POLL_EVENTS",        MEMDBG_CMD_DEBUG_POLL_EVENTS},
    {"DEBUG_GET_BREAKPOINTS",    MEMDBG_CMD_DEBUG_GET_BREAKPOINTS},
    {"DEBUG_GET_WATCHPOINTS",    MEMDBG_CMD_DEBUG_GET_WATCHPOINTS},
    {"DEBUG_SET_BREAKPOINT_COND", MEMDBG_CMD_DEBUG_SET_BREAKPOINT_COND},
    {"DEBUG_CLEAR_ALL_BREAKPOINTS", MEMDBG_CMD_DEBUG_CLEAR_ALL_BREAKPOINTS},
    {"DEBUG_CLEAR_ALL_WATCHPOINTS", MEMDBG_CMD_DEBUG_CLEAR_ALL_WATCHPOINTS},
    {"DEBUG_GET_FPREGS",         MEMDBG_CMD_DEBUG_GET_FPREGS},
    {"DEBUG_SET_FPREGS",         MEMDBG_CMD_DEBUG_SET_FPREGS},
    {"DEBUG_GET_FSGSBASE",       MEMDBG_CMD_DEBUG_GET_FSGSBASE},
    {"DEBUG_SET_FSGSBASE",       MEMDBG_CMD_DEBUG_SET_FSGSBASE},
    {"TRACER_ATTACH",            MEMDBG_CMD_TRACER_ATTACH},
    {"TRACER_DETACH",            MEMDBG_CMD_TRACER_DETACH},
    {"TRACER_POLL",              MEMDBG_CMD_TRACER_POLL},
    {"TRACER_STATUS",            MEMDBG_CMD_TRACER_STATUS},
    {"KERNEL_BASE",              MEMDBG_CMD_KERNEL_BASE},
    {"KERNEL_READ",              MEMDBG_CMD_KERNEL_READ},
    {"KERNEL_WRITE",             MEMDBG_CMD_KERNEL_WRITE},
    {"CONSOLE_NOTIFY",           MEMDBG_CMD_CONSOLE_NOTIFY},
    {"CONSOLE_PRINT",            MEMDBG_CMD_CONSOLE_PRINT},
    {"CONSOLE_REBOOT",           MEMDBG_CMD_CONSOLE_REBOOT},
    {"ASM_ENCODE",               MEMDBG_CMD_ASM_ENCODE},
    {"DISASM",                   MEMDBG_CMD_DISASM},
    {"XREFS_TO",                 MEMDBG_CMD_XREFS_TO},
    {"QUICKSCAN_CAPS",           MEMDBG_CMD_QUICKSCAN_CAPS},
    {"QUICKSCAN_START",          MEMDBG_CMD_QUICKSCAN_START},
    {"QUICKSCAN_COUNT",          MEMDBG_CMD_QUICKSCAN_COUNT},
    {"QUICKSCAN_FETCH",          MEMDBG_CMD_QUICKSCAN_FETCH},
    {"QUICKSCAN_END",            MEMDBG_CMD_QUICKSCAN_END},
    {"QUICKSCAN_CONFIG",         MEMDBG_CMD_QUICKSCAN_CONFIG},
    {"QUICKSCAN_REGIONS",        MEMDBG_CMD_QUICKSCAN_REGIONS},
    {"QUICKSCAN_CANCEL",         MEMDBG_CMD_QUICKSCAN_CANCEL},
    {"PTWALK_DISCOVER",          MEMDBG_CMD_PTWALK_DISCOVER},
    {"PTWALK_AUGMENT",           MEMDBG_CMD_PTWALK_AUGMENT},
    {"PTWALK_READ",              MEMDBG_CMD_PTWALK_READ},
    {"PTWALK_WRITE",             MEMDBG_CMD_PTWALK_WRITE},
    {"PTWALK_PROBE",             MEMDBG_CMD_PTWALK_PROBE},
    {"BATCH_WRITE_ADV",          MEMDBG_CMD_BATCH_WRITE_ADV},
    {"AUTH_KEY",                 MEMDBG_CMD_AUTH_KEY},
    {"ARENA_CONFIG",             MEMDBG_CMD_ARENA_CONFIG},
    {"KLOG_CONNECT",             MEMDBG_CMD_KLOG_CONNECT},
    {"GET_EXTENDED_CAPS",        MEMDBG_CMD_GET_EXTENDED_CAPS},
    {"SHUTDOWN",                 MEMDBG_CMD_SHUTDOWN},
  };

  const int n = sizeof(cmds) / sizeof(cmds[0]);
  int duplicates = 0;

  for (int i = 0; i < n; ++i) {
    for (int j = i + 1; j < n; ++j) {
      if (cmds[i].id == cmds[j].id) {
        printf("  FAIL  duplicate command ID 0x%04x: %s == %s\n",
               (unsigned)cmds[i].id, cmds[i].name, cmds[j].name);
        ++g_failed;
        ++duplicates;
      }
    }
  }

  if (duplicates == 0) {
    TEST("all command IDs are unique", 1);
  }
}

/* ===================================================================
 *  3. Capability bit uniqueness
 * =================================================================== */

static void test_capability_uniqueness(void) {
  printf("\n--- Capability bit uniqueness ---\n");

  struct { const char *name; uint32_t bit; } const caps[] = {
    {"PROCESS_LIST",       MEMDBG_CAP_PROCESS_LIST},
    {"PROCESS_MAPS",       MEMDBG_CAP_PROCESS_MAPS},
    {"MEMORY_READ",        MEMDBG_CAP_MEMORY_READ},
    {"MEMORY_WRITE",       MEMDBG_CAP_MEMORY_WRITE},
    {"SCAN_EXACT",         MEMDBG_CAP_SCAN_EXACT},
    {"UDP_LOG",            MEMDBG_CAP_UDP_LOG},
    {"SCAN_PROCESS_EXACT", MEMDBG_CAP_SCAN_PROCESS_EXACT},
    {"SCAN_TELEMETRY",     MEMDBG_CAP_SCAN_TELEMETRY},
    {"PROCESS_INFO",       MEMDBG_CAP_PROCESS_INFO},
    {"SCAN_AOB",           MEMDBG_CAP_SCAN_AOB},
    {"SCAN_POINTER",       MEMDBG_CAP_SCAN_POINTER},
    {"FOREGROUND_APP",     MEMDBG_CAP_FOREGROUND_APP},
    {"PROCESS_CONTROL",    MEMDBG_CAP_PROCESS_CONTROL},
    {"BATCH_READ",         MEMDBG_CAP_BATCH_READ},
    {"PERF_TELEMETRY",     MEMDBG_CAP_PERF_TELEMETRY},
    {"SCAN_UNKNOWN",       MEMDBG_CAP_SCAN_UNKNOWN},
    {"BATCH_WRITE",        MEMDBG_CAP_BATCH_WRITE},
    {"LZ4",                MEMDBG_CAP_LZ4},
    {"SCAN_PROCESS_AOB",   MEMDBG_CAP_SCAN_PROCESS_AOB},
    {"DISCOVERY",          MEMDBG_CAP_DISCOVERY},
    {"DEBUGGER",           MEMDBG_CAP_DEBUGGER},
    {"TRACER",             MEMDBG_CAP_TRACER},
    {"MEMORY_PROTECT",     MEMDBG_CAP_MEMORY_PROTECT},
    {"MEMORY_ALLOC",       MEMDBG_CAP_MEMORY_ALLOC},
    {"STACK_WALK",         MEMDBG_CAP_STACK_WALK},
    {"REMOTE_CALL",        MEMDBG_CAP_REMOTE_CALL},
    {"KERNEL_ACCESS",      MEMDBG_CAP_KERNEL_ACCESS},
    {"CONSOLE_UI",         MEMDBG_CAP_CONSOLE_UI},
    {"DEBUG_FPREGS",       MEMDBG_CAP_DEBUG_FPREGS},
    {"DEBUG_FSGS",         MEMDBG_CAP_DEBUG_FSGS},
    {"DISASSEMBLY",        MEMDBG_CAP_DISASSEMBLY},
  };

  /* Each bit must be a power of two (single bit set) */
  int single_bit_failures = 0;
  for (int i = 0; i < (int)(sizeof(caps) / sizeof(caps[0])); ++i) {
    if ((caps[i].bit & (caps[i].bit - 1U)) != 0U) {
      printf("  FAIL  %s = 0x%08x is not a single bit\n",
             caps[i].name, (unsigned)caps[i].bit);
      ++g_failed;
      ++single_bit_failures;
    }
  }
  if (single_bit_failures == 0) {
    TEST("all caps are single-bit values", 1);
  }

  /* No two caps share the same bit */
  int duplicates = 0;
  const int n = sizeof(caps) / sizeof(caps[0]);
  for (int i = 0; i < n; ++i) {
    for (int j = i + 1; j < n; ++j) {
      if (caps[i].bit == caps[j].bit) {
        printf("  FAIL  duplicate cap bit 0x%08x: %s == %s\n",
               (unsigned)caps[i].bit, caps[i].name, caps[j].name);
        ++g_failed;
        ++duplicates;
      }
    }
  }
  if (duplicates == 0) {
    TEST("all capability bits are unique", 1);
  }
}

/* ===================================================================
 *  4. Extended capability bit uniqueness
 * =================================================================== */

static void test_extended_cap_uniqueness(void) {
  printf("\n--- Extended capability bit uniqueness ---\n");

  struct { const char *name; uint32_t bit; } const ecaps[] = {
    {"QUICKSCAN",      MEMDBG_EXT_CAP_QUICKSCAN},
    {"PTWALK",          MEMDBG_EXT_CAP_PTWALK},
    {"ALIAS",           MEMDBG_EXT_CAP_ALIAS},
    {"SIMD",            MEMDBG_EXT_CAP_SIMD},
    {"KLOG_SERVER",     MEMDBG_EXT_CAP_KLOG_SERVER},
    {"AUTH",            MEMDBG_EXT_CAP_AUTH},
    {"ARENA",           MEMDBG_EXT_CAP_ARENA},
    {"BATCH_WRITE_ADV", MEMDBG_EXT_CAP_BATCH_WRITE_ADV},
    {"HIJACK",          MEMDBG_EXT_CAP_HIJACK},
    {"SCAN_JOBS",       MEMDBG_EXT_CAP_SCAN_JOBS},
  };

  int duplicates = 0;
  const int n = sizeof(ecaps) / sizeof(ecaps[0]);

  for (int i = 0; i < n; ++i) {
    if ((ecaps[i].bit & (ecaps[i].bit - 1U)) != 0U) {
      printf("  FAIL  ext_cap %s = 0x%08x is not a single bit\n",
             ecaps[i].name, (unsigned)ecaps[i].bit);
      ++g_failed;
      ++duplicates;
    }
  }

  for (int i = 0; i < n; ++i) {
    for (int j = i + 1; j < n; ++j) {
      if (ecaps[i].bit == ecaps[j].bit) {
        printf("  FAIL  duplicate ext_cap bit 0x%08x: %s == %s\n",
               (unsigned)ecaps[i].bit, ecaps[i].name, ecaps[j].name);
        ++g_failed;
        ++duplicates;
      }
    }
  }

  if (duplicates == 0) {
    TEST("all extended capability bits are unique", 1);
  }
}

/* ===================================================================
 *  5. Wire size consistency (C++ static_assert replicates in C)
 * =================================================================== */

static void test_wire_sizes(void) {
  printf("\n--- Wire struct size consistency ---\n");

  /* Wire framing */
  TEST("sizeof packet_header == 16", sizeof(memdbg_packet_header_t) == 16U);
  TEST("sizeof response_header == 20", sizeof(memdbg_response_header_t) == 20U);

  /* Session */
  TEST("sizeof hello_request == 16", sizeof(memdbg_hello_request_t) == 16U);
  TEST("sizeof hello_response == 64", sizeof(memdbg_hello_response_t) == 64U);
  TEST("HELLO_V1_SIZE == 44", MEMDBG_HELLO_V1_SIZE == 44U);
  TEST("HELLO_V2_SIZE == 64", MEMDBG_HELLO_V2_SIZE == 64U);

  /* Process */
  TEST("sizeof process_entry == 56", sizeof(memdbg_process_entry_t) == 56U);
  TEST("sizeof process_info_response == 260",
       sizeof(memdbg_process_info_response_t) == 260U);

  /* Memory maps */
  TEST("sizeof map_entry == 88", sizeof(memdbg_map_entry_t) == 88U);

  /* Memory */
  TEST("sizeof memory_request == 16", sizeof(memdbg_memory_request_t) == 16U);

  /* Debugger */
  TEST("sizeof debug_regs == 176", sizeof(memdbg_debug_regs_t) == 176U);
  TEST("sizeof debug_dbregs == 128", sizeof(memdbg_debug_dbregs_t) == 128U);
  TEST("sizeof debug_thread_entry == 100",
       sizeof(memdbg_debug_thread_entry_t) == 100U);
  TEST("sizeof debug_fpregs == 1032",
       sizeof(memdbg_debug_fpregs_t) == 1032U);

  /* Auth / Arena */
  TEST("sizeof auth_key_request == 8",
       sizeof(memdbg_auth_key_request_t) == 8U);
  TEST("sizeof arena_config_request == 8",
       sizeof(memdbg_arena_config_request_t) == 8U);

  /* Extended caps */
  TEST("sizeof extended_caps_response == 4",
       sizeof(memdbg_extended_caps_response_t) == 4U);

  /* Batch process info response */
  TEST("sizeof batch_process_info_response == 8",
       sizeof(memdbg_batch_process_info_response_t) == 8U);
}

/* ===================================================================
 *  Main
 * =================================================================== */

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("=== Protocol ABI Consistency Tests ===\n");
  printf("Framework: golden packets, ID uniqueness, wire sizes\n");

  test_golden_packet_header();
  test_golden_response_header();
  test_golden_hello_request();
  test_command_id_uniqueness();
  test_capability_uniqueness();
  test_extended_cap_uniqueness();
  test_wire_sizes();

  printf("\n=== Results ============================\n");
  printf("Total:  %d\n", g_passed + g_failed);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("========================================\n");
  return g_failed == 0 ? 0 : 1;
}
