/*
 * Host-side regression test for PS4 native debug gate arming.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/core/memdbg_log.h"

#include <ps4/kernel.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

const intptr_t KERNEL_ADDRESS_IMAGE_BASE = (intptr_t)0x100000000LL;
const intptr_t KERNEL_ADDRESS_PRISON0 = (intptr_t)0x12346000;
const intptr_t KERNEL_ADDRESS_ROOTVNODE = (intptr_t)0x12345000;

enum { MOCK_KERNEL_SPAN = 0x01000000 };

static uint8_t g_kmem[MOCK_KERNEL_SPAN];
static uint32_t g_fw_raw = 0x09000000u;
static int g_copyin_calls;
static int g_copyout_calls;
static int g_fail_copyin_once;
static intptr_t g_last_copyin_addr;

void memdbg_log_write(memdbg_log_level_t level, const char *fmt, ...) {
  (void)level;
  (void)fmt;
}

uint32_t kernel_get_fw_version(void) { return g_fw_raw; }

static int mock_offset(intptr_t kaddr, size_t len, size_t *off_out) {
  if (kaddr < KERNEL_ADDRESS_IMAGE_BASE)
    return -1;
  {
    const size_t off = (size_t)(kaddr - KERNEL_ADDRESS_IMAGE_BASE);
    if (off >= MOCK_KERNEL_SPAN || len > MOCK_KERNEL_SPAN - off)
      return -1;
    *off_out = off;
  }
  return 0;
}

int32_t kernel_copyout(intptr_t kaddr, void *udaddr, size_t len) {
  size_t off;
  ++g_copyout_calls;
  if (udaddr == NULL || mock_offset(kaddr, len, &off) != 0)
    return -1;
  memcpy(udaddr, &g_kmem[off], len);
  return 0;
}

int32_t kernel_copyin(const void *udaddr, intptr_t kaddr, size_t len) {
  size_t off;
  ++g_copyin_calls;
  g_last_copyin_addr = kaddr;
  if (g_fail_copyin_once) {
    g_fail_copyin_once = 0;
    return -1;
  }
  if (udaddr == NULL || mock_offset(kaddr, len, &off) != 0)
    return -1;
  memcpy(&g_kmem[off], udaddr, len);
  return 0;
}

#include "../src/privilege/ps4_debug_gate.c"

static void reset_state(void) {
  memset(g_kmem, 0xcc, sizeof(g_kmem));
  g_fw_raw = 0x09000000u;
  g_copyin_calls = 0;
  g_copyout_calls = 0;
  g_fail_copyin_once = 0;
  g_last_copyin_addr = 0;
}

static int expect_bytes(uint32_t rva, const uint8_t *want, size_t len,
                        const char *label) {
  if (memcmp(&g_kmem[rva], want, len) != 0) {
    fprintf(stderr, "FAIL: %s mismatch at rva=0x%x\n", label, rva);
    return 1;
  }
  return 0;
}

int main(void) {
  int failures = 0;
  static const uint8_t acmgr[8] = {0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
                                   0xc3};
  static const uint8_t allow[1] = {0xeb};
  static const uint8_t policy[5] = {0xe9, 0x7c, 0x02, 0x00, 0x00};

  /* Firmware 9.00 (SDK encoding) arms all three sites. */
  reset_state();
  if (memdbg_ps4_debug_gate_arm() != 0) {
    fprintf(stderr, "FAIL: fw 9.00 arm returned error\n");
    ++failures;
  }
  failures += expect_bytes(0x0008bc20u, acmgr, sizeof(acmgr), "9.00 acmgr");
  failures += expect_bytes(0x0041f4e5u, allow, sizeof(allow), "9.00 allow");
  failures += expect_bytes(0x0041f9d1u, policy, sizeof(policy), "9.00 policy");
  if (g_copyin_calls != 3) {
    fprintf(stderr, "FAIL: expected 3 writes on first arm, got %d\n",
            g_copyin_calls);
    ++failures;
  }

  /* Second arm is idempotent. */
  g_copyin_calls = 0;
  g_copyout_calls = 0;
  if (memdbg_ps4_debug_gate_arm() != 0) {
    fprintf(stderr, "FAIL: idempotent arm returned error\n");
    ++failures;
  }
  if (g_copyin_calls != 0) {
    fprintf(stderr, "FAIL: idempotent arm wrote %d times\n", g_copyin_calls);
    ++failures;
  }
  if (g_copyout_calls != 3) {
    fprintf(stderr, "FAIL: idempotent arm should still verify sites\n");
    ++failures;
  }

  /* Console-observed encoding: 0x11008001 -> BCD 11.00. */
  reset_state();
  g_fw_raw = 0x11008001u;
  if (memdbg_ps4_debug_gate_arm() != 0) {
    fprintf(stderr, "FAIL: console fw encoding 0x11008001 arm returned error\n");
    ++failures;
  }
  failures += expect_bytes(0x003d0de0u, acmgr, sizeof(acmgr), "11.00 bcd acmgr");
  failures += expect_bytes(0x00384285u, allow, sizeof(allow), "11.00 bcd allow");
  failures += expect_bytes(0x00384771u, policy, sizeof(policy), "11.00 bcd policy");

  /* Firmware 11.00. */
  reset_state();
  g_fw_raw = 0x0b000000u;
  if (memdbg_ps4_debug_gate_arm() != 0) {
    fprintf(stderr, "FAIL: fw 11.00 arm returned error\n");
    ++failures;
  }
  failures += expect_bytes(0x003d0de0u, acmgr, sizeof(acmgr), "11.00 acmgr");
  failures += expect_bytes(0x00384285u, allow, sizeof(allow), "11.00 allow");
  failures += expect_bytes(0x00384771u, policy, sizeof(policy), "11.00 policy");

  /* Packed decimal encoding also maps. */
  reset_state();
  g_fw_raw = 900u;
  if (memdbg_ps4_debug_gate_arm() != 0) {
    fprintf(stderr, "FAIL: packed fw id 900 arm returned error\n");
    ++failures;
  }

  /* Firmware 5.05 uses a different policy skip distance. */
  reset_state();
  g_fw_raw = 0x05050000u;
  {
    static const uint8_t policy_505[5] = {0xe9, 0xd0, 0x00, 0x00, 0x00};
    if (memdbg_ps4_debug_gate_arm() != 0) {
      fprintf(stderr, "FAIL: fw 5.05 arm returned error\n");
      ++failures;
    }
    failures += expect_bytes(0x00011730u, acmgr, sizeof(acmgr), "5.05 acmgr");
    failures += expect_bytes(0x0030d9aau, allow, sizeof(allow), "5.05 allow");
    failures +=
        expect_bytes(0x0030de01u, policy_505, sizeof(policy_505), "5.05 policy");
  }

  /* Firmware 12.02 shares the 12.00 site family. */
  reset_state();
  g_fw_raw = 1202u;
  if (memdbg_ps4_debug_gate_arm() != 0) {
    fprintf(stderr, "FAIL: fw 12.02 arm returned error\n");
    ++failures;
  }
  failures += expect_bytes(0x003b2cd0u, acmgr, sizeof(acmgr), "12.02 acmgr");
  failures += expect_bytes(0x00366985u, allow, sizeof(allow), "12.02 allow");
  failures += expect_bytes(0x00366e71u, policy, sizeof(policy), "12.02 policy");

  /* Unsupported firmware must not write. */
  reset_state();
  g_fw_raw = 0x04990000u;
  if (memdbg_ps4_debug_gate_arm() == 0) {
    fprintf(stderr, "FAIL: unsupported fw unexpectedly succeeded\n");
    ++failures;
  }
  if (g_copyin_calls != 0 || errno != ENOTSUP) {
    fprintf(stderr,
            "FAIL: unsupported fw should set ENOTSUP without writes "
            "(writes=%d errno=%d)\n",
            g_copyin_calls, errno);
    ++failures;
  }

  /* Partial write failure is reported. */
  reset_state();
  g_fw_raw = 0x09000000u;
  g_fail_copyin_once = 1;
  if (memdbg_ps4_debug_gate_arm() == 0) {
    fprintf(stderr, "FAIL: copyin failure was ignored\n");
    ++failures;
  }
  if (errno != EPERM) {
    fprintf(stderr, "FAIL: expected EPERM after write failure, got %d\n", errno);
    ++failures;
  }

  if (failures == 0)
    puts("PASS: PS4 debug gates arm idempotently on supported firmware");
  return failures == 0 ? 0 : 1;
}
