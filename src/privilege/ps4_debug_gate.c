/*
 * MemDBG - PS4 native debugger gate arming.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Data-driven apply of the three semantic sites required for PT_ATTACH:
 *   1) ACMGR "system level debugging allowed" predicate
 *   2) ptrace allow-path branch
 *   3) ptrace policy-block skip
 *
 * Firmware coverage mirrors the GoldHEN-era PS4 debug gate set
 * (5.05 through 12.02 families, plus close siblings that share sites).
 */

#include "memdbg/privilege/ps4_debug_gate.h"

#include "memdbg/core/memdbg_log.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#if defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
#include <ps4/kernel.h>
#define MEMDBG_PS4_DEBUG_GATE_LIVE 1
#else
#define MEMDBG_PS4_DEBUG_GATE_LIVE 0
#endif

#if MEMDBG_PS4_DEBUG_GATE_LIVE

enum { MEMDBG_PS4_GATE_SLOT_COUNT = 3 };

typedef struct memdbg_ps4_debug_gate_profile {
  uint16_t fw_id;
  uint32_t acmgr_rva;
  uint32_t ptrace_allow_rva;
  uint32_t ptrace_policy_rva;
  int32_t ptrace_policy_rel32;
} memdbg_ps4_debug_gate_profile_t;

/* Always-allow ACMGR predicate: mov eax, 1; ret */
static const uint8_t k_acmgr_allow_stub[8] = {
    0x48u, 0xc7u, 0xc0u, 0x01u, 0x00u, 0x00u, 0x00u, 0xc3u};

/* Force the taken/allow side of a near conditional branch. */
static const uint8_t k_ptrace_allow_byte[1] = {0xebu};

/*
 * Firmware ids are major*100 + minor (900 = 9.00, 1100 = 11.00).
 * RVAs are relative to KERNEL_ADDRESS_IMAGE_BASE.
 *
 * Sibling firmwares that share identical gate sites get duplicate rows so
 * lookup stays a simple exact match on fw_id.
 */
static const memdbg_ps4_debug_gate_profile_t k_profiles[] = {
    /* 5.05 / 5.07 */
    {505u, 0x00011730u, 0x0030d9aau, 0x0030de01u, 0x000000d0},
    {507u, 0x00011730u, 0x0030d9aau, 0x0030de01u, 0x000000d0},
    /* 6.71 / 6.72 */
    {671u, 0x00233bd0u, 0x0010f879u, 0x0010fd22u, 0x000002e2},
    {672u, 0x00233bd0u, 0x0010f879u, 0x0010fd22u, 0x000002e2},
    /* 7.00 / 7.01 / 7.02 */
    {700u, 0x001cb880u, 0x000448d5u, 0x00044dafu, 0x0000027c},
    {701u, 0x001cb880u, 0x000448d5u, 0x00044dafu, 0x0000027c},
    {702u, 0x001cb880u, 0x000448d5u, 0x00044dafu, 0x0000027c},
    /* 7.50 / 7.51 / 7.55 */
    {750u, 0x00364cd0u, 0x00361cf5u, 0x003621cfu, 0x0000027c},
    {751u, 0x00364cd0u, 0x00361cf5u, 0x003621cfu, 0x0000027c},
    {755u, 0x00364cd0u, 0x00361cf5u, 0x003621cfu, 0x0000027c},
    /* 8.00 / 8.01 / 8.03 */
    {800u, 0x001d5710u, 0x00174155u, 0x0017462fu, 0x0000027c},
    {801u, 0x001d5710u, 0x00174155u, 0x0017462fu, 0x0000027c},
    {803u, 0x001d5710u, 0x00174155u, 0x0017462fu, 0x0000027c},
    /* 8.50 / 8.52 */
    {850u, 0x002935e0u, 0x00132535u, 0x00132a0fu, 0x0000027c},
    {852u, 0x002935e0u, 0x00132535u, 0x00132a0fu, 0x0000027c},
    /* 9.00 */
    {900u, 0x0008bc20u, 0x0041f4e5u, 0x0041f9d1u, 0x0000027c},
    /* 9.03 / 9.04 */
    {903u, 0x0008bc20u, 0x0041d455u, 0x0041d941u, 0x0000027c},
    {904u, 0x0008bc20u, 0x0041d455u, 0x0041d941u, 0x0000027c},
    /* 9.50 / 9.51 / 9.60 */
    {950u, 0x00032590u, 0x0047a005u, 0x0047a4f1u, 0x0000027c},
    {951u, 0x00032590u, 0x0047a005u, 0x0047a4f1u, 0x0000027c},
    {960u, 0x00032590u, 0x0047a005u, 0x0047a4f1u, 0x0000027c},
    /* 10.00 / 10.01 */
    {1000u, 0x000a5c60u, 0x0044e625u, 0x0044eb11u, 0x0000027c},
    {1001u, 0x000a5c60u, 0x0044e625u, 0x0044eb11u, 0x0000027c},
    /* 10.50 / 10.51 / 10.70 / 10.71 */
    {1050u, 0x001f4470u, 0x00424e85u, 0x00425371u, 0x0000027c},
    {1051u, 0x001f4470u, 0x00424e85u, 0x00425371u, 0x0000027c},
    {1070u, 0x001f4470u, 0x00424e85u, 0x00425371u, 0x0000027c},
    {1071u, 0x001f4470u, 0x00424e85u, 0x00425371u, 0x0000027c},
    /* 11.00 */
    {1100u, 0x003d0de0u, 0x00384285u, 0x00384771u, 0x0000027c},
    /* 11.02 */
    {1102u, 0x003d0e00u, 0x003842a5u, 0x00384791u, 0x0000027c},
    /* 11.50 / 11.52 */
    {1150u, 0x003b2a90u, 0x00366745u, 0x00366c31u, 0x0000027c},
    {1152u, 0x003b2a90u, 0x00366745u, 0x00366c31u, 0x0000027c},
    /* 12.00 / 12.02 */
    {1200u, 0x003b2cd0u, 0x00366985u, 0x00366e71u, 0x0000027c},
    {1202u, 0x003b2cd0u, 0x00366985u, 0x00366e71u, 0x0000027c},
};

static uint16_t memdbg_ps4_fw_id_from_raw(uint32_t raw) {
  /*
   * Real PS4 SDK values observed on console look like 0x11008001: the high
   * 16 bits are BCD major/minor (0x1100 -> 11.00) and the low 16 bits carry
   * build/flags.  Accept that form first.
   */
  {
    const uint16_t bcd = (uint16_t)((raw >> 16) & 0xffffu);
    const unsigned d0 = (bcd >> 12) & 0xfu;
    const unsigned d1 = (bcd >> 8) & 0xfu;
    const unsigned d2 = (bcd >> 4) & 0xfu;
    const unsigned d3 = bcd & 0xfu;
    if (bcd != 0u && d0 <= 9u && d1 <= 9u && d2 <= 9u && d3 <= 9u) {
      const unsigned major = d0 * 10u + d1;
      const unsigned minor = d2 * 10u + d3;
      if (major >= 1u && major <= 99u)
        return (uint16_t)(major * 100u + minor);
    }
  }

  /* Hex major/minor bytes with zero low word (e.g. 0x0b000000 -> 11.00). */
  if ((raw & 0xffffu) == 0u && raw >= 0x01000000u) {
    const unsigned major = (raw >> 24) & 0xffu;
    const unsigned minor = (raw >> 16) & 0xffu;
    if (major >= 1u && major <= 99u && minor <= 99u)
      return (uint16_t)(major * 100u + minor);
  }

  /* Packed decimal used by some helpers (900, 1100). */
  if (raw >= 100u && raw <= 9999u)
    return (uint16_t)raw;

  /* BCD-ish full low word 0x0900 / 0x0b00 when presented alone. */
  if (raw >= 0x0100u && raw <= 0x9999u) {
    const unsigned d0 = (raw >> 12) & 0xfu;
    const unsigned d1 = (raw >> 8) & 0xfu;
    const unsigned d2 = (raw >> 4) & 0xfu;
    const unsigned d3 = raw & 0xfu;
    if (d0 <= 9u && d1 <= 9u && d2 <= 9u && d3 <= 9u) {
      const unsigned major = d0 * 10u + d1;
      const unsigned minor = d2 * 10u + d3;
      if (major >= 1u && major <= 99u)
        return (uint16_t)(major * 100u + minor);
    }
  }

  return 0u;
}

static const memdbg_ps4_debug_gate_profile_t *
memdbg_ps4_debug_gate_find_profile(uint16_t fw_id) {
  size_t i;
  for (i = 0; i < sizeof(k_profiles) / sizeof(k_profiles[0]); ++i) {
    if (k_profiles[i].fw_id == fw_id)
      return &k_profiles[i];
  }
  return NULL;
}

static void memdbg_ps4_debug_gate_build_policy_patch(int32_t rel32,
                                                     uint8_t out[5]) {
  out[0] = 0xe9u;
  out[1] = (uint8_t)((uint32_t)rel32 & 0xffu);
  out[2] = (uint8_t)(((uint32_t)rel32 >> 8) & 0xffu);
  out[3] = (uint8_t)(((uint32_t)rel32 >> 16) & 0xffu);
  out[4] = (uint8_t)(((uint32_t)rel32 >> 24) & 0xffu);
}

static int memdbg_ps4_debug_gate_apply_bytes(intptr_t addr, const uint8_t *want,
                                             size_t len, const char *slot_name,
                                             int *applied_out,
                                             int *skipped_out) {
  uint8_t cur[8];
  int32_t rc;

  if (len == 0u || len > sizeof(cur) || want == NULL || addr == 0) {
    errno = EINVAL;
    return -1;
  }

  rc = kernel_copyout(addr, cur, len);
  if (rc != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "privilege: ps4 debug gate read failed slot=%s addr=0x%lx "
                     "rc=%d",
                     slot_name, (unsigned long)addr, (int)rc);
    errno = EIO;
    return -1;
  }

  if (memcmp(cur, want, len) == 0) {
    if (skipped_out != NULL)
      (*skipped_out)++;
    return 0;
  }

  rc = kernel_copyin(want, addr, len);
  if (rc != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "privilege: ps4 debug gate write failed slot=%s addr=0x%lx "
                     "rc=%d",
                     slot_name, (unsigned long)addr, (int)rc);
    errno = EPERM;
    return -1;
  }

  if (applied_out != NULL)
    (*applied_out)++;
  return 0;
}

int memdbg_ps4_debug_gate_arm(void) {
  const uint32_t raw_fw = kernel_get_fw_version();
  const uint16_t fw_id = memdbg_ps4_fw_id_from_raw(raw_fw);
  const memdbg_ps4_debug_gate_profile_t *profile;
  const intptr_t base = KERNEL_ADDRESS_IMAGE_BASE;
  uint8_t policy_patch[5];
  int applied = 0;
  int skipped = 0;
  int failures = 0;

  if (base == 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "privilege: ps4 debug gates skipped (kernel base unset)");
    errno = ENODEV;
    return -1;
  }

  profile = memdbg_ps4_debug_gate_find_profile(fw_id);
  if (profile == NULL) {
    memdbg_log_write(
        MEMDBG_LOG_WARN,
        "privilege: ps4 debug gates unsupported fw_raw=0x%x fw_id=%u "
        "(debugger attach may return permission denied)",
        (unsigned)raw_fw, (unsigned)fw_id);
    errno = ENOTSUP;
    return -1;
  }

  memdbg_ps4_debug_gate_build_policy_patch(profile->ptrace_policy_rel32,
                                           policy_patch);

  if (memdbg_ps4_debug_gate_apply_bytes(
          base + (intptr_t)profile->acmgr_rva, k_acmgr_allow_stub,
          sizeof(k_acmgr_allow_stub), "acmgr_system_debug", &applied,
          &skipped) != 0)
    failures++;

  if (memdbg_ps4_debug_gate_apply_bytes(
          base + (intptr_t)profile->ptrace_allow_rva, k_ptrace_allow_byte,
          sizeof(k_ptrace_allow_byte), "ptrace_allow_branch", &applied,
          &skipped) != 0)
    failures++;

  if (memdbg_ps4_debug_gate_apply_bytes(
          base + (intptr_t)profile->ptrace_policy_rva, policy_patch,
          sizeof(policy_patch), "ptrace_policy_skip", &applied, &skipped) != 0)
    failures++;

  if (failures != 0) {
    memdbg_log_write(
        MEMDBG_LOG_WARN,
        "privilege: ps4 debug gates incomplete fw=%u applied=%d skipped=%d "
        "failed=%d/%d",
        (unsigned)fw_id, applied, skipped, failures, MEMDBG_PS4_GATE_SLOT_COUNT);
    errno = EPERM;
    return -1;
  }

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "privilege: ps4 debug gates armed fw=%u applied=%d/%d "
                   "skipped=%d",
                   (unsigned)fw_id, applied + skipped,
                   MEMDBG_PS4_GATE_SLOT_COUNT, skipped);
  return 0;
}

#else /* !MEMDBG_PS4_DEBUG_GATE_LIVE */

int memdbg_ps4_debug_gate_arm(void) { return 0; }

#endif /* MEMDBG_PS4_DEBUG_GATE_LIVE */
