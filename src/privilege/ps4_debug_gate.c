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
  /* Original disp8 used to repair NOP NOP written by older MemDBG builds. */
  uint8_t allow_legacy_nop_disp;
} memdbg_ps4_debug_gate_profile_t;

/* Always-allow ACMGR predicate: mov eax, 1; ret */
static const uint8_t k_acmgr_allow_stub[8] = {
    0x48u, 0xc7u, 0xc0u, 0x01u, 0x00u, 0x00u, 0x00u, 0xc3u};

/* Match ps4debug: force the taken/allow side of the short conditional branch. */
static const uint8_t k_ptrace_allow_jmp[1] = {0xebu};

/*
 * Firmware ids are major*100 + minor (900 = 9.00, 1100 = 11.00).
 * RVAs are relative to KERNEL_ADDRESS_IMAGE_BASE.
 *
 * Sibling firmwares that share identical gate sites get duplicate rows so
 * lookup stays a simple exact match on fw_id.
 */
static const memdbg_ps4_debug_gate_profile_t k_profiles[] = {
    /* 5.05 / 5.07 */
    {505u, 0x00011730u, 0x0030d9aau, 0x0030de01u, 0x000000d0, 0},
    {507u, 0x00011730u, 0x0030d9aau, 0x0030de01u, 0x000000d0, 0},
    /* 6.71 / 6.72 */
    {671u, 0x00233bd0u, 0x0010f879u, 0x0010fd22u, 0x000002e2, 0},
    {672u, 0x00233bd0u, 0x0010f879u, 0x0010fd22u, 0x000002e2, 0},
    /* 7.00 / 7.01 / 7.02 */
    {700u, 0x001cb880u, 0x000448d5u, 0x00044dafu, 0x0000027c, 0},
    {701u, 0x001cb880u, 0x000448d5u, 0x00044dafu, 0x0000027c, 0},
    {702u, 0x001cb880u, 0x000448d5u, 0x00044dafu, 0x0000027c, 0},
    /* 7.50 / 7.51 / 7.55 */
    {750u, 0x00364cd0u, 0x00361cf5u, 0x003621cfu, 0x0000027c, 0},
    {751u, 0x00364cd0u, 0x00361cf5u, 0x003621cfu, 0x0000027c, 0},
    {755u, 0x00364cd0u, 0x00361cf5u, 0x003621cfu, 0x0000027c, 0},
    /* 8.00 / 8.01 / 8.03 */
    {800u, 0x001d5710u, 0x00174155u, 0x0017462fu, 0x0000027c, 0},
    {801u, 0x001d5710u, 0x00174155u, 0x0017462fu, 0x0000027c, 0},
    {803u, 0x001d5710u, 0x00174155u, 0x0017462fu, 0x0000027c, 0},
    /* 8.50 / 8.52 */
    {850u, 0x002935e0u, 0x00132535u, 0x00132a0fu, 0x0000027c, 0},
    {852u, 0x002935e0u, 0x00132535u, 0x00132a0fu, 0x0000027c, 0},
    /* 9.00 */
    {900u, 0x0008bc20u, 0x0041f4e5u, 0x0041f9d1u, 0x0000027c, 0},
    /* 9.03 / 9.04 */
    {903u, 0x0008bc20u, 0x0041d455u, 0x0041d941u, 0x0000027c, 0},
    {904u, 0x0008bc20u, 0x0041d455u, 0x0041d941u, 0x0000027c, 0},
    /* 9.50 / 9.51 / 9.60 */
    {950u, 0x00032590u, 0x0047a005u, 0x0047a4f1u, 0x0000027c, 0},
    {951u, 0x00032590u, 0x0047a005u, 0x0047a4f1u, 0x0000027c, 0},
    {960u, 0x00032590u, 0x0047a005u, 0x0047a4f1u, 0x0000027c, 0},
    /* 10.00 / 10.01 */
    {1000u, 0x000a5c60u, 0x0044e625u, 0x0044eb11u, 0x0000027c, 0},
    {1001u, 0x000a5c60u, 0x0044e625u, 0x0044eb11u, 0x0000027c, 0},
    /* 10.50 / 10.51 / 10.70 / 10.71 */
    {1050u, 0x001f4470u, 0x00424e85u, 0x00425371u, 0x0000027c, 0},
    {1051u, 0x001f4470u, 0x00424e85u, 0x00425371u, 0x0000027c, 0},
    {1070u, 0x001f4470u, 0x00424e85u, 0x00425371u, 0x0000027c, 0},
    {1071u, 0x001f4470u, 0x00424e85u, 0x00425371u, 0x0000027c, 0},
    /* 11.00 / 11.02: ps4debug rewrites JA +0x1c to JMP +0x1c. */
    {1100u, 0x003d0de0u, 0x00384285u, 0x00384771u, 0x0000027c, 0x1c},
    {1102u, 0x003d0e00u, 0x003842a5u, 0x00384791u, 0x0000027c, 0x1c},
    /* 11.50 / 11.52 */
    {1150u, 0x003b2a90u, 0x00366745u, 0x00366c31u, 0x0000027c, 0},
    {1152u, 0x003b2a90u, 0x00366745u, 0x00366c31u, 0x0000027c, 0},
    /* 12.00 / 12.02 */
    {1200u, 0x003b2cd0u, 0x00366985u, 0x00366e71u, 0x0000027c, 0},
    {1202u, 0x003b2cd0u, 0x00366985u, 0x00366e71u, 0x0000027c, 0},
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

static int memdbg_ps4_debug_gate_is_jcc(uint8_t opcode) {
  return opcode >= 0x70u && opcode <= 0x7fu;
}

static void memdbg_ps4_debug_gate_hex(const uint8_t *bytes, size_t len,
                                      char *out, size_t out_len) {
  static const char k_hex[] = "0123456789abcdef";
  size_t i;
  size_t pos = 0u;

  if (out == NULL || out_len == 0u)
    return;
  out[0] = '\0';
  for (i = 0u; i < len; ++i) {
    if (pos + 3u >= out_len)
      break;
    if (i != 0u)
      out[pos++] = ' ';
    out[pos++] = k_hex[(bytes[i] >> 4) & 0xfu];
    out[pos++] = k_hex[bytes[i] & 0xfu];
    out[pos] = '\0';
  }
}

static int memdbg_ps4_debug_gate_apply_bytes(intptr_t addr, const uint8_t *want,
                                             size_t len, const char *slot_name,
                                             int allow_jcc_site,
                                             uint8_t allow_legacy_nop_disp,
                                             int *applied_out,
                                             int *skipped_out) {
  uint8_t cur[8];
  uint8_t verify[8];
  uint8_t allow_repair[2];
  char hex[48];
  int32_t rc;
  const uint8_t *patch = want;
  size_t patch_len = len;

  if (len == 0u || len > sizeof(cur) || want == NULL || addr == 0) {
    errno = EINVAL;
    return -1;
  }

  /* Peek two bytes at the allow site to detect obsolete NOP NOP patches. */
  {
    const size_t peek = allow_jcc_site ? 2u : len;
    rc = kernel_copyout(addr, cur, peek);
    if (rc != 0) {
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "privilege: ps4 debug gate read failed slot=%s addr=0x%lx "
                       "rc=%d",
                       slot_name, (unsigned long)addr, (int)rc);
      errno = EIO;
      return -1;
    }
    memdbg_ps4_debug_gate_hex(cur, peek, hex, sizeof(hex));
  }

  if (allow_jcc_site) {
    const int legacy_nop = cur[0] == 0x90u && cur[1] == 0x90u;
    if (!memdbg_ps4_debug_gate_is_jcc(cur[0]) && cur[0] != 0xebu &&
        !(legacy_nop && allow_legacy_nop_disp != 0u)) {
      memdbg_log_write(
          MEMDBG_LOG_WARN,
          "privilege: ps4 debug gate unexpected opcode slot=%s addr=0x%lx "
          "bytes=[%s] (expected Jcc 0x70-0x7f; wrong kernel base/offset?)",
          slot_name, (unsigned long)addr, hex);
      errno = EINVAL;
      return -1;
    }
    if (legacy_nop) {
      /*
       * Nightly builds before this fix replaced 11.00's "77 1c" with
       * "90 90". Restore the displacement while converting it to the exact
       * ps4debug patch "eb 1c", so upgrading does not require a reboot.
       */
      allow_repair[0] = k_ptrace_allow_jmp[0];
      allow_repair[1] = allow_legacy_nop_disp;
      patch = allow_repair;
      patch_len = sizeof(allow_repair);
    } else {
      patch = k_ptrace_allow_jmp;
      patch_len = sizeof(k_ptrace_allow_jmp);
    }
  }

  if (memcmp(cur, patch, patch_len) == 0) {
    if (skipped_out != NULL)
      (*skipped_out)++;
    memdbg_log_write(MEMDBG_LOG_INFO,
                     "privilege: ps4 debug gate already armed slot=%s "
                     "addr=0x%lx bytes=[%s]",
                     slot_name, (unsigned long)addr, hex);
    return 0;
  }

  rc = kernel_copyin(patch, addr, patch_len);
  if (rc != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "privilege: ps4 debug gate write failed slot=%s addr=0x%lx "
                     "rc=%d before=[%s]",
                     slot_name, (unsigned long)addr, (int)rc, hex);
    errno = EPERM;
    return -1;
  }

  rc = kernel_copyout(addr, verify, patch_len);
  if (rc != 0 || memcmp(verify, patch, patch_len) != 0) {
    char after[48];
    memdbg_ps4_debug_gate_hex(verify, patch_len, after, sizeof(after));
    memdbg_log_write(
        MEMDBG_LOG_WARN,
        "privilege: ps4 debug gate verify failed slot=%s addr=0x%lx "
        "before=[%s] after=[%s]",
        slot_name, (unsigned long)addr, hex, after);
    errno = EIO;
    return -1;
  }

  if (applied_out != NULL)
    (*applied_out)++;
  memdbg_log_write(MEMDBG_LOG_INFO,
                   "privilege: ps4 debug gate patched slot=%s addr=0x%lx "
                   "before=[%s] patch_len=%u",
                   slot_name, (unsigned long)addr, hex, (unsigned)patch_len);
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
  int first_errno = 0;

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

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "privilege: ps4 debug gates arming fw=%u fw_raw=0x%x "
                   "base=0x%lx prison0=0x%lx rootvnode=0x%lx",
                   (unsigned)fw_id, (unsigned)raw_fw, (unsigned long)base,
                   (unsigned long)KERNEL_ADDRESS_PRISON0,
                   (unsigned long)KERNEL_ADDRESS_ROOTVNODE);

  if (memdbg_ps4_debug_gate_apply_bytes(
          base + (intptr_t)profile->acmgr_rva, k_acmgr_allow_stub,
          sizeof(k_acmgr_allow_stub), "acmgr_system_debug", 0, 0, &applied,
          &skipped) != 0) {
    if (first_errno == 0)
      first_errno = errno != 0 ? errno : EPERM;
    failures++;
  }

  if (memdbg_ps4_debug_gate_apply_bytes(
          base + (intptr_t)profile->ptrace_allow_rva, k_ptrace_allow_jmp,
          sizeof(k_ptrace_allow_jmp), "ptrace_allow_branch", 1,
          profile->allow_legacy_nop_disp, &applied, &skipped) != 0) {
    if (first_errno == 0)
      first_errno = errno != 0 ? errno : EPERM;
    failures++;
  }

  if (memdbg_ps4_debug_gate_apply_bytes(
          base + (intptr_t)profile->ptrace_policy_rva, policy_patch,
          sizeof(policy_patch), "ptrace_policy_skip", 0, 0, &applied,
          &skipped) != 0) {
    if (first_errno == 0)
      first_errno = errno != 0 ? errno : EPERM;
    failures++;
  }

  if (failures != 0) {
    memdbg_log_write(
        MEMDBG_LOG_WARN,
        "privilege: ps4 debug gates incomplete fw=%u applied=%d skipped=%d "
        "failed=%d/%d",
        (unsigned)fw_id, applied, skipped, failures, MEMDBG_PS4_GATE_SLOT_COUNT);
    errno = first_errno != 0 ? first_errno : EPERM;
    return -1;
  }

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "privilege: ps4 debug gates armed fw=%u applied=%d/%d "
                   "skipped=%d base=0x%lx",
                   (unsigned)fw_id, applied + skipped,
                   MEMDBG_PS4_GATE_SLOT_COUNT, skipped, (unsigned long)base);
  return 0;
}

#else /* !MEMDBG_PS4_DEBUG_GATE_LIVE */

int memdbg_ps4_debug_gate_arm(void) { return 0; }

#endif /* MEMDBG_PS4_DEBUG_GATE_LIVE */
