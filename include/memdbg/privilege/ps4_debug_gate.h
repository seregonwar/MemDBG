/*
 * MemDBG - PS4 native debugger gate arming.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * On PS4, PT_ATTACH is gated by Sony ACMGR + in-kernel ptrace policy checks.
 * GoldHEN mdbg R/W does not remove those gates.  This module arms the minimal
 * kernel sites needed for MemDBG's ptrace-based debugger on supported firmware.
 */

#ifndef MEMDBG_PRIVILEGE_PS4_DEBUG_GATE_H
#define MEMDBG_PRIVILEGE_PS4_DEBUG_GATE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Arm PS4 native-debug kernel gates for the running firmware.
 *
 * Returns 0 when all required sites are already correct or were patched.
 * Returns a negative errno-style code when the firmware is unsupported or a
 * required write failed.  Non-PS4 builds always return 0.
 *
 * Failure is non-fatal for daemon startup: memory/scan via mdbg can still work.
 */
int memdbg_ps4_debug_gate_arm(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PRIVILEGE_PS4_DEBUG_GATE_H */
