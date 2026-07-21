/*
 * memDBG - Syscall name table lookup.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Thin wrapper that selects the correct syscall table at compile time.
 * Platform-specific tables live in syscall_names_table_*.inc.
 */

#include "memdbg/tracer/tracer.h"

#include <stddef.h>

/* ------------------------------------------------------------------ */
/*  FreeBSD / console (x86-64) syscall table                          */
/* ------------------------------------------------------------------ */

#if defined(__FreeBSD__) || defined(PLATFORM_PS4) || defined(PLATFORM_PS5) || \
    defined(PS4) || defined(PS5) || defined(__ORBIS__) || defined(__PROSPERO__)

#include "tables/freebsd.inc"

/* ------------------------------------------------------------------ */
/*  macOS (x86-64 / arm64) syscall table                              */
/* ------------------------------------------------------------------ */

#elif defined(__APPLE__)

#include "tables/macos.inc"

/* ------------------------------------------------------------------ */
/*  Fallback (should not be reached on a supported platform)          */
/* ------------------------------------------------------------------ */

#else

const char *memdbg_tracer_syscall_name(int syscall_no) {
  (void)syscall_no;
  return "unknown";
}

#endif
