/*
 * memDBG - PAL: Cross-platform debugger primitives.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Thin wrapper that selects the correct platform implementation at compile
 * time.  Platform-specific code lives in pal_debug_*.inc.
 */

#include "memdbg/pal/debug.h"

#include "memdbg/privilege/privilege.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#define MEMDBG_PAL_DEBUG_CONSOLE 1
#define MEMDBG_PAL_DEBUG_PS5 1
#include "memdbg/pal/debug_ps5.h"
#elif defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
#define MEMDBG_PAL_DEBUG_CONSOLE 1
#elif defined(__FreeBSD__)
#define MEMDBG_PAL_DEBUG_FREEBSD 1
#elif defined(__APPLE__)
#define MEMDBG_PAL_DEBUG_MACOS 1
#endif

#if defined(MEMDBG_PAL_DEBUG_FREEBSD) || defined(MEMDBG_PAL_DEBUG_CONSOLE)
#include "freebsd.inc"
#elif defined(MEMDBG_PAL_DEBUG_MACOS)
#include "macos.inc"
#else
#include "unsupported.inc"
#endif
