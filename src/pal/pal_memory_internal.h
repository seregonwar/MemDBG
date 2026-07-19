/*
 * memDBG - PAL: Shared platform detection for memory access backends.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Included by every pal_memory*.c translation unit so that each
 * platform backend can be compiled independently without duplicating
 * the detection logic.
 */

#ifndef MEMDBG_PAL_MEMORY_INTERNAL_H
#define MEMDBG_PAL_MEMORY_INTERNAL_H

#include "memdbg/pal/pal_memory.h"
#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/pal/pal_fileio.h"
#include "memdbg/pal/pal_process.h"
#include "memdbg/pal/pal_kernel_fast.h"
#include "memdbg/scanner/pt_walker.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
#define MEMDBG_PAL_PS4 1
#endif

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#define MEMDBG_PAL_PS5 1
#endif

#if defined(MEMDBG_PAL_PS4) || defined(MEMDBG_PAL_PS5)
#define MEMDBG_PAL_CONSOLE 1
#endif

#if defined(MEMDBG_PAL_PS4)
#include <ps4/mdbg.h>
#elif defined(MEMDBG_PAL_PS5)
#include <ps5/kernel.h>
#include <ps5/mdbg.h>
#include <sys/mman.h>

extern long __crt_syscall(long sysno, ...);
#endif

#if defined(__FreeBSD__) && !defined(MEMDBG_PAL_CONSOLE)
#include <sys/ptrace.h>
#include <sys/types.h>
#endif

#endif /* MEMDBG_PAL_MEMORY_INTERNAL_H */
