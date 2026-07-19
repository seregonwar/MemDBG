/*
 * PS4 mdbg header stub — compiled only for host-side testing of
 * pal_memory_console.c with mocked PS4 SDK functions.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * On PS4 the memory backend uses mdbg_copyout and mdbg_copyin directly
 * without PTWALK, DMAP, or PS5-specific kernel helpers.
 */
#ifndef TESTS_PS4_MDBG_H
#define TESTS_PS4_MDBG_H

#include <stdint.h>
#include <sys/types.h>

/* All SDK symbols used by pal_memory_console.c on PS4 are redirected
 * to mock_* functions defined in the test translation unit.  These
 * macros must be in effect BEFORE pal_memory_internal.h is included. */
#define mdbg_copyout                  mock_mdbg_copyout
#define mdbg_copyin                   mock_mdbg_copyin

/* ---- mock declarations ---- */
extern int mock_mdbg_copyout(pid_t pid, intptr_t address,
                             void *buffer, size_t length);
extern int mock_mdbg_copyin(pid_t pid, const void *buffer,
                            intptr_t address, size_t length);

#endif /* TESTS_PS4_MDBG_H */
