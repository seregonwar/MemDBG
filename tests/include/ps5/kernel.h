/*
 * PS5 kernel header stub — compiled only for host-side testing of
 * pal_memory_console.c with mocked SDK functions.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef TESTS_PS5_KERNEL_H
#define TESTS_PS5_KERNEL_H

#include <stdint.h>
#include <sys/types.h>

/* All SDK symbols used by pal_memory_console.c are redirected to
 * mock_* functions defined in the test translation unit.  The macros
 * below must be in effect BEFORE pal_memory_internal.h is included
 * by the console memory backend. */
#define mdbg_copyout                  mock_mdbg_copyout
#define mdbg_copyin                   mock_mdbg_copyin
#define kernel_get_fw_version         mock_kernel_get_fw_version
#define kernel_get_vmem_protection    mock_kernel_get_vmem_protection
#define kernel_set_vmem_protection    mock_kernel_set_vmem_protection
#define kernel_mprotect               mock_kernel_mprotect
#define memdbg_kernel_external_begin  mock_memdbg_kernel_external_begin
#define memdbg_kernel_external_end    mock_memdbg_kernel_external_end
#define kernel_get_proc               mock_kernel_get_proc
#define kernel_setlong                mock_kernel_setlong
#define kernel_getlong                mock_kernel_getlong

/* ---- mock declarations ---- */
extern int mock_mdbg_copyout(pid_t pid, intptr_t address,
                             void *buffer, size_t length);
extern int mock_mdbg_copyin(pid_t pid, const void *buffer,
                            intptr_t address, size_t length);
extern uint32_t mock_kernel_get_fw_version(void);
extern int mock_kernel_get_vmem_protection(pid_t pid, intptr_t address,
                                           size_t length);
extern int mock_kernel_set_vmem_protection(pid_t pid, intptr_t address,
                                           size_t length, int protection);
extern int mock_kernel_mprotect(pid_t pid, intptr_t address,
                                size_t length, int prot);
extern int mock_memdbg_kernel_external_begin(void);
extern void mock_memdbg_kernel_external_end(void);
extern intptr_t mock_kernel_get_proc(pid_t pid);
extern int mock_kernel_setlong(intptr_t addr, uint64_t val);
extern uint64_t mock_kernel_getlong(intptr_t addr);

#endif /* TESTS_PS5_KERNEL_H */
