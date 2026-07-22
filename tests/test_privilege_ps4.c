/*
 * Regression test for PS4 self-jailbreak pointer handling.
 *
 * The PS4 SDK exposes KERNEL_ADDRESS_ROOTVNODE and KERNEL_ADDRESS_PRISON0 as
 * already-resolved pointers.  Treating them as pointer slots and reading
 * through them produces small structure-field values such as 0x2, corrupting
 * the payload's filesystem jail and hanging the next stat()/mkdir().
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/core/memdbg_log.h"

#include <ps4/kernel.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

const intptr_t KERNEL_ADDRESS_ROOTVNODE = (intptr_t)0x12345000;
const intptr_t KERNEL_ADDRESS_PRISON0 = (intptr_t)0x12346000;

static int g_kernel_getlong_calls;
static intptr_t g_rootdir_set;
static intptr_t g_jaildir_set;
static intptr_t g_prison_set;

void memdbg_log_write(memdbg_log_level_t level, const char *fmt, ...) {
  (void)level;
  (void)fmt;
}

uint64_t kernel_getlong(intptr_t addr) {
  (void)addr;
  ++g_kernel_getlong_calls;
  return UINT64_C(2);
}

intptr_t kernel_get_proc_filedesc(pid_t pid) {
  (void)pid;
  return (intptr_t)0x12347000;
}

uint64_t kernel_get_ucred_authid(pid_t pid) {
  (void)pid;
  return UINT64_C(0x3800000000000001);
}

int32_t kernel_get_ucred_caps(pid_t pid, uint8_t caps[16]) {
  (void)pid;
  memset(caps, 0x5a, 16U);
  return 0;
}

uint64_t kernel_get_ucred_attrs(pid_t pid) {
  (void)pid;
  return UINT64_C(0x80);
}

intptr_t kernel_get_proc_rootdir(pid_t pid) {
  (void)pid;
  return (intptr_t)0x11111000;
}

intptr_t kernel_get_proc_jaildir(pid_t pid) {
  (void)pid;
  return (intptr_t)0x11112000;
}

intptr_t kernel_get_ucred_prison(int pid) {
  (void)pid;
  return (intptr_t)0x11113000;
}

int32_t kernel_set_ucred_uid(pid_t pid, uid_t uid) {
  (void)pid;
  (void)uid;
  return 0;
}

int32_t kernel_set_ucred_ruid(pid_t pid, uid_t ruid) {
  (void)pid;
  (void)ruid;
  return 0;
}

int32_t kernel_set_ucred_svuid(pid_t pid, uid_t svuid) {
  (void)pid;
  (void)svuid;
  return 0;
}

int32_t kernel_set_ucred_rgid(pid_t pid, gid_t rgid) {
  (void)pid;
  (void)rgid;
  return 0;
}

int32_t kernel_set_ucred_svgid(pid_t pid, gid_t svgid) {
  (void)pid;
  (void)svgid;
  return 0;
}

int32_t kernel_set_ucred_authid(pid_t pid, uint64_t authid) {
  (void)pid;
  (void)authid;
  return 0;
}

int32_t kernel_set_ucred_caps(pid_t pid, const uint8_t caps[16]) {
  (void)pid;
  (void)caps;
  return 0;
}

int32_t kernel_set_ucred_attrs(pid_t pid, uint64_t attrs) {
  (void)pid;
  (void)attrs;
  return 0;
}

int32_t kernel_set_proc_rootdir(pid_t pid, intptr_t vnode) {
  (void)pid;
  g_rootdir_set = vnode;
  return 0;
}

int32_t kernel_set_proc_jaildir(pid_t pid, intptr_t vnode) {
  (void)pid;
  g_jaildir_set = vnode;
  return 0;
}

int32_t kernel_set_ucred_prison(int pid, intptr_t prison) {
  (void)pid;
  g_prison_set = prison;
  return 0;
}

/* Compile the production implementation against the mocks above. */
#include "../src/privilege/privilege.c"

int main(void) {
  int failures = 0;

  if (memdbg_privilege_jailbreak_self() != 0) {
    fprintf(stderr, "FAIL: PS4 self-jailbreak returned an error\n");
    ++failures;
  }
  if (g_rootdir_set != KERNEL_ADDRESS_ROOTVNODE ||
      g_jaildir_set != KERNEL_ADDRESS_ROOTVNODE) {
    fprintf(stderr, "FAIL: root vnode was not passed through directly\n");
    ++failures;
  }
  if (g_prison_set != KERNEL_ADDRESS_PRISON0) {
    fprintf(stderr, "FAIL: prison0 was not passed through directly\n");
    ++failures;
  }
  if (g_kernel_getlong_calls != 0) {
    fprintf(stderr, "FAIL: resolved PS4 pointers were dereferenced (%d calls)\n",
            g_kernel_getlong_calls);
    ++failures;
  }
  if (!memdbg_privilege_is_active()) {
    fprintf(stderr, "FAIL: successful escalation was not marked active\n");
    ++failures;
  }

  if (failures == 0)
    puts("PASS: PS4 privilege pointers are used without double dereference");
  return failures == 0 ? 0 : 1;
}
