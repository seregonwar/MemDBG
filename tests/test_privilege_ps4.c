/*
 * Regression test for PS4 loader credential preservation.
 *
 * GoldHEN hosts payload ELFs in a shared, long-lived process.  MemDBG must not
 * permanently rewrite that process's auth ID, prison, or filesystem vnodes:
 * doing so breaks system services and subsequent payload launches.
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
static int g_credential_write_calls;
static bool g_fail_caps_write_once;
static uid_t g_uid = 501;
static uid_t g_ruid = 502;
static uid_t g_svuid = 503;
static gid_t g_rgid = 601;
static gid_t g_svgid = 602;
static intptr_t g_prison = (intptr_t)0x11113000;
static uint64_t g_authid = UINT64_C(0x3800000000000001);
static uint8_t g_caps[16] = {
  0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
  0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
};

#define MOCK_UCRED ((intptr_t)0x12348000)

void memdbg_log_write(memdbg_log_level_t level, const char *fmt, ...) {
  (void)level;
  (void)fmt;
}

uint64_t kernel_getlong(intptr_t addr) {
  (void)addr;
  ++g_kernel_getlong_calls;
  return UINT64_C(2);
}

intptr_t kernel_get_proc_ucred(pid_t pid) {
  (void)pid;
  return MOCK_UCRED;
}

int32_t kernel_copyout(intptr_t kaddr, void *udaddr, size_t len) {
  const void *source = NULL;

  if (kaddr == MOCK_UCRED + 0x04 && len == sizeof(g_uid)) source = &g_uid;
  if (kaddr == MOCK_UCRED + 0x08 && len == sizeof(g_ruid)) source = &g_ruid;
  if (kaddr == MOCK_UCRED + 0x0c && len == sizeof(g_svuid)) source = &g_svuid;
  if (kaddr == MOCK_UCRED + 0x14 && len == sizeof(g_rgid)) source = &g_rgid;
  if (kaddr == MOCK_UCRED + 0x18 && len == sizeof(g_svgid)) source = &g_svgid;
  if (source == NULL) return -1;
  memcpy(udaddr, source, len);
  return 0;
}

intptr_t kernel_get_proc_filedesc(pid_t pid) {
  (void)pid;
  return (intptr_t)0x12347000;
}

uint64_t kernel_get_ucred_authid(pid_t pid) {
  (void)pid;
  return g_authid;
}

int32_t kernel_get_ucred_caps(pid_t pid, uint8_t caps[16]) {
  (void)pid;
  memcpy(caps, g_caps, 16U);
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
  return g_prison;
}

int32_t kernel_set_ucred_uid(pid_t pid, uid_t uid) {
  (void)pid;
  g_uid = uid;
  ++g_credential_write_calls;
  return 0;
}

int32_t kernel_set_ucred_ruid(pid_t pid, uid_t ruid) {
  (void)pid;
  g_ruid = ruid;
  ++g_credential_write_calls;
  return 0;
}

int32_t kernel_set_ucred_svuid(pid_t pid, uid_t svuid) {
  (void)pid;
  g_svuid = svuid;
  ++g_credential_write_calls;
  return 0;
}

int32_t kernel_set_ucred_rgid(pid_t pid, gid_t rgid) {
  (void)pid;
  g_rgid = rgid;
  ++g_credential_write_calls;
  return 0;
}

int32_t kernel_set_ucred_svgid(pid_t pid, gid_t svgid) {
  (void)pid;
  g_svgid = svgid;
  ++g_credential_write_calls;
  return 0;
}

int32_t kernel_set_ucred_authid(pid_t pid, uint64_t authid) {
  (void)pid;
  g_authid = authid;
  ++g_credential_write_calls;
  return 0;
}

int32_t kernel_set_ucred_caps(pid_t pid, const uint8_t caps[16]) {
  (void)pid;
  ++g_credential_write_calls;
  if (g_fail_caps_write_once) {
    g_fail_caps_write_once = false;
    return -1;
  }
  memcpy(g_caps, caps, 16U);
  return 0;
}

int32_t kernel_set_ucred_attrs(pid_t pid, uint64_t attrs) {
  (void)pid;
  (void)attrs;
  ++g_credential_write_calls;
  return 0;
}

int32_t kernel_set_proc_rootdir(pid_t pid, intptr_t vnode) {
  (void)pid;
  g_rootdir_set = vnode;
  ++g_credential_write_calls;
  return 0;
}

int32_t kernel_set_proc_jaildir(pid_t pid, intptr_t vnode) {
  (void)pid;
  g_jaildir_set = vnode;
  ++g_credential_write_calls;
  return 0;
}

int32_t kernel_set_ucred_prison(int pid, intptr_t prison) {
  (void)pid;
  g_prison = prison;
  ++g_credential_write_calls;
  return 0;
}

/* Compile the production implementation against the mocks above. */
#include "../src/privilege/privilege.c"

int main(void) {
  int failures = 0;
  memdbg_ucred_backup_t ptrace_backup;
  uint8_t full_caps[16];

  memset(full_caps, 0xff, sizeof(full_caps));

  if (memdbg_privilege_jailbreak_self() != 0) {
    fprintf(stderr, "FAIL: PS4 self-jailbreak returned an error\n");
    ++failures;
  }
  if (g_rootdir_set != 0 || g_jaildir_set != 0 ||
      g_prison != (intptr_t)0x11113000 || g_credential_write_calls != 0) {
    fprintf(stderr, "FAIL: PS4 loader credentials were modified\n");
    ++failures;
  }
  if (g_kernel_getlong_calls != 0) {
    fprintf(stderr, "FAIL: PS4 kernel state was dereferenced (%d calls)\n",
            g_kernel_getlong_calls);
    ++failures;
  }
  if (memdbg_privilege_is_active()) {
    fprintf(stderr, "FAIL: preserved PS4 credentials were marked escalated\n");
    ++failures;
  }

  /* The narrow, reversible ptrace credential window must remain available. */
  g_credential_write_calls = 0;
  if (memdbg_privilege_begin_ptrace(&ptrace_backup) != 0) {
    fprintf(stderr, "FAIL: temporary PS4 ptrace credentials failed\n");
    ++failures;
  } else {
    if (g_uid != 0 || g_ruid != 0 || g_svuid != 0 || g_rgid != 0 ||
        g_svgid != 0 || g_prison != KERNEL_ADDRESS_PRISON0 ||
        g_authid != MEMDBG_PRIVILEGE_PTRACE_AUTHID ||
        memcmp(g_caps, full_caps, sizeof(g_caps)) != 0) {
      fprintf(stderr, "FAIL: ptrace identity was not fully elevated\n");
      ++failures;
    }
    if (memdbg_privilege_end_ptrace(&ptrace_backup) != 0) {
      fprintf(stderr, "FAIL: temporary PS4 ptrace credentials failed\n");
      ++failures;
    }
  }

  if (g_credential_write_calls != 16) {
    fprintf(stderr,
            "FAIL: ptrace credentials were not applied/restored narrowly\n");
    ++failures;
  }
  if (g_uid != 501 || g_ruid != 502 || g_svuid != 503 || g_rgid != 601 ||
      g_svgid != 602 || g_prison != (intptr_t)0x11113000 ||
      g_authid != UINT64_C(0x3800000000000001)) {
    fprintf(stderr, "FAIL: PS4 loader identity was not restored exactly\n");
    ++failures;
  }
  memset(full_caps, 0x5a, sizeof(full_caps));
  if (memcmp(g_caps, full_caps, sizeof(g_caps)) != 0) {
    fprintf(stderr, "FAIL: PS4 loader capabilities were not restored\n");
    ++failures;
  }

  /* A partial elevation must roll every loader credential back and leave the
   * lock usable for the next debugger request. */
  g_credential_write_calls = 0;
  g_fail_caps_write_once = true;
  if (memdbg_privilege_begin_ptrace(&ptrace_backup) == 0) {
    fprintf(stderr, "FAIL: injected ptrace credential failure was ignored\n");
    ++failures;
    (void)memdbg_privilege_end_ptrace(&ptrace_backup);
  }
  if (g_credential_write_calls != 16 || g_uid != 501 || g_ruid != 502 ||
      g_svuid != 503 || g_rgid != 601 || g_svgid != 602 ||
      g_prison != (intptr_t)0x11113000 ||
      g_authid != UINT64_C(0x3800000000000001) ||
      memcmp(g_caps, full_caps, sizeof(g_caps)) != 0) {
    fprintf(stderr, "FAIL: partial ptrace elevation was not rolled back\n");
    ++failures;
  }
  if (memdbg_privilege_begin_ptrace(&ptrace_backup) != 0 ||
      memdbg_privilege_end_ptrace(&ptrace_backup) != 0) {
    fprintf(stderr, "FAIL: ptrace credential lock remained poisoned\n");
    ++failures;
  }

  if (failures == 0)
    puts("PASS: PS4 GoldHEN loader credentials remain unchanged");
  return failures == 0 ? 0 : 1;
}
