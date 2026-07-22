/*
 * MemDBG - Privilege helpers for jailbroken console payloads.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/privilege/privilege.h"

#include "memdbg/core/memdbg_log.h"
#include "memdbg/pal/pal_kernel_fast.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#include <ps5/kernel.h>
#define MEMDBG_PRIVILEGE_HAS_CONSOLE 1
#define MEMDBG_PRIVILEGE_HAS_PS5 1
#define MEMDBG_PRIVILEGE_SYSTEM_AUTHID 0x4801000000000013ULL
#define MEMDBG_PRIVILEGE_PTRACE_AUTHID 0x4800000000010003ULL
#elif defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
#include <ps4/authid.h>
#include <ps4/kernel.h>
#define MEMDBG_PRIVILEGE_HAS_CONSOLE 1
#define MEMDBG_PRIVILEGE_HAS_PS5 0
#define MEMDBG_PRIVILEGE_SYSTEM_AUTHID ((uint64_t)SCE_AUTHID_SYSCORE)
#define MEMDBG_PRIVILEGE_PTRACE_AUTHID ((uint64_t)SCE_AUTHID_DECID)
#else
#define MEMDBG_PRIVILEGE_HAS_CONSOLE 0
#define MEMDBG_PRIVILEGE_HAS_PS5 0
#endif

bool memdbg_privilege_supported(void) {
#if MEMDBG_PRIVILEGE_HAS_CONSOLE
  return true;
#else
  return false;
#endif
}

#if MEMDBG_PRIVILEGE_HAS_CONSOLE

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>

static const uint8_t k_full_caps[16] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

#if !MEMDBG_PRIVILEGE_HAS_PS5
/* These are the same PS4 ucred offsets used by the SDK's
 * kernel_set_ucred_* helpers.  The SDK does not expose matching getters, so
 * copy the original values out before opening the temporary ptrace window. */
#define PS4_UCRED_UID_OFFSET   0x04
#define PS4_UCRED_RUID_OFFSET  0x08
#define PS4_UCRED_SVUID_OFFSET 0x0c
#define PS4_UCRED_RGID_OFFSET  0x14
#define PS4_UCRED_SVGID_OFFSET 0x18

static int privilege_ps4_backup_ids(pid_t pid,
                                    memdbg_ucred_backup_t *backup) {
  const intptr_t ucred = kernel_get_proc_ucred(pid);

  if (ucred == 0 ||
      kernel_copyout(ucred + PS4_UCRED_UID_OFFSET, &backup->uid,
                     sizeof(backup->uid)) != 0 ||
      kernel_copyout(ucred + PS4_UCRED_RUID_OFFSET, &backup->ruid,
                     sizeof(backup->ruid)) != 0 ||
      kernel_copyout(ucred + PS4_UCRED_SVUID_OFFSET, &backup->svuid,
                     sizeof(backup->svuid)) != 0 ||
      kernel_copyout(ucred + PS4_UCRED_RGID_OFFSET, &backup->rgid,
                     sizeof(backup->rgid)) != 0 ||
      kernel_copyout(ucred + PS4_UCRED_SVGID_OFFSET, &backup->svgid,
                     sizeof(backup->svgid)) != 0) {
    return -1;
  }

  backup->ucred_prison = kernel_get_ucred_prison(pid);
  return backup->ucred_prison != 0 ? 0 : -1;
}

static int privilege_ps4_set_ptrace_identity(
    pid_t pid, uid_t uid, uid_t ruid, uid_t svuid, gid_t rgid, gid_t svgid,
    intptr_t prison) {
  int failures = 0;

  failures += kernel_set_ucred_uid(pid, uid) != 0;
  failures += kernel_set_ucred_ruid(pid, ruid) != 0;
  failures += kernel_set_ucred_svuid(pid, svuid) != 0;
  failures += kernel_set_ucred_rgid(pid, rgid) != 0;
  failures += kernel_set_ucred_svgid(pid, svgid) != 0;
  failures += kernel_set_ucred_prison(pid, prison) != 0;
  return failures;
}
#endif

static pthread_once_t g_credential_lock_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_credential_lock;
static atomic_bool g_credential_state_poisoned = ATOMIC_VAR_INIT(false);
static atomic_bool g_self_privileged = ATOMIC_VAR_INIT(false);

bool memdbg_privilege_is_active(void) {
  return atomic_load_explicit(&g_self_privileged, memory_order_acquire);
}

static void credential_lock_init(void) {
  pthread_mutexattr_t attr;
  (void)pthread_mutexattr_init(&attr);
  (void)pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  (void)pthread_mutex_init(&g_credential_lock, &attr);
  (void)pthread_mutexattr_destroy(&attr);
}

int memdbg_privilege_operation_begin(void) {
  if (atomic_load_explicit(&g_credential_state_poisoned,
                           memory_order_acquire)) {
    errno = EPERM;
    return -1;
  }
  if (pthread_once(&g_credential_lock_once, credential_lock_init) != 0 ||
      pthread_mutex_lock(&g_credential_lock) != 0) {
    errno = EBUSY;
    return -1;
  }
  if (atomic_load_explicit(&g_credential_state_poisoned,
                           memory_order_acquire)) {
    (void)pthread_mutex_unlock(&g_credential_lock);
    errno = EPERM;
    return -1;
  }
#if MEMDBG_PRIVILEGE_HAS_PS5
  if (memdbg_kernel_external_begin() != 0) {
    (void)pthread_mutex_unlock(&g_credential_lock);
    errno = EBUSY;
    return -1;
  }
#endif
  return 0;
}

int memdbg_privilege_operation_end(void) {
#if MEMDBG_PRIVILEGE_HAS_PS5
  memdbg_kernel_external_end();
#endif
  if (pthread_mutex_unlock(&g_credential_lock) != 0) {
    errno = EBUSY;
    return -1;
  }
  return 0;
}

/* PS5 payloads own their process and use the SDK's dedicated vnode helper.
 * PS4 payloads run inside the GoldHEN loader and deliberately do not rewrite
 * the loader's persistent root/jail state (see jailbreak_self below). */
#if MEMDBG_PRIVILEGE_HAS_PS5
static bool pid_alive(pid_t pid) { return kill(pid, 0) == 0; }

static intptr_t privilege_root_vnode(void) {
  return kernel_get_root_vnode();
}
#endif

int memdbg_privilege_jailbreak_self(void) {
#if !MEMDBG_PRIVILEGE_HAS_PS5
  /* A PS4 ELF is hosted by GoldHEN's long-lived loader process (commonly PID
   * 46), which already exposes the mdbg kernel primitives used by the PAL.
   * Rewriting that shared process's auth ID, prison, and root/jail vnodes is
   * both unnecessary and unsafe: it changes the execution context used by
   * system notification and subsequent ELF launches.  The known-good PS4
   * payloads before the regression intentionally left this state untouched.
   * Temporary credential changes needed by ptrace remain in
   * begin/end_ptrace. */
  memdbg_log_write(MEMDBG_LOG_INFO,
                   "privilege: retaining GoldHEN loader credentials on PS4");
  return 0;
#else
  pid_t pid = getpid();
  uint8_t caps[16];
  int failures = 0;
  intptr_t rootv, fd;
  memdbg_ucred_backup_t backup;

  memset(caps, 0xff, sizeof(caps));
  memset(&backup, 0, sizeof(backup));

  /* Capture current state for rollback on partial failure */
  backup.authid = kernel_get_ucred_authid(pid);
  if (kernel_get_ucred_caps(pid, backup.caps) != 0) return -1;
  backup.attrs = kernel_get_ucred_attrs(pid);
#if MEMDBG_PRIVILEGE_HAS_PS5
  backup.uid   = kernel_get_ucred_uid(pid);
  backup.ruid  = kernel_get_ucred_ruid(pid);
  backup.svuid = kernel_get_ucred_svuid(pid);
  backup.rgid  = kernel_get_ucred_rgid(pid);
  backup.svgid = kernel_get_ucred_svgid(pid);
  backup.proc_rootdir = kernel_get_proc_rootdir(pid);
  backup.proc_jaildir = kernel_get_proc_jaildir(pid);
#else
  backup.uid = getuid();
  backup.ruid = backup.uid;
  backup.svuid = backup.uid;
  backup.rgid = getgid();
  backup.svgid = backup.rgid;
  backup.proc_rootdir = kernel_get_proc_rootdir(pid);
  backup.proc_jaildir = kernel_get_proc_jaildir(pid);
  backup.ucred_prison = kernel_get_ucred_prison(pid);
#endif

  /* Apply changes */
  failures += kernel_set_ucred_uid(pid, 0) != 0;
  failures += kernel_set_ucred_ruid(pid, 0) != 0;
  failures += kernel_set_ucred_svuid(pid, 0) != 0;
  failures += kernel_set_ucred_rgid(pid, 0) != 0;
  failures += kernel_set_ucred_svgid(pid, 0) != 0;
  failures +=
      kernel_set_ucred_authid(pid, MEMDBG_PRIVILEGE_SYSTEM_AUTHID) != 0;
  failures += kernel_set_ucred_caps(pid, caps) != 0;

  rootv = privilege_root_vnode();
  if (rootv != 0) {
    failures += kernel_set_proc_rootdir(pid, rootv) != 0;
    failures += kernel_set_proc_jaildir(pid, rootv) != 0;
    if (pid_alive(pid))
      fd = kernel_get_proc_filedesc(pid);
    else { fd = 0; failures++; }
#if MEMDBG_PRIVILEGE_HAS_PS5
    if (fd != 0) {
      backup.fd_rdir = (intptr_t)kernel_getlong(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR);
      backup.fd_jdir = (intptr_t)kernel_getlong(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR);
      backup.fd_modified = true;
      failures += kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, (uint64_t)rootv) != 0;
      failures += kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, (uint64_t)rootv) != 0;
    }
#else
    (void)fd;
    backup.ucred_prison = kernel_get_ucred_prison(pid);
    {
      intptr_t prison0 = privilege_prison0();
      if (prison0 != 0)
        failures += kernel_set_ucred_prison(pid, prison0) != 0;
    }
#endif
  } else {
    failures++;
  }

  if (failures != 0) {
    memdbg_privilege_restore_target(pid, &backup);
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "privilege: self escalation incomplete pid=%d failures=%d (rolled back)",
                     (int)pid, failures);
    return -1;
  }

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "privilege: payload escaped sandbox pid=%d root=0x%lx",
                   (int)pid, (unsigned long)rootv);
  atomic_store_explicit(&g_self_privileged, true, memory_order_release);
  return 0;
#endif
}

int memdbg_privilege_begin_ptrace(memdbg_ucred_backup_t *backup) {
  const pid_t pid = getpid();
  int failures = 0;

  if (backup == NULL) {
    errno = EINVAL;
    return -1;
  }
  memset(backup, 0, sizeof(*backup));

  if (memdbg_privilege_operation_begin() != 0) return -1;

  backup->authid = kernel_get_ucred_authid(pid);
  if (backup->authid == 0U ||
      kernel_get_ucred_caps(pid, backup->caps) != 0) {
    (void)memdbg_privilege_operation_end();
    errno = EPERM;
    return -1;
  }

#if !MEMDBG_PRIVILEGE_HAS_PS5
  if (KERNEL_ADDRESS_PRISON0 == 0 ||
      privilege_ps4_backup_ids(pid, backup) != 0) {
    (void)memdbg_privilege_operation_end();
    errno = EPERM;
    return -1;
  }

  /* FreeBSD checks prison membership and Unix credentials before reaching
   * Sony's auth-ID/capability gate in ptrace.  GoldHEN's ELF loader is a
   * shared process, so apply the traditional PS4 debugger identity only
   * while the credential lock is held and restore it immediately afterward. */
  failures += privilege_ps4_set_ptrace_identity(
      pid, 0, 0, 0, 0, 0, KERNEL_ADDRESS_PRISON0);
#endif
  failures +=
      kernel_set_ucred_authid(pid, MEMDBG_PRIVILEGE_PTRACE_AUTHID) != 0;
  failures += kernel_set_ucred_caps(pid, k_full_caps) != 0;

  if (failures != 0) {
    int restore_failures = 0;
    restore_failures += kernel_set_ucred_authid(pid, backup->authid) != 0;
    restore_failures += kernel_set_ucred_caps(pid, backup->caps) != 0;
#if !MEMDBG_PRIVILEGE_HAS_PS5
    restore_failures += privilege_ps4_set_ptrace_identity(
        pid, backup->uid, backup->ruid, backup->svuid, backup->rgid,
        backup->svgid, backup->ucred_prison);
#endif
    const bool restore_failed = restore_failures != 0;
    if (restore_failed)
      atomic_store_explicit(&g_credential_state_poisoned, true,
                            memory_order_release);
    (void)memdbg_privilege_operation_end();
    errno = restore_failed ? EIO : EPERM;
    return -1;
  }

  return 0;
}

int memdbg_privilege_end_ptrace(const memdbg_ucred_backup_t *backup) {
  const pid_t pid = getpid();
  int failures = 0;

  if (backup == NULL) {
    errno = EINVAL;
    return -1;
  }

  failures += kernel_set_ucred_authid(pid, backup->authid) != 0;
  failures += kernel_set_ucred_caps(pid, backup->caps) != 0;
#if !MEMDBG_PRIVILEGE_HAS_PS5
  failures += privilege_ps4_set_ptrace_identity(
      pid, backup->uid, backup->ruid, backup->svuid, backup->rgid,
      backup->svgid, backup->ucred_prison);
#endif
  if (failures != 0)
    atomic_store_explicit(&g_credential_state_poisoned, true,
                          memory_order_release);
  failures += memdbg_privilege_operation_end() != 0;
  if (failures != 0) {
    memdbg_log_write(MEMDBG_LOG_ERROR,
                     "privilege: failed to restore ptrace credentials pid=%d failures=%d",
                     (int)pid, failures);
    errno = EIO;
    return -1;
  }
  return 0;
}

int memdbg_privilege_elevate_target(pid_t pid, memdbg_ucred_backup_t *backup) {
#if !MEMDBG_PRIVILEGE_HAS_PS5
  (void)pid;
  if (backup != NULL) memset(backup, 0, sizeof(*backup));
  errno = ENOTSUP;
  return -1;
#else
  int failures = 0;
  intptr_t ucred;
  intptr_t rootv;

  if (pid <= 0 || backup == NULL) return -1;
  memset(backup, 0, sizeof(*backup));

  backup->authid = kernel_get_ucred_authid(pid);
  if (kernel_get_ucred_caps(pid, backup->caps) != 0) return -1;
  backup->attrs = kernel_get_ucred_attrs(pid);
  backup->uid   = kernel_get_ucred_uid(pid);
  backup->ruid  = kernel_get_ucred_ruid(pid);
  backup->svuid = kernel_get_ucred_svuid(pid);
  backup->rgid  = kernel_get_ucred_rgid(pid);
  backup->svgid = kernel_get_ucred_svgid(pid);
  backup->proc_rootdir = kernel_get_proc_rootdir(pid);
  backup->proc_jaildir = kernel_get_proc_jaildir(pid);
  backup->fd_rdir = 0;
  backup->fd_jdir = 0;

#if MEMDBG_PRIVILEGE_HAS_PS5
  if (pid_alive(pid))
    ucred = kernel_get_proc_ucred(pid);
  else { ucred = 0; failures++; }
  if (ucred != 0) {
    if (kernel_copyout(ucred + 0x10, &backup->ngroups,
                       sizeof(backup->ngroups)) == 0)
      backup->ngroups_valid = true;
  }
#else
  ucred = 0;
  backup->ucred_prison = kernel_get_ucred_prison(pid);
#endif

  failures += kernel_set_ucred_uid(pid, 0) != 0;
  failures += kernel_set_ucred_ruid(pid, 0) != 0;
  failures += kernel_set_ucred_svuid(pid, 0) != 0;
  failures += kernel_set_ucred_rgid(pid, 0) != 0;
  failures += kernel_set_ucred_svgid(pid, 0) != 0;

#if MEMDBG_PRIVILEGE_HAS_PS5
  if (ucred != 0) {
    uint32_t zero = 0;
    failures += kernel_copyin(&zero, ucred + 0x10, sizeof(zero)) != 0;
  }
#endif

  failures +=
      kernel_set_ucred_authid(pid, MEMDBG_PRIVILEGE_SYSTEM_AUTHID) != 0;
  failures += kernel_set_ucred_caps(pid, k_full_caps) != 0;
  failures += kernel_set_ucred_attrs(pid, 0x80) != 0;

  rootv = privilege_root_vnode();
  if (rootv != 0) {
    intptr_t fd;

    failures += kernel_set_proc_rootdir(pid, rootv) != 0;
    failures += kernel_set_proc_jaildir(pid, rootv) != 0;
    if (pid_alive(pid))
      fd = kernel_get_proc_filedesc(pid);
    else { fd = 0; failures++; }
#if MEMDBG_PRIVILEGE_HAS_PS5
    if (fd != 0) {
      backup->fd_rdir = (intptr_t)kernel_getlong(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR);
      backup->fd_jdir = (intptr_t)kernel_getlong(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR);
      backup->fd_modified = true;
      failures += kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, (uint64_t)rootv) != 0;
      failures += kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, (uint64_t)rootv) != 0;
    }
#endif
  } else {
    failures++;
  }

  if (failures != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "privilege: target elevation failed pid=%d failures=%d",
                     (int)pid, failures);
    memdbg_privilege_restore_target(pid, backup);
    return -1;
  }

  return 0;
#endif
}

void memdbg_privilege_restore_target(pid_t pid,
                                     const memdbg_ucred_backup_t *backup) {
  if (pid <= 0 || backup == NULL) return;

  (void)kernel_set_ucred_authid(pid, backup->authid);
  (void)kernel_set_ucred_caps(pid, backup->caps);
  (void)kernel_set_ucred_attrs(pid, backup->attrs);
  (void)kernel_set_ucred_uid(pid, backup->uid);
  (void)kernel_set_ucred_ruid(pid, backup->ruid);
  (void)kernel_set_ucred_svuid(pid, backup->svuid);
  (void)kernel_set_ucred_rgid(pid, backup->rgid);
  (void)kernel_set_ucred_svgid(pid, backup->svgid);
  if (backup->proc_rootdir != 0)
    (void)kernel_set_proc_rootdir(pid, backup->proc_rootdir);
  if (backup->proc_jaildir != 0)
    (void)kernel_set_proc_jaildir(pid, backup->proc_jaildir);
#if !MEMDBG_PRIVILEGE_HAS_PS5
  if (backup->ucred_prison != 0)
    (void)kernel_set_ucred_prison(pid, backup->ucred_prison);
#endif
#if MEMDBG_PRIVILEGE_HAS_PS5
  intptr_t ucred;
  if (backup->fd_modified) {
    intptr_t fd = 0;
    if (pid_alive(pid))
      fd = kernel_get_proc_filedesc(pid);
    if (fd != 0) {
      kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, (uint64_t)backup->fd_rdir);
      kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, (uint64_t)backup->fd_jdir);
    }
  }

  if (backup->ngroups_valid && pid_alive(pid)) {
    ucred = kernel_get_proc_ucred(pid);
    if (ucred != 0)
      (void)kernel_copyin(&backup->ngroups, ucred + 0x10,
                          sizeof(backup->ngroups));
  }
#endif
}

#else

int memdbg_privilege_operation_begin(void) { return 0; }
int memdbg_privilege_operation_end(void) { return 0; }

bool memdbg_privilege_is_active(void) { return false; }

int memdbg_privilege_jailbreak_self(void) { return 0; }

int memdbg_privilege_begin_ptrace(memdbg_ucred_backup_t *backup) {
  if (backup == NULL) {
    errno = EINVAL;
    return -1;
  }
  memset(backup, 0, sizeof(*backup));
  return 0;
}

int memdbg_privilege_end_ptrace(const memdbg_ucred_backup_t *backup) {
  if (backup == NULL) {
    errno = EINVAL;
    return -1;
  }
  return 0;
}

int memdbg_privilege_elevate_target(pid_t pid, memdbg_ucred_backup_t *backup) {
  (void)pid;
  if (backup != NULL) memset(backup, 0, sizeof(*backup));
  return 0;
}

void memdbg_privilege_restore_target(pid_t pid,
                                     const memdbg_ucred_backup_t *backup) {
  (void)pid;
  (void)backup;
}

#endif
