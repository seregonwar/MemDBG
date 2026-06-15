/*
 * MemDBG - Privilege helpers for jailbroken console payloads.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/privilege/privilege.h"

#include "memdbg/core/memdbg_log.h"

#include <string.h>
#include <unistd.h>

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#include <ps5/kernel.h>
#define MEMDBG_PRIVILEGE_HAS_PS5 1
#else
#define MEMDBG_PRIVILEGE_HAS_PS5 0
#endif

#define MEMDBG_PRIVILEGE_AUTHID 0x4801000000000013ULL

bool memdbg_privilege_supported(void) {
#if MEMDBG_PRIVILEGE_HAS_PS5
  return true;
#else
  return false;
#endif
}

#if MEMDBG_PRIVILEGE_HAS_PS5

static const uint8_t k_full_caps[16] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

int memdbg_privilege_jailbreak_self(void) {
  pid_t pid = getpid();
  uint8_t caps[16];
  int failures = 0;
  intptr_t rootv;

  memset(caps, 0xff, sizeof(caps));

  failures += kernel_set_ucred_uid(pid, 0) != 0;
  failures += kernel_set_ucred_ruid(pid, 0) != 0;
  failures += kernel_set_ucred_svuid(pid, 0) != 0;
  failures += kernel_set_ucred_rgid(pid, 0) != 0;
  failures += kernel_set_ucred_svgid(pid, 0) != 0;
  failures += kernel_set_ucred_authid(pid, MEMDBG_PRIVILEGE_AUTHID) != 0;
  failures += kernel_set_ucred_caps(pid, caps) != 0;

  rootv = kernel_get_root_vnode();
  if (rootv != 0) {
    intptr_t fd;

    failures += kernel_set_proc_rootdir(pid, rootv) != 0;
    failures += kernel_set_proc_jaildir(pid, rootv) != 0;
    fd = kernel_get_proc_filedesc(pid);
    if (fd != 0) {
      kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, rootv);
      kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, rootv);
    }
  } else {
    failures++;
  }

  if (failures != 0) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "privilege: self escalation incomplete pid=%d failures=%d",
                     (int)pid, failures);
    return -1;
  }

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "privilege: payload escaped sandbox pid=%d root=0x%lx",
                   (int)pid, (unsigned long)rootv);
  return 0;
}

int memdbg_privilege_elevate_target(pid_t pid, memdbg_ucred_backup_t *backup) {
  int failures = 0;
  intptr_t ucred;
  intptr_t rootv;

  if (pid <= 0 || backup == NULL) return -1;
  memset(backup, 0, sizeof(*backup));

  backup->authid = kernel_get_ucred_authid(pid);
  if (kernel_get_ucred_caps(pid, backup->caps) != 0) return -1;
  backup->attrs = kernel_get_ucred_attrs(pid);
  backup->uid = kernel_get_ucred_uid(pid);
  backup->ruid = kernel_get_ucred_ruid(pid);
  backup->svuid = kernel_get_ucred_svuid(pid);
  backup->rgid = kernel_get_ucred_rgid(pid);
  backup->svgid = kernel_get_ucred_svgid(pid);
  backup->proc_rootdir = kernel_get_proc_rootdir(pid);
  backup->proc_jaildir = kernel_get_proc_jaildir(pid);
  backup->fd_rdir = 0;
  backup->fd_jdir = 0;

  ucred = kernel_get_proc_ucred(pid);
  if (ucred != 0)
    (void)kernel_copyout(ucred + 0x10, &backup->ngroups,
                         sizeof(backup->ngroups));

  failures += kernel_set_ucred_uid(pid, 0) != 0;
  failures += kernel_set_ucred_ruid(pid, 0) != 0;
  failures += kernel_set_ucred_svuid(pid, 0) != 0;
  failures += kernel_set_ucred_rgid(pid, 0) != 0;
  failures += kernel_set_ucred_svgid(pid, 0) != 0;

  if (ucred != 0) {
    uint32_t zero = 0;
    failures += kernel_copyin(&zero, ucred + 0x10, sizeof(zero)) != 0;
  }

  failures += kernel_set_ucred_authid(pid, MEMDBG_PRIVILEGE_AUTHID) != 0;
  failures += kernel_set_ucred_caps(pid, k_full_caps) != 0;
  failures += kernel_set_ucred_attrs(pid, 0x80) != 0;

  rootv = kernel_get_root_vnode();
  if (rootv != 0) {
    intptr_t fd;

    failures += kernel_set_proc_rootdir(pid, rootv) != 0;
    failures += kernel_set_proc_jaildir(pid, rootv) != 0;
    fd = kernel_get_proc_filedesc(pid);
    if (fd != 0) {
      backup->fd_rdir = kernel_getlong(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR);
      backup->fd_jdir = kernel_getlong(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR);
      kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, rootv);
      kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, rootv);
    }
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
}

void memdbg_privilege_restore_target(pid_t pid,
                                     const memdbg_ucred_backup_t *backup) {
  intptr_t ucred;

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
  if (backup->fd_rdir != 0 || backup->fd_jdir != 0) {
    intptr_t fd = kernel_get_proc_filedesc(pid);
    if (fd != 0) {
      if (backup->fd_rdir != 0)
        kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, backup->fd_rdir);
      if (backup->fd_jdir != 0)
        kernel_setlong(fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, backup->fd_jdir);
    }
  }

  ucred = kernel_get_proc_ucred(pid);
  if (ucred != 0)
    (void)kernel_copyin(&backup->ngroups, ucred + 0x10,
                        sizeof(backup->ngroups));
}

#else

int memdbg_privilege_jailbreak_self(void) { return 0; }

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
