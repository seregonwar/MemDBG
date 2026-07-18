/*
 * MemDBG - Privilege helpers for jailbroken console payloads.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_PRIVILEGE_PRIVILEGE_H
#define MEMDBG_PRIVILEGE_PRIVILEGE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct memdbg_ucred_backup {
  uint64_t authid;
  uint8_t caps[16];
  uint64_t attrs;
  uid_t uid;
  uid_t ruid;
  uid_t svuid;
  gid_t rgid;
  gid_t svgid;
  uint32_t ngroups;
  bool     ngroups_valid;
  bool     fd_modified;
  intptr_t proc_rootdir;
  intptr_t proc_jaildir;
  intptr_t ucred_prison;
  intptr_t fd_rdir;
  intptr_t fd_jdir;
} memdbg_ucred_backup_t;

bool memdbg_privilege_supported(void);
int memdbg_privilege_operation_begin(void);
int memdbg_privilege_operation_end(void);
int memdbg_privilege_jailbreak_self(void);
int memdbg_privilege_begin_ptrace(memdbg_ucred_backup_t *backup);
int memdbg_privilege_end_ptrace(const memdbg_ucred_backup_t *backup);
int memdbg_privilege_elevate_target(pid_t pid, memdbg_ucred_backup_t *backup);
void memdbg_privilege_restore_target(pid_t pid,
                                     const memdbg_ucred_backup_t *backup);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PRIVILEGE_PRIVILEGE_H */
