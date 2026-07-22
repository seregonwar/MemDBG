/* PS4 kernel header stub for host-side privilege tests. */
#ifndef TESTS_PS4_KERNEL_H
#define TESTS_PS4_KERNEL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

extern const intptr_t KERNEL_ADDRESS_PRISON0;
extern const intptr_t KERNEL_ADDRESS_ROOTVNODE;

uint64_t kernel_getlong(intptr_t addr);
intptr_t kernel_get_proc_filedesc(pid_t pid);

int32_t kernel_set_ucred_uid(pid_t pid, uid_t uid);
int32_t kernel_set_ucred_ruid(pid_t pid, uid_t ruid);
int32_t kernel_set_ucred_svuid(pid_t pid, uid_t svuid);
int32_t kernel_set_ucred_rgid(pid_t pid, gid_t rgid);
int32_t kernel_set_ucred_svgid(pid_t pid, gid_t svgid);

intptr_t kernel_get_ucred_prison(int pid);
int32_t kernel_set_ucred_prison(int pid, intptr_t prison);

uint64_t kernel_get_ucred_authid(pid_t pid);
int32_t kernel_set_ucred_authid(pid_t pid, uint64_t authid);
int32_t kernel_get_ucred_caps(pid_t pid, uint8_t caps[16]);
int32_t kernel_set_ucred_caps(pid_t pid, const uint8_t caps[16]);
uint64_t kernel_get_ucred_attrs(pid_t pid);
int32_t kernel_set_ucred_attrs(pid_t pid, uint64_t attrs);

intptr_t kernel_get_proc_rootdir(pid_t pid);
int32_t kernel_set_proc_rootdir(pid_t pid, intptr_t vnode);
intptr_t kernel_get_proc_jaildir(pid_t pid);
int32_t kernel_set_proc_jaildir(pid_t pid, intptr_t vnode);

#endif /* TESTS_PS4_KERNEL_H */
