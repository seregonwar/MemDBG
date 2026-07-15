/*
 * memDBG - PAL: Cross-platform process listing / maps / info.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/pal/pal_process.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(PLATFORM_PS4) || defined(PLATFORM_PS5) || defined(PS4) ||          \
    defined(PS5) || defined(__ORBIS__) || defined(__PROSPERO__)
#define MEMDBG_PROCESS_CONSOLE 1
#endif

#if defined(__linux__) || defined(__APPLE__) ||                                  \
    (defined(__FreeBSD__) && !defined(MEMDBG_PROCESS_CONSOLE))
#define MEMDBG_PROCESS_HOST_ENUMERATION 1
#endif

#if defined(__FreeBSD__) || defined(MEMDBG_PROCESS_CONSOLE)
#define MEMDBG_PROCESS_BSD_SYSCTL 1
#endif

#if defined(__APPLE__) || defined(MEMDBG_PROCESS_BSD_SYSCTL)
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#endif

/* KERN_PROC_VMMAP records are much larger than the compact wire entries.
 * Games with several thousand mappings can legitimately exceed 4 MiB of raw
 * sysctl data while producing a sub-megabyte response. Keep allocation
 * bounded, but leave enough headroom for current PS5 titles. */
#define MEMDBG_SYSCTL_MAX_BYTES (32U * 1024U * 1024U)

/* ---- Helpers shared across platforms ---- */

#if defined(MEMDBG_PROCESS_HOST_ENUMERATION) || defined(MEMDBG_PROCESS_BSD_SYSCTL)
static pal_process_entry_t *proc_append(pal_process_list_t *list, int pid, int ppid, const char *name) {
  size_t nc = list->count + 1U;
  pal_process_entry_t *next = (pal_process_entry_t *)realloc(list->entries, nc * sizeof(*list->entries));
  if (next == NULL) return NULL;
  list->entries = next;
  memset(&list->entries[list->count], 0, sizeof(list->entries[list->count]));
  list->entries[list->count].pid = pid;
  list->entries[list->count].ppid = ppid;
  (void)snprintf(list->entries[list->count].name, sizeof(list->entries[list->count].name),
                 "%s", name && name[0] ? name : "unknown");
  list->count = nc;
  return &list->entries[list->count - 1U];
}
#endif

#if defined(__linux__) || defined(MEMDBG_PROCESS_BSD_SYSCTL)
static pal_map_entry_t *map_append(pal_map_list_t *list, uint64_t start, uint64_t end,
                                   uint32_t prot, uint32_t flags, const char *name) {
  size_t nc = list->count + 1U;
  pal_map_entry_t *next = (pal_map_entry_t *)realloc(list->entries, nc * sizeof(*list->entries));
  if (next == NULL) return NULL;
  list->entries = next;
  memset(&list->entries[list->count], 0, sizeof(list->entries[list->count]));
  list->entries[list->count].start      = start;
  list->entries[list->count].end        = end;
  list->entries[list->count].protection = prot;
  list->entries[list->count].flags      = flags;
  if (name) (void)snprintf(list->entries[list->count].name,
                           sizeof(list->entries[list->count].name), "%s", name);
  list->count = nc;
  return &list->entries[list->count - 1U];
}
#endif

/* ========================================================================
 *  Linux  —  /proc
 * ======================================================================== */
#if defined(__linux__)

static bool str_is_digits(const char *s) {
  if (!s || !*s) return false;
  for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
    if (!isdigit(*p)) return false;
  return true;
}

static void read_comm(int pid, char *out, size_t out_size) {
  char path[64]; FILE *fp;
  out[0] = '\0';
  (void)snprintf(path, sizeof(path), "/proc/%d/comm", pid);
  fp = fopen(path, "r");
  if (!fp) { (void)snprintf(out, out_size, "%d", pid); return; }
  if (fgets(out, (int)out_size, fp)) out[strcspn(out, "\r\n")] = '\0';
  (void)fclose(fp);
}

memdbg_status_t pal_process_list(pal_process_list_t *out) {
  memset(out, 0, sizeof(*out));
  DIR *d = opendir("/proc");
  if (!d) return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  struct dirent *ent;
  while ((ent = readdir(d))) {
    if (!str_is_digits(ent->d_name)) continue;
    int pid = atoi(ent->d_name);
    if (pid <= 1) continue;
    char name[64];
    read_comm(pid, name, sizeof(name));
    /* Read PPID from /proc/<pid>/stat (4th field). */
    int ppid = 0;
    {
      char stat_path[64];
      (void)snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
      FILE *sfp = fopen(stat_path, "r");
      if (sfp) {
        char stat_line[512];
        if (fgets(stat_line, sizeof(stat_line), sfp)) {
          /* Format: pid (comm) state ppid ...
             Skip past the comm field (enclosed in parentheses). */
          char *rp = strrchr(stat_line, ')');
          if (rp) sscanf(rp + 2, "%*c %d", &ppid);
        }
        fclose(sfp);
      }
    }
    if (!proc_append(out, pid, ppid, name)) { closedir(d); pal_process_list_free(out); return MEMDBG_ERR_NOMEM; }
  }
  closedir(d);
  return MEMDBG_OK;
}

memdbg_status_t pal_process_maps(int pid, pal_map_list_t *out) {
  memset(out, 0, sizeof(*out));
  char path[64], line[512];
  (void)snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *fp = fopen(path, "r");
  if (!fp) return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  while (fgets(line, sizeof(line), fp)) {
    unsigned long long s = 0, e = 0;
    char perms[8] = "", name[128] = "";
    uint32_t prot = 0;
    int nf = sscanf(line, "%llx-%llx %7s %*s %*s %*s %127[^\n]", &s, &e, perms, name);
    if (nf < 3) continue;
    if (perms[0] == 'r') prot |= 1U;
    if (perms[1] == 'w') prot |= 2U;
    if (perms[2] == 'x') prot |= 4U;
    if (!map_append(out, (uint64_t)s, (uint64_t)e, prot, 0U, nf == 4 ? name : ""))
      { fclose(fp); pal_process_maps_free(out); return MEMDBG_ERR_NOMEM; }
  }
  fclose(fp);
  return MEMDBG_OK;
}

memdbg_status_t pal_process_path(int pid, char *out, size_t out_size) {
  char link[64];
  out[0] = '\0';
  (void)snprintf(link, sizeof(link), "/proc/%d/exe", pid);
  ssize_t n = readlink(link, out, out_size - 1U);
  if (n > 0) out[n] = '\0';
  return MEMDBG_OK;
}

void pal_process_list_free(pal_process_list_t *l) { if (l) { free(l->entries); memset(l, 0, sizeof(*l)); } }
void pal_process_maps_free(pal_map_list_t *l)    { if (l) { free(l->entries); memset(l, 0, sizeof(*l)); } }

/* ========================================================================
 *  macOS  —  sysctl KERN_PROC_ALL
 * ======================================================================== */
#elif defined(__APPLE__)

memdbg_status_t pal_process_list(pal_process_list_t *out) {
  memset(out, 0, sizeof(*out));
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
  size_t len = 0;
  if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) return MEMDBG_ERR_IO;
  struct kinfo_proc *procs = (struct kinfo_proc *)malloc(len);
  if (!procs) return MEMDBG_ERR_NOMEM;
  if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) { free(procs); return MEMDBG_ERR_IO; }
  size_t n = len / sizeof(procs[0]);
  for (size_t i = 0; i < n; ++i) {
    int ppid = procs[i].kp_eproc.e_ppid;
    if (!proc_append(out, procs[i].kp_proc.p_pid, ppid, procs[i].kp_proc.p_comm))
      { free(procs); pal_process_list_free(out); return MEMDBG_ERR_NOMEM; }
  }
  free(procs);
  return MEMDBG_OK;
}

memdbg_status_t pal_process_maps(int pid, pal_map_list_t *out) {
  (void)pid; memset(out, 0, sizeof(*out));
  return MEMDBG_ERR_UNSUPPORTED; /* macOS has no /proc/pid/maps — use vmmap or mach_vm_region */
}

memdbg_status_t pal_process_path(int pid, char *out, size_t out_size) {
  (void)pid; (void)out_size; if (out != NULL) out[0] = '\0';
  return MEMDBG_ERR_UNSUPPORTED;
}

void pal_process_list_free(pal_process_list_t *l) { if (l) { free(l->entries); memset(l, 0, sizeof(*l)); } }
void pal_process_maps_free(pal_map_list_t *l)    { if (l) { free(l->entries); memset(l, 0, sizeof(*l)); } }

/* ========================================================================
 *  FreeBSD / PS4 / PS5  —  sysctl KERN_PROC_PROC + KERN_PROC_VMMAP
 * ======================================================================== */
#elif defined(MEMDBG_PROCESS_BSD_SYSCTL)

static bool bsd_record_has_field(size_t record_size, size_t field_offset,
                                 size_t field_size) {
  return record_size >= field_offset &&
         record_size - field_offset >= field_size;
}

static size_t bsd_record_field_bytes(size_t record_size, size_t field_offset,
                                     size_t field_size) {
  if (record_size <= field_offset) return 0U;
  size_t available = record_size - field_offset;
  return available < field_size ? available : field_size;
}

static void copy_record_string(char *dst, size_t dst_size, const char *src,
                               size_t src_size) {
  if (dst == NULL || dst_size == 0U) return;
  dst[0] = '\0';
  if (src == NULL || src_size == 0U) return;

  size_t len = 0U;
  while (len < src_size && src[len] != '\0' && len + 1U < dst_size) {
    dst[len] = src[len];
    len++;
  }
  dst[len] = '\0';
}

static void bsd_copy_process_name(char *dst, size_t dst_size,
                                  const struct kinfo_proc *proc,
                                  size_t record_size) {
  size_t bytes = bsd_record_field_bytes(
      record_size, offsetof(struct kinfo_proc, ki_comm), sizeof(proc->ki_comm));
  copy_record_string(dst, dst_size, bytes != 0U ? proc->ki_comm : NULL, bytes);
  if (dst != NULL && dst[0] != '\0') {
    return;
  }

  bytes = bsd_record_field_bytes(record_size,
                                 offsetof(struct kinfo_proc, ki_tdname),
                                 sizeof(proc->ki_tdname));
  copy_record_string(dst, dst_size, bytes != 0U ? proc->ki_tdname : NULL,
                     bytes);
  if (dst != NULL && dst[0] == '\0') {
    (void)snprintf(dst, dst_size, "%s", "unknown");
  }
}

memdbg_status_t pal_process_list(pal_process_list_t *out) {
  memset(out, 0, sizeof(*out));
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
  size_t len = 0;
  if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) return MEMDBG_ERR_IO;
  if (len == 0U) return MEMDBG_OK;
  if (len > MEMDBG_SYSCTL_MAX_BYTES) return MEMDBG_ERR_OVERFLOW;
  unsigned char *buf = (unsigned char *)malloc(len);
  if (!buf) return MEMDBG_ERR_NOMEM;
  if (sysctl(mib, 4, buf, &len, NULL, 0) != 0) { free(buf); return MEMDBG_ERR_IO; }
  if (len > MEMDBG_SYSCTL_MAX_BYTES) { free(buf); return MEMDBG_ERR_OVERFLOW; }

  for (size_t off = 0U; off + sizeof(int) <= len;) {
    struct kinfo_proc *proc = (struct kinfo_proc *)(void *)(buf + off);
    size_t record_size = proc->ki_structsize > 0
                             ? (size_t)proc->ki_structsize
                             : sizeof(*proc);
    if (record_size < sizeof(int) || off + record_size > len) break;
    if (bsd_record_has_field(record_size, offsetof(struct kinfo_proc, ki_pid),
                             sizeof(proc->ki_pid)) &&
        proc->ki_pid > 1) {
      char name[64];
      bsd_copy_process_name(name, sizeof(name), proc, record_size);
      int ppid = bsd_record_has_field(record_size,
                     offsetof(struct kinfo_proc, ki_ppid),
                     sizeof(proc->ki_ppid)) ? (int)proc->ki_ppid : 0;
      if (!proc_append(out, proc->ki_pid, ppid, name))
        { free(buf); pal_process_list_free(out); return MEMDBG_ERR_NOMEM; }
    }
    off += record_size;
  }
  free(buf);
  return MEMDBG_OK;
}

memdbg_status_t pal_process_maps(int pid, pal_map_list_t *out) {
  memset(out, 0, sizeof(*out));
#ifdef KERN_PROC_VMMAP
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid};
  size_t len = 0;
  if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) return MEMDBG_ERR_IO;
  if (len == 0U) return MEMDBG_OK;
  if (len > MEMDBG_SYSCTL_MAX_BYTES) return MEMDBG_ERR_OVERFLOW;
  unsigned char *buf = (unsigned char *)malloc(len);
  if (!buf) return MEMDBG_ERR_NOMEM;
  if (sysctl(mib, 4, buf, &len, NULL, 0) != 0) { free(buf); return MEMDBG_ERR_IO; }
  if (len > MEMDBG_SYSCTL_MAX_BYTES) { free(buf); return MEMDBG_ERR_OVERFLOW; }

  for (size_t off = 0U; off + sizeof(int) <= len;) {
    struct kinfo_vmentry *entry = (struct kinfo_vmentry *)(void *)(buf + off);
    size_t record_size = entry->kve_structsize > 0
                             ? (size_t)entry->kve_structsize
                             : sizeof(*entry);
    if (record_size < sizeof(int) || off + record_size > len) break;
    if (!bsd_record_has_field(record_size, offsetof(struct kinfo_vmentry, kve_end),
                              sizeof(entry->kve_end))) {
      break;
    }

    uint32_t prot = 0;
    uint32_t flags = bsd_record_has_field(
                         record_size, offsetof(struct kinfo_vmentry, kve_flags),
                         sizeof(entry->kve_flags))
                         ? (uint32_t)entry->kve_flags
                         : 0U;
    int protection =
        bsd_record_has_field(record_size,
                             offsetof(struct kinfo_vmentry, kve_protection),
                             sizeof(entry->kve_protection))
            ? entry->kve_protection
            : 0;
#  ifdef KVME_PROT_READ
    if (protection & KVME_PROT_READ)  prot |= 1U;
    if (protection & KVME_PROT_WRITE) prot |= 2U;
    if (protection & KVME_PROT_EXEC)  prot |= 4U;
#  else
    prot = (uint32_t)protection;
#  endif
    char path[64];
    size_t path_bytes = bsd_record_field_bytes(
        record_size, offsetof(struct kinfo_vmentry, kve_path),
        sizeof(entry->kve_path));
    copy_record_string(path, sizeof(path),
                       path_bytes != 0U ? entry->kve_path : NULL, path_bytes);
    if (entry->kve_end > entry->kve_start &&
        !map_append(out, (uint64_t)entry->kve_start, (uint64_t)entry->kve_end,
                    prot, flags, path))
      { free(buf); pal_process_maps_free(out); return MEMDBG_ERR_NOMEM; }
    off += record_size;
  }
  free(buf);
  return MEMDBG_OK;
#else
  (void)pid; return MEMDBG_ERR_UNSUPPORTED;
#endif
}

memdbg_status_t pal_process_path(int pid, char *out, size_t out_size) {
  if (out == NULL || out_size == 0U) return MEMDBG_ERR_PARAM;
  out[0] = '\0';
#if defined(MEMDBG_PROCESS_CONSOLE)
  /*
   * On retail console shells, KERN_PROC_PATHNAME can emit noisy
   * "kern.proc.pathname is not approved" system-log entries even when the
   * caller only needs best-effort process info. Console callers enrich the
   * path from KERN_PROC_VMMAP below, which is already used for maps/title IDs.
   */
  (void)pid;
  return MEMDBG_ERR_UNSUPPORTED;
#elif defined(KERN_PROC_PATHNAME)
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid};
  size_t len = out_size;
  if (sysctl(mib, 4, out, &len, NULL, 0) != 0) out[0] = '\0';
#else
  (void)pid;
#endif
  return MEMDBG_OK;
}

void pal_process_list_free(pal_process_list_t *l) { if (l) { free(l->entries); memset(l, 0, sizeof(*l)); } }
void pal_process_maps_free(pal_map_list_t *l)    { if (l) { free(l->entries); memset(l, 0, sizeof(*l)); } }

/* ========================================================================
 *  Other  —  unsupported
 * ======================================================================== */
#else

memdbg_status_t pal_process_list(pal_process_list_t *out) {
  memset(out, 0, sizeof(*out)); return MEMDBG_ERR_UNSUPPORTED; }
memdbg_status_t pal_process_maps(int pid, pal_map_list_t *out) {
  (void)pid; memset(out, 0, sizeof(*out)); return MEMDBG_ERR_UNSUPPORTED; }
memdbg_status_t pal_process_path(int pid, char *out, size_t out_size) {
  (void)pid; (void)out_size; if (out != NULL) out[0] = '\0'; return MEMDBG_ERR_UNSUPPORTED; }
void pal_process_list_free(pal_process_list_t *l) { if (l) { free(l->entries); memset(l, 0, sizeof(*l)); } }
void pal_process_maps_free(pal_map_list_t *l)    { if (l) { free(l->entries); memset(l, 0, sizeof(*l)); } }

#endif
