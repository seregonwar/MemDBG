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
#include <pthread.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#endif

/* KERN_PROC_VMMAP records are much larger than the compact wire entries.
 * Keep process enumeration bounded separately from VM maps: titles with about
 * 11,000 mappings can exceed 32 MiB of raw PS5 sysctl data while still fitting
 * in the compact protocol response. */
#define MEMDBG_PROCESS_SYSCTL_MAX_BYTES (32U * 1024U * 1024U)
#define MEMDBG_VMMAP_SYSCTL_MAX_BYTES   (64U * 1024U * 1024U)

/* ---- Helpers shared across platforms ---- */

const char *pal_map_type_name(uint32_t type) {
  switch (type) {
  case MEMDBG_MAP_TYPE_NONE: return "untyped";
  case MEMDBG_MAP_TYPE_DEFAULT: return "default";
  case MEMDBG_MAP_TYPE_VNODE: return "file";
  case MEMDBG_MAP_TYPE_SWAP: return "swap";
  case MEMDBG_MAP_TYPE_DEVICE: return "device";
  case MEMDBG_MAP_TYPE_PHYSICAL: return "physical";
  case MEMDBG_MAP_TYPE_DEAD: return "dead";
  case MEMDBG_MAP_TYPE_SCATTER_GATHER: return "scatter/gather";
  case MEMDBG_MAP_TYPE_MANAGED_DEVICE: return "managed device";
  default: return "unknown";
  }
}

uint32_t pal_map_pack_flags(uint32_t native_flags, uint32_t type) {
  return (native_flags & MEMDBG_MAP_FLAG_NATIVE_MASK) |
         ((type & 0xffU) << MEMDBG_MAP_FLAG_TYPE_SHIFT);
}

void pal_map_format_name(char *out, size_t out_size, const char *native_name,
                         uint32_t type) {
  if (out == NULL || out_size == 0U) return;
  if (native_name != NULL && native_name[0] != '\0') {
    (void)snprintf(out, out_size, "%s", native_name);
    return;
  }
  (void)snprintf(out, out_size, "[%s]", pal_map_type_name(type));
}

#if defined(MEMDBG_PROCESS_HOST_ENUMERATION) || defined(MEMDBG_PROCESS_BSD_SYSCTL)
static pal_process_entry_t *proc_append(pal_process_list_t *list, int pid, int ppid, const char *name) {
  if (list->count == list->capacity) {
    size_t next_capacity = list->capacity == 0U ? 64U : list->capacity * 2U;
    if (next_capacity <= list->capacity ||
        next_capacity > SIZE_MAX / sizeof(*list->entries))
      return NULL;
    pal_process_entry_t *next = (pal_process_entry_t *)realloc(
        list->entries, next_capacity * sizeof(*list->entries));
    if (next == NULL) return NULL;
    list->entries = next;
    list->capacity = next_capacity;
  }
  memset(&list->entries[list->count], 0, sizeof(list->entries[list->count]));
  list->entries[list->count].pid = pid;
  list->entries[list->count].ppid = ppid;
  (void)snprintf(list->entries[list->count].name, sizeof(list->entries[list->count].name),
                 "%s", name && name[0] ? name : "unknown");
  list->count++;
  return &list->entries[list->count - 1U];
}
#endif

#if defined(__linux__) || defined(MEMDBG_PROCESS_BSD_SYSCTL)
static pal_map_entry_t *map_append(pal_map_list_t *list, uint64_t start, uint64_t end,
                                   uint32_t prot, uint32_t flags, uint32_t type,
                                   const char *name) {
  if (list->count == list->capacity) {
    size_t next_capacity = list->capacity == 0U ? 64U : list->capacity * 2U;
    if (next_capacity <= list->capacity ||
        next_capacity > SIZE_MAX / sizeof(*list->entries)) {
      return NULL;
    }
    pal_map_entry_t *next = (pal_map_entry_t *)realloc(
        list->entries, next_capacity * sizeof(*list->entries));
    if (next == NULL) return NULL;
    list->entries = next;
    list->capacity = next_capacity;
  }
  memset(&list->entries[list->count], 0, sizeof(list->entries[list->count]));
  list->entries[list->count].start      = start;
  list->entries[list->count].end        = end;
  list->entries[list->count].protection = prot;
  list->entries[list->count].flags = pal_map_pack_flags(flags, type);
  pal_map_format_name(list->entries[list->count].name,
                      sizeof(list->entries[list->count].name), name, type);
  list->count++;
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
    const char *native_name = nf == 4 ? name : "";
    const uint32_t type =
        native_name[0] == '/' ? MEMDBG_MAP_TYPE_VNODE
                              : MEMDBG_MAP_TYPE_DEFAULT;
    if (!map_append(out, (uint64_t)s, (uint64_t)e, prot, 0U, type, native_name))
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

/* Sony's KERN_PROC snapshot path is not reliably re-entrant across payload
 * threads. Four frontend roles (and GUI plugins) can legitimately request a
 * list at once, so serialize only the two sysctl calls that create the short
 * process snapshot. Maps and memory I/O remain fully parallel. */
static pthread_mutex_t g_process_sysctl_mutex = PTHREAD_MUTEX_INITIALIZER;

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
  unsigned char *buf = NULL;
  memdbg_status_t status = MEMDBG_ERR_IO;

  (void)pthread_mutex_lock(&g_process_sysctl_mutex);
  /* The process set may grow between the size query and the copy. Reserve
     slack and retry ENOMEM instead of treating a normal race as fatal. */
  for (unsigned int attempt = 0U; attempt < 3U; ++attempt) {
    len = 0U;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) break;
    if (len == 0U) {
      status = MEMDBG_OK;
      break;
    }
    if (len > MEMDBG_PROCESS_SYSCTL_MAX_BYTES) {
      status = MEMDBG_ERR_OVERFLOW;
      break;
    }
    size_t slack = len / 4U + 4096U;
    if (slack > MEMDBG_PROCESS_SYSCTL_MAX_BYTES - len)
      slack = MEMDBG_PROCESS_SYSCTL_MAX_BYTES - len;
    size_t capacity = len + slack;
    /* Some Sony sysctl implementations do not always shrink oldlenp to the
     * bytes written. Zero the reserved slack so a conservative returned
     * length cannot expose garbage as a synthetic kinfo record. */
    buf = (unsigned char *)calloc(1U, capacity);
    if (buf == NULL) {
      status = MEMDBG_ERR_NOMEM;
      break;
    }
    len = capacity;
    if (sysctl(mib, 4, buf, &len, NULL, 0) == 0) {
      status = len <= capacity ? MEMDBG_OK : MEMDBG_ERR_OVERFLOW;
      break;
    }
    free(buf);
    buf = NULL;
    if (errno != ENOMEM) break;
  }
  (void)pthread_mutex_unlock(&g_process_sysctl_mutex);
  if (status != MEMDBG_OK) {
    free(buf);
    return status;
  }
  if (buf == NULL || len == 0U) {
    free(buf);
    return MEMDBG_OK;
  }

  for (size_t off = 0U; off + sizeof(int) <= len;) {
    struct kinfo_proc *proc = (struct kinfo_proc *)(void *)(buf + off);
    size_t record_size = proc->ki_structsize > 0
                             ? (size_t)proc->ki_structsize
                             : sizeof(*proc);
    if (record_size < sizeof(int) || record_size > len - off) break;
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
      if (out->count > 4096U) {
        free(buf);
        pal_process_list_free(out);
        return MEMDBG_ERR_OVERFLOW;
      }
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
  unsigned char *buf = NULL;
  memdbg_status_t snapshot_status = MEMDBG_ERR_IO;

  /* Sony's process sysctl implementation shares snapshot state.  Serialize
   * the two-call transaction and tolerate maps changing between the size
   * query and copy instead of issuing overlapping retries from role sockets. */
  (void)pthread_mutex_lock(&g_process_sysctl_mutex);
  for (unsigned int attempt = 0U; attempt < 3U; ++attempt) {
    len = 0U;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) break;
    if (len == 0U) {
      snapshot_status = MEMDBG_OK;
      break;
    }
    if (len > MEMDBG_VMMAP_SYSCTL_MAX_BYTES) {
      snapshot_status = MEMDBG_ERR_OVERFLOW;
      break;
    }
    size_t slack = len / 4U + 4096U;
    if (slack > MEMDBG_VMMAP_SYSCTL_MAX_BYTES - len)
      slack = MEMDBG_VMMAP_SYSCTL_MAX_BYTES - len;
    size_t capacity = len + slack;
    /* See pal_process_list(): zeroed slack makes a conservative oldlenp safe
     * for the variable-sized VMMAP record parser. */
    buf = (unsigned char *)calloc(1U, capacity);
    if (buf == NULL) {
      snapshot_status = MEMDBG_ERR_NOMEM;
      break;
    }
    len = capacity;
    if (sysctl(mib, 4, buf, &len, NULL, 0) == 0) {
      snapshot_status = len <= capacity ? MEMDBG_OK : MEMDBG_ERR_OVERFLOW;
      break;
    }
    free(buf);
    buf = NULL;
    if (errno != ENOMEM) break;
  }
  (void)pthread_mutex_unlock(&g_process_sysctl_mutex);
  if (snapshot_status != MEMDBG_OK) {
    free(buf);
    return snapshot_status;
  }
  if (buf == NULL || len == 0U) {
    free(buf);
    return MEMDBG_OK;
  }

  /* Native VMMAP records are much larger than the compact wire entry.
     Reserve from the returned byte count so titles with thousands of maps
     normally need one compact allocation instead of a realloc ladder. */
  size_t estimated_maps = len / sizeof(struct kinfo_vmentry);
  if (estimated_maps < 64U) estimated_maps = 64U;
  if (estimated_maps <= SIZE_MAX / sizeof(*out->entries)) {
    out->entries = (pal_map_entry_t *)malloc(
        estimated_maps * sizeof(*out->entries));
    if (out->entries != NULL) out->capacity = estimated_maps;
  }

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
    uint32_t type =
        bsd_record_has_field(record_size,
                            offsetof(struct kinfo_vmentry, kve_type),
                            sizeof(entry->kve_type))
            ? (uint32_t)entry->kve_type
            : (uint32_t)MEMDBG_MAP_TYPE_UNKNOWN;
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
                    prot, flags, type, path))
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
