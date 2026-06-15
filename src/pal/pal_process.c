/*
 * memDBG - PAL: Cross-platform process listing / maps / info.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/pal/pal_process.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#endif

/* ---- Helpers shared across platforms ---- */

static pal_process_entry_t *proc_append(pal_process_list_t *list, int pid, const char *name) {
  size_t nc = list->count + 1U;
  pal_process_entry_t *next = (pal_process_entry_t *)realloc(list->entries, nc * sizeof(*list->entries));
  if (next == NULL) return NULL;
  list->entries = next;
  memset(&list->entries[list->count], 0, sizeof(list->entries[list->count]));
  list->entries[list->count].pid = pid;
  (void)snprintf(list->entries[list->count].name, sizeof(list->entries[list->count].name),
                 "%s", name && name[0] ? name : "unknown");
  list->count = nc;
  return &list->entries[list->count - 1U];
}

#if defined(__linux__) || defined(__FreeBSD__)
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
    char name[64];
    read_comm(pid, name, sizeof(name));
    if (!proc_append(out, pid, name)) { closedir(d); pal_process_list_free(out); return MEMDBG_ERR_NOMEM; }
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
    if (!proc_append(out, procs[i].kp_proc.p_pid, procs[i].kp_proc.p_comm))
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
 *  FreeBSD  —  sysctl KERN_PROC_PROC + KERN_PROC_VMMAP
 * ======================================================================== */
#elif defined(__FreeBSD__)

memdbg_status_t pal_process_list(pal_process_list_t *out) {
  memset(out, 0, sizeof(*out));
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
  size_t len = 0;
  if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) return MEMDBG_ERR_IO;
  struct kinfo_proc *procs = (struct kinfo_proc *)malloc(len);
  if (!procs) return MEMDBG_ERR_NOMEM;
  if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) { free(procs); return MEMDBG_ERR_IO; }
  size_t n = len / sizeof(procs[0]);
  for (size_t i = 0; i < n; ++i) {
    if (!proc_append(out, procs[i].ki_pid, procs[i].ki_comm))
      { free(procs); pal_process_list_free(out); return MEMDBG_ERR_NOMEM; }
  }
  free(procs);
  return MEMDBG_OK;
}

memdbg_status_t pal_process_maps(int pid, pal_map_list_t *out) {
  memset(out, 0, sizeof(*out));
#ifdef KERN_PROC_VMMAP
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid};
  size_t len = 0;
  if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) return MEMDBG_ERR_IO;
  struct kinfo_vmentry *entries = (struct kinfo_vmentry *)malloc(len);
  if (!entries) return MEMDBG_ERR_NOMEM;
  if (sysctl(mib, 4, entries, &len, NULL, 0) != 0) { free(entries); return MEMDBG_ERR_IO; }
  size_t n = len / sizeof(entries[0]);
  for (size_t i = 0; i < n; ++i) {
    uint32_t prot = 0;
#  ifdef KVME_PROT_READ
    if (entries[i].kve_protection & KVME_PROT_READ)  prot |= 1U;
    if (entries[i].kve_protection & KVME_PROT_WRITE) prot |= 2U;
    if (entries[i].kve_protection & KVME_PROT_EXEC)  prot |= 4U;
#  else
    prot = (uint32_t)entries[i].kve_protection;
#  endif
    if (!map_append(out, (uint64_t)entries[i].kve_start, (uint64_t)entries[i].kve_end,
                    prot, (uint32_t)entries[i].kve_flags, entries[i].kve_path))
      { free(entries); pal_process_maps_free(out); return MEMDBG_ERR_NOMEM; }
  }
  free(entries);
  return MEMDBG_OK;
#else
  (void)pid; return MEMDBG_ERR_UNSUPPORTED;
#endif
}

memdbg_status_t pal_process_path(int pid, char *out, size_t out_size) {
  out[0] = '\0';
#ifdef KERN_PROC_PATHNAME
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
 *  PS4 (Orbis) / PS5 (Prospero)  —  stubs
 * ======================================================================== */
#elif defined(__ORBIS__) || defined(__PROSPERO__)

memdbg_status_t pal_process_list(pal_process_list_t *out) {
  memset(out, 0, sizeof(*out));
  return MEMDBG_ERR_UNSUPPORTED; /* stub — implement with sceDbgProcessList */
}

memdbg_status_t pal_process_maps(int pid, pal_map_list_t *out) {
  (void)pid; memset(out, 0, sizeof(*out));
  return MEMDBG_ERR_UNSUPPORTED; /* stub — implement with sceDbgGetProcessMaps */
}

memdbg_status_t pal_process_path(int pid, char *out, size_t out_size) {
  (void)pid; (void)out_size; if (out != NULL) out[0] = '\0';
  return MEMDBG_ERR_UNSUPPORTED;
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
