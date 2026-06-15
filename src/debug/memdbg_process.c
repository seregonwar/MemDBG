/*
 * memDBG - Memory debugger payload for jailbroken consoles.
 * Copyright (C) 2026 SeregonWar
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/debug/memdbg_process.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(PLATFORM_PS4) ||     \
    defined(PLATFORM_PS5)
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#endif

static memdbg_status_t append_process(memdbg_process_list_t *list, int pid,
                                      const char *name) {
  size_t next_count = list->count + 1U;
  memdbg_process_entry_t *next =
      (memdbg_process_entry_t *)realloc(list->entries,
                                        next_count * sizeof(*list->entries));
  if (next == NULL) {
    return MEMDBG_ERR_NOMEM;
  }
  list->entries = next;
  memset(&list->entries[list->count], 0, sizeof(list->entries[list->count]));
  list->entries[list->count].pid = pid;
  (void)snprintf(list->entries[list->count].name,
                 sizeof(list->entries[list->count].name), "%s",
                 name != NULL && name[0] != '\0' ? name : "unknown");
  list->count = next_count;
  return MEMDBG_OK;
}

#if defined(__linux__) || defined(__FreeBSD__)
static memdbg_status_t append_map(memdbg_map_list_t *list, uint64_t start,
                                  uint64_t end, uint32_t protection,
                                  uint32_t flags, const char *name) {
  size_t next_count = list->count + 1U;
  memdbg_map_entry_t *next =
      (memdbg_map_entry_t *)realloc(list->entries,
                                    next_count * sizeof(*list->entries));
  if (next == NULL) {
    return MEMDBG_ERR_NOMEM;
  }
  list->entries = next;
  memset(&list->entries[list->count], 0, sizeof(list->entries[list->count]));
  list->entries[list->count].start = start;
  list->entries[list->count].end = end;
  list->entries[list->count].protection = protection;
  list->entries[list->count].flags = flags;
  if (name != NULL) {
    (void)snprintf(list->entries[list->count].name,
                   sizeof(list->entries[list->count].name), "%s", name);
  }
  list->count = next_count;
  return MEMDBG_OK;
}
#endif

#if defined(__linux__)
static bool string_is_pid(const char *s) {
  if (s == NULL || *s == '\0') {
    return false;
  }
  for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; ++p) {
    if (!isdigit(*p)) {
      return false;
    }
  }
  return true;
}

static void linux_read_comm(int pid, char *out, size_t out_size) {
  char path[64];
  FILE *fp;
  if (out == NULL || out_size == 0U) {
    return;
  }
  out[0] = '\0';
  (void)snprintf(path, sizeof(path), "/proc/%d/comm", pid);
  fp = fopen(path, "r");
  if (fp == NULL) {
    (void)snprintf(out, out_size, "%d", pid);
    return;
  }
  if (fgets(out, (int)out_size, fp) != NULL) {
    out[strcspn(out, "\r\n")] = '\0';
  }
  (void)fclose(fp);
}
#endif

memdbg_status_t memdbg_process_list(memdbg_process_list_t *out) {
  if (out == NULL) {
    return MEMDBG_ERR_PARAM;
  }
  memset(out, 0, sizeof(*out));

#if defined(__linux__)
  DIR *dir = opendir("/proc");
  if (dir == NULL) {
    return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  }

  struct dirent *ent;
  while ((ent = readdir(dir)) != NULL) {
    if (!string_is_pid(ent->d_name)) {
      continue;
    }
    int pid = atoi(ent->d_name);
    char name[64];
    linux_read_comm(pid, name, sizeof(name));
    memdbg_status_t st = append_process(out, pid, name);
    if (st != MEMDBG_OK) {
      (void)closedir(dir);
      memdbg_process_list_free(out);
      return st;
    }
  }
  (void)closedir(dir);
  return MEMDBG_OK;

#elif defined(__APPLE__)
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
  size_t len = 0U;
  if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) {
    return MEMDBG_ERR_IO;
  }
  struct kinfo_proc *procs = (struct kinfo_proc *)malloc(len);
  if (procs == NULL) {
    return MEMDBG_ERR_NOMEM;
  }
  if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) {
    free(procs);
    return MEMDBG_ERR_IO;
  }
  size_t count = len / sizeof(procs[0]);
  for (size_t i = 0; i < count; ++i) {
    memdbg_status_t st =
        append_process(out, procs[i].kp_proc.p_pid, procs[i].kp_proc.p_comm);
    if (st != MEMDBG_OK) {
      free(procs);
      memdbg_process_list_free(out);
      return st;
    }
  }
  free(procs);
  return MEMDBG_OK;

#elif defined(__FreeBSD__)
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
  size_t len = 0U;
  if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) {
    return MEMDBG_ERR_IO;
  }
  struct kinfo_proc *procs = (struct kinfo_proc *)malloc(len);
  if (procs == NULL) {
    return MEMDBG_ERR_NOMEM;
  }
  if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) {
    free(procs);
    return MEMDBG_ERR_IO;
  }
  size_t count = len / sizeof(procs[0]);
  for (size_t i = 0; i < count; ++i) {
    memdbg_status_t st = append_process(out, procs[i].ki_pid, procs[i].ki_comm);
    if (st != MEMDBG_OK) {
      free(procs);
      memdbg_process_list_free(out);
      return st;
    }
  }
  free(procs);
  return MEMDBG_OK;
#else
  return MEMDBG_ERR_UNSUPPORTED;
#endif
}

void memdbg_process_list_free(memdbg_process_list_t *list) {
  if (list == NULL) {
    return;
  }
  free(list->entries);
  list->entries = NULL;
  list->count = 0U;
}

memdbg_status_t memdbg_process_maps(int pid, memdbg_map_list_t *out) {
  if (pid <= 0 || out == NULL) {
    return MEMDBG_ERR_PARAM;
  }
  memset(out, 0, sizeof(*out));

#if defined(__linux__)
  char path[64];
  char line[512];
  (void)snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *fp = fopen(path, "r");
  if (fp == NULL) {
    return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    unsigned long long start = 0ULL;
    unsigned long long end = 0ULL;
    char perms[8] = "";
    char name[128] = "";
    uint32_t prot = 0U;

    int fields = sscanf(line, "%llx-%llx %7s %*s %*s %*s %127[^\n]", &start,
                        &end, perms, name);
    if (fields < 3) {
      continue;
    }
    if (perms[0] == 'r') {
      prot |= 1U;
    }
    if (perms[1] == 'w') {
      prot |= 2U;
    }
    if (perms[2] == 'x') {
      prot |= 4U;
    }
    memdbg_status_t st = append_map(out, (uint64_t)start, (uint64_t)end, prot,
                                    0U, fields == 4 ? name : "");
    if (st != MEMDBG_OK) {
      (void)fclose(fp);
      memdbg_process_maps_free(out);
      return st;
    }
  }
  (void)fclose(fp);
  return MEMDBG_OK;

#elif defined(__FreeBSD__)
#ifdef KERN_PROC_VMMAP
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid};
  size_t len = 0U;
  if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) {
    return MEMDBG_ERR_IO;
  }
  struct kinfo_vmentry *entries = (struct kinfo_vmentry *)malloc(len);
  if (entries == NULL) {
    return MEMDBG_ERR_NOMEM;
  }
  if (sysctl(mib, 4, entries, &len, NULL, 0) != 0) {
    free(entries);
    return MEMDBG_ERR_IO;
  }
  size_t count = len / sizeof(entries[0]);
  for (size_t i = 0; i < count; ++i) {
    uint32_t prot = 0U;
#ifdef KVME_PROT_READ
    if ((entries[i].kve_protection & KVME_PROT_READ) != 0) {
      prot |= 1U;
    }
    if ((entries[i].kve_protection & KVME_PROT_WRITE) != 0) {
      prot |= 2U;
    }
    if ((entries[i].kve_protection & KVME_PROT_EXEC) != 0) {
      prot |= 4U;
    }
#else
    prot = (uint32_t)entries[i].kve_protection;
#endif
    memdbg_status_t st =
        append_map(out, (uint64_t)entries[i].kve_start,
                   (uint64_t)entries[i].kve_end, prot,
                   (uint32_t)entries[i].kve_flags, entries[i].kve_path);
    if (st != MEMDBG_OK) {
      free(entries);
      memdbg_process_maps_free(out);
      return st;
    }
  }
  free(entries);
  return MEMDBG_OK;
#else
  (void)pid;
  return MEMDBG_ERR_UNSUPPORTED;
#endif
#else
  (void)pid;
  return MEMDBG_ERR_UNSUPPORTED;
#endif
}

void memdbg_process_maps_free(memdbg_map_list_t *list) {
  if (list == NULL) {
    return;
  }
  free(list->entries);
  list->entries = NULL;
  list->count = 0U;
}

static void copy_field(char *dst, size_t dst_size, const char *src) {
  if (dst == NULL || dst_size == 0U) {
    return;
  }
  (void)snprintf(dst, dst_size, "%s", src != NULL ? src : "");
}

static bool is_alnum_upper(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

static bool match_title_id(const char *s) {
  if (s == NULL) {
    return false;
  }
  bool prefix = (strncmp(s, "CUSA", 4) == 0) || (strncmp(s, "PPSA", 4) == 0) ||
                (strncmp(s, "PCSA", 4) == 0);
  if (!prefix) {
    return false;
  }
  for (int i = 4; i < 9; ++i) {
    if (s[i] < '0' || s[i] > '9') {
      return false;
    }
  }
  return true;
}

static void extract_title_id(const char *text, char *out, size_t out_size) {
  if (text == NULL || out == NULL || out_size == 0U || out[0] != '\0') {
    return;
  }
  for (const char *p = text; *p != '\0'; ++p) {
    if (match_title_id(p)) {
      copy_field(out, out_size, p);
      if (out_size > 9U) {
        out[9] = '\0';
      }
      return;
    }
  }
}

static bool match_content_id(const char *s) {
  if (s == NULL) {
    return false;
  }
  if (!is_alnum_upper(s[0]) || !is_alnum_upper(s[1])) {
    return false;
  }
  for (int i = 2; i < 6; ++i) {
    if (s[i] < '0' || s[i] > '9') {
      return false;
    }
  }
  if (s[6] != '-' || !match_title_id(s + 7) || s[16] != '_' ||
      s[17] < '0' || s[17] > '9' || s[18] < '0' || s[18] > '9' ||
      s[19] != '-') {
    return false;
  }
  for (int i = 20; i < 36; ++i) {
    if (!is_alnum_upper(s[i])) {
      return false;
    }
  }
  return true;
}

static void extract_content_id(const char *text, char *out, size_t out_size) {
  if (text == NULL || out == NULL || out_size == 0U || out[0] != '\0') {
    return;
  }
  for (const char *p = text; *p != '\0'; ++p) {
    if (match_content_id(p)) {
      size_t len = out_size - 1U < 36U ? out_size - 1U : 36U;
      memcpy(out, p, len);
      out[len] = '\0';
      return;
    }
  }
}

static bool read_small_text_file(const char *path, char *out, size_t out_size) {
  FILE *fp;
  size_t n;
  if (path == NULL || out == NULL || out_size == 0U) {
    return false;
  }
  fp = fopen(path, "rb");
  if (fp == NULL) {
    return false;
  }
  n = fread(out, 1U, out_size - 1U, fp);
  out[n] = '\0';
  (void)fclose(fp);
  return n != 0U;
}

static void json_string_field(const char *json, const char *key, char *out,
                              size_t out_size) {
  char marker[64];
  const char *p;
  if (json == NULL || key == NULL || out == NULL || out_size == 0U ||
      out[0] != '\0') {
    return;
  }
  (void)snprintf(marker, sizeof(marker), "\"%s\"", key);
  p = strstr(json, marker);
  if (p == NULL) {
    return;
  }
  p = strchr(p + strlen(marker), ':');
  if (p == NULL) {
    return;
  }
  p = strchr(p, '"');
  if (p == NULL) {
    return;
  }
  ++p;
  size_t i = 0U;
  while (*p != '\0' && *p != '"' && i + 1U < out_size) {
    if (*p == '\\' && p[1] != '\0') {
      ++p;
    }
    out[i++] = *p++;
  }
  out[i] = '\0';
}

static void enrich_from_param_json(memdbg_process_info_response_t *out) {
  char path[256];
  char json[16384];
  if (out == NULL || out->title_id[0] == '\0') {
    return;
  }

  const char *patterns[] = {
      "/system_data/priv/appmeta/%s/param.json",
      "/user/appmeta/%s/param.json",
      "/user/app/%s/sce_sys/param.json",
      "/mnt/sandbox/%s_000/sce_sys/param.json",
  };
  for (size_t i = 0U; i < sizeof(patterns) / sizeof(patterns[0]); ++i) {
    (void)snprintf(path, sizeof(path), patterns[i], out->title_id);
    if (!read_small_text_file(path, json, sizeof(json))) {
      continue;
    }
    json_string_field(json, "titleId", out->title_id, sizeof(out->title_id));
    json_string_field(json, "contentId", out->content_id,
                      sizeof(out->content_id));
    if (out->content_id[0] != '\0') {
      return;
    }
  }
}

static void process_path(int pid, char *out, size_t out_size) {
  if (out == NULL || out_size == 0U) {
    return;
  }
  out[0] = '\0';
#if defined(__linux__)
  char link_path[64];
  (void)snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
  ssize_t n = readlink(link_path, out, out_size - 1U);
  if (n > 0) {
    out[n] = '\0';
  }
#elif defined(__FreeBSD__)
#ifdef KERN_PROC_PATHNAME
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid};
  size_t len = out_size;
  if (sysctl(mib, 4, out, &len, NULL, 0) != 0) {
    out[0] = '\0';
  }
#else
  (void)pid;
#endif
#else
  (void)pid;
#endif
}

memdbg_status_t memdbg_process_info(int pid,
                                    memdbg_process_info_response_t *out) {
  if (pid <= 0 || out == NULL) {
    return MEMDBG_ERR_PARAM;
  }
  memset(out, 0, sizeof(*out));
  out->pid = pid;

  memdbg_process_list_t processes;
  if (memdbg_process_list(&processes) == MEMDBG_OK) {
    for (size_t i = 0U; i < processes.count; ++i) {
      if (processes.entries[i].pid == pid) {
        copy_field(out->name, sizeof(out->name), processes.entries[i].name);
        break;
      }
    }
    memdbg_process_list_free(&processes);
  }

  process_path(pid, out->path, sizeof(out->path));
  extract_title_id(out->path, out->title_id, sizeof(out->title_id));
  extract_content_id(out->path, out->content_id, sizeof(out->content_id));

  memdbg_map_list_t maps;
  if (memdbg_process_maps(pid, &maps) == MEMDBG_OK) {
    for (size_t i = 0U; i < maps.count; ++i) {
      if (out->path[0] == '\0' && maps.entries[i].name[0] != '\0' &&
          (maps.entries[i].protection & 4U) != 0U) {
        copy_field(out->path, sizeof(out->path), maps.entries[i].name);
      }
      extract_title_id(maps.entries[i].name, out->title_id,
                       sizeof(out->title_id));
      extract_content_id(maps.entries[i].name, out->content_id,
                         sizeof(out->content_id));
    }
    memdbg_process_maps_free(&maps);
  }

  enrich_from_param_json(out);
  if (out->name[0] == '\0') {
    copy_field(out->name, sizeof(out->name),
               out->title_id[0] != '\0' ? out->title_id : "unknown");
  }
  return MEMDBG_OK;
}
