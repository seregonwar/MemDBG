/*
 * memDBG - Process inspection and map cache.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This module wraps the PAL process API with an LRU map cache and
 * process-info enrichment (title ID / content ID extraction from paths).
 * Platform-specific enumeration lives in src/pal/pal_process.c.
 */

#include "memdbg/debug/memdbg_process.h"
#include "memdbg/pal/pal_process.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- Map cache ---- */

#define CACHE_MAX 8

typedef struct {
  int                pid;
  memdbg_map_entry_t *entries;
  size_t             count;
  time_t             timestamp;
  bool               valid;
} cache_entry_t;

static cache_entry_t  g_cache[CACHE_MAX];
static pthread_mutex_t g_cache_mtx = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint     g_cache_hits, g_cache_misses;
static bool            g_cache_init = false;

static void cache_init(void) {
  pthread_mutex_lock(&g_cache_mtx);
  if (!g_cache_init) {
    memset(g_cache, 0, sizeof(g_cache));
    g_cache_init = true;
  }
  pthread_mutex_unlock(&g_cache_mtx);
}

void memdbg_process_maps_cache_flush(int pid) {
  pthread_mutex_lock(&g_cache_mtx);
  for (int i = 0; i < CACHE_MAX; ++i) {
    if (!g_cache[i].valid) continue;
    if (pid <= 0 || g_cache[i].pid == pid) { free(g_cache[i].entries); memset(&g_cache[i], 0, sizeof(g_cache[i])); }
  }
  pthread_mutex_unlock(&g_cache_mtx);
}

void memdbg_process_cache_stats(uint32_t *hits, uint32_t *misses) {
  if (hits)   *hits   = atomic_load_explicit(&g_cache_hits,   memory_order_relaxed);
  if (misses) *misses = atomic_load_explicit(&g_cache_misses, memory_order_relaxed);
}

memdbg_status_t memdbg_process_maps_cached(int pid, memdbg_map_list_t *out) {
  if (pid <= 0 || out == NULL) return MEMDBG_ERR_PARAM;
  cache_init();
  time_t now = time(NULL);

  /* Lookup */
  pthread_mutex_lock(&g_cache_mtx);
  for (int i = 0; i < CACHE_MAX; ++i) {
    if (g_cache[i].valid && g_cache[i].pid == pid && now - g_cache[i].timestamp < 5) {
      out->count = g_cache[i].count;
      out->entries = NULL;
      if (out->count) {
        out->entries = (memdbg_map_entry_t *)malloc(out->count * sizeof(memdbg_map_entry_t));
        if (!out->entries) { pthread_mutex_unlock(&g_cache_mtx); return MEMDBG_ERR_NOMEM; }
        memcpy(out->entries, g_cache[i].entries, out->count * sizeof(memdbg_map_entry_t));
      }
      atomic_fetch_add_explicit(&g_cache_hits, 1U, memory_order_relaxed);
      pthread_mutex_unlock(&g_cache_mtx);
      return MEMDBG_OK;
    }
  }
  pthread_mutex_unlock(&g_cache_mtx);

    /* Miss — fetch from PAL.
   * Note: memdbg_map_entry_t and pal_map_entry_t share identical layout
   * ({uint64_t start/end; uint32_t prot/flags; char name[64]}).  If either
   * struct changes, the other must be kept in sync. */
  atomic_fetch_add_explicit(&g_cache_misses, 1U, memory_order_relaxed);
  pal_map_list_t pmaps;
  memdbg_status_t st = pal_process_maps(pid, &pmaps);
  if (st != MEMDBG_OK) return st;
  out->count   = pmaps.count;
  out->entries = (memdbg_map_entry_t *)pmaps.entries; /* steal ownership */
  memset(&pmaps, 0, sizeof(pmaps));

  /* Store */
  pthread_mutex_lock(&g_cache_mtx);
  int slot = -1;
  time_t oldest = now;
  for (int i = 0; i < CACHE_MAX; ++i) {
    if (!g_cache[i].valid) { slot = i; break; }
    if (slot < 0 || g_cache[i].timestamp < oldest) { oldest = g_cache[i].timestamp; slot = i; }
  }
  if (slot < 0) slot = 0;
  if (g_cache[slot].valid) free(g_cache[slot].entries);
  g_cache[slot].pid = pid; g_cache[slot].count = out->count; g_cache[slot].timestamp = now;
  g_cache[slot].valid = true; g_cache[slot].entries = NULL;
  if (out->count) {
    g_cache[slot].entries = (memdbg_map_entry_t *)malloc(out->count * sizeof(memdbg_map_entry_t));
    if (g_cache[slot].entries) memcpy(g_cache[slot].entries, out->entries, out->count * sizeof(memdbg_map_entry_t));
  }
  pthread_mutex_unlock(&g_cache_mtx);
  return MEMDBG_OK;
}

/* ---- Process list (passthrough to PAL with type conversion) ---- */

memdbg_status_t memdbg_process_list(memdbg_process_list_t *out) {
  if (!out) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));

  pal_process_list_t plist;
  memdbg_status_t st = pal_process_list(&plist);
  if (st != MEMDBG_OK) return st;

  out->count = plist.count;
  out->entries = (memdbg_process_entry_t *)plist.entries; /* steal */
  memset(&plist, 0, sizeof(plist));
  return MEMDBG_OK;
}

void memdbg_process_list_free(memdbg_process_list_t *list) {
  if (!list) return;
  free(list->entries);
  memset(list, 0, sizeof(*list));
}

/* ---- Memory maps (non-cached passthrough) ---- */

memdbg_status_t memdbg_process_maps(int pid, memdbg_map_list_t *out) {
  if (pid <= 0 || !out) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));

  pal_map_list_t pmaps;
  memdbg_status_t st = pal_process_maps(pid, &pmaps);
  if (st != MEMDBG_OK) return st;

  out->count   = pmaps.count;
  out->entries = (memdbg_map_entry_t *)pmaps.entries;
  memset(&pmaps, 0, sizeof(pmaps));
  return MEMDBG_OK;
}

void memdbg_process_maps_free(memdbg_map_list_t *list) {
  if (!list) return;
  free(list->entries);
  memset(list, 0, sizeof(*list));
}

/* ---- Process info (title ID / content ID extraction) ---- */

static void copy_field(char *dst, size_t dsz, const char *src) {
  if (dst && dsz) (void)snprintf(dst, dsz, "%s", src ? src : "");
}

static bool is_alnum_upper(char c) { return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'); }

static bool match_title_id(const char *s) {
  if (!s) return false;
  if (strnlen(s, 9) < 9U) return false;
  bool pfx = !strncmp(s, "CUSA", 4) || !strncmp(s, "PPSA", 4) || !strncmp(s, "PCSA", 4);
  if (!pfx) return false;
  for (int i = 4; i < 9; ++i) if (s[i] < '0' || s[i] > '9') return false;
  return true;
}

static void extract_title_id(const char *text, char *out, size_t out_size) {
  if (!text || !out || !out_size || out[0]) return;
  for (const char *p = text; *p; ++p) {
    if (match_title_id(p)) { copy_field(out, out_size, p); if (out_size > 9U) out[9] = '\0'; return; }
  }
}

static bool match_content_id(const char *s) {
  if (!s || strnlen(s, 36) < 36U) return false;
  if (!is_alnum_upper(s[0]) || !is_alnum_upper(s[1])) return false;
  for (int i = 2; i < 6; ++i) if (s[i] < '0' || s[i] > '9') return false;
  if (s[6] != '-' || !match_title_id(s + 7) || s[16] != '_' ||
      s[17] < '0' || s[17] > '9' || s[18] < '0' || s[18] > '9' || s[19] != '-') return false;
  for (int i = 20; i < 36; ++i) if (!is_alnum_upper(s[i])) return false;
  return true;
}

static void extract_content_id(const char *text, char *out, size_t out_size) {
  if (!text || !out || !out_size || out[0]) return;
  for (const char *p = text; *p; ++p) {
    if (match_content_id(p)) { size_t n = out_size-1<36U ? out_size-1 : 36U; memcpy(out, p, n); out[n] = '\0'; return; }
  }
}

static bool read_small_text_file(const char *path, char *out, size_t out_size) {
  FILE *fp; size_t n;
  if (!path || !out || !out_size) return false;
  fp = fopen(path, "rb"); if (!fp) return false;
  n = fread(out, 1U, out_size - 1U, fp); out[n] = '\0'; (void)fclose(fp);
  return n != 0U;
}

static void json_string_field(const char *json, const char *key, char *out, size_t out_size) {
  char marker[64]; const char *p;
  if (!json || !key || !out || !out_size || out[0]) return;
  (void)snprintf(marker, sizeof(marker), "\"%s\"", key);
  p = strstr(json, marker); if (!p) return;
  p = strchr(p + strlen(marker), ':'); if (!p) return;
  p = strchr(p, '"'); if (!p) return; ++p;
  size_t i = 0;
  while (*p && *p != '"' && i + 1U < out_size) { if (*p == '\\' && p[1]) ++p; out[i++] = *p++; }
  out[i] = '\0';
}

static void enrich_from_param_json(memdbg_process_info_response_t *out) {
  char path[256], json[16384];
  if (!out || !out->title_id[0]) return;
  const char *patterns[] = {
    "/system_data/priv/appmeta/%s/param.json", "/user/appmeta/%s/param.json",
    "/user/app/%s/sce_sys/param.json", "/mnt/sandbox/%s_000/sce_sys/param.json",
  };
  for (size_t i = 0; i < sizeof(patterns)/sizeof(patterns[0]); ++i) {
    (void)snprintf(path, sizeof(path), patterns[i], out->title_id);
    if (!read_small_text_file(path, json, sizeof(json))) continue;
    json_string_field(json, "titleId", out->title_id, sizeof(out->title_id));
    json_string_field(json, "contentId", out->content_id, sizeof(out->content_id));
    if (out->content_id[0]) return;
  }
}

memdbg_status_t memdbg_process_info(int pid, memdbg_process_info_response_t *out) {
  if (pid <= 0 || !out) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out)); out->pid = pid;

  /* Name from process list */
  pal_process_list_t plist;
  if (pal_process_list(&plist) == MEMDBG_OK) {
    for (size_t i = 0; i < plist.count; ++i)
      if (plist.entries[i].pid == pid) { copy_field(out->name, sizeof(out->name), plist.entries[i].name); break; }
    pal_process_list_free(&plist);
  }

  /* Path */
  pal_process_path(pid, out->path, sizeof(out->path));
  extract_title_id(out->path, out->title_id, sizeof(out->title_id));
  extract_content_id(out->path, out->content_id, sizeof(out->content_id));

  /* Enrich from maps */
  pal_map_list_t pmaps;
  if (pal_process_maps(pid, &pmaps) == MEMDBG_OK) {
    for (size_t i = 0; i < pmaps.count; ++i) {
      if (!out->path[0] && pmaps.entries[i].name[0] && (pmaps.entries[i].protection & 4U))
        copy_field(out->path, sizeof(out->path), pmaps.entries[i].name);
      extract_title_id(pmaps.entries[i].name, out->title_id, sizeof(out->title_id));
      extract_content_id(pmaps.entries[i].name, out->content_id, sizeof(out->content_id));
    }
    pal_process_maps_free(&pmaps);
  }

  enrich_from_param_json(out);
  if (!out->name[0]) copy_field(out->name, sizeof(out->name), out->title_id[0] ? out->title_id : "unknown");
  return MEMDBG_OK;
}
