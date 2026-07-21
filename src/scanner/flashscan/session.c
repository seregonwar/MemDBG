/*
 * memDBG - FlashScan session management.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "flashscan_internal.h"

struct flashscan_sess g_sessions[FLASHSCAN_MAX_SESSIONS];
page_alias_ctx_t *g_alias_ctxs[FLASHSCAN_MAX_SESSIONS];
int g_session_owner_fd[FLASHSCAN_MAX_SESSIONS];
pthread_mutex_t g_session_owner_mutex = PTHREAD_MUTEX_INITIALIZER;

uint64_t g_fs_ram_limit     = 512ULL << 20;
char     g_fs_spill_dir[64] = "/data";
int      g_fs_force_fail    = 0;
volatile int g_fs_cancel_requested = 0;
uint64_t g_fs_mat_max       = 1ULL << 20;

void snapshot_store_path(unsigned slot, char *out, const char *tag) {
  int n = snprintf(out, 96, "%s/%s%02u.bin",
                   g_fs_spill_dir, tag, slot);
  (void)n;
}

struct flashscan_sess *session_get(unsigned slot) {
  if (slot >= FLASHSCAN_MAX_SESSIONS) return NULL;
  return &g_sessions[slot];
}

void alias_context_free_slot(unsigned slot) {
  if (slot >= FLASHSCAN_MAX_SESSIONS) return;
  if (g_alias_ctxs[slot]) {
    page_alias_end(g_alias_ctxs[slot]);
    g_alias_ctxs[slot] = NULL;
  }
}

page_alias_ctx_t *alias_context_get(unsigned slot, uint32_t pid) {
  if (slot >= FLASHSCAN_MAX_SESSIONS) return NULL;
  if (!g_alias_ctxs[slot])
    g_alias_ctxs[slot] = page_alias_begin(pid, 0);
  else
    page_alias_rebind(g_alias_ctxs[slot], pid);
  return g_alias_ctxs[slot];
}

void flashscan_init(void) {
  memset(g_sessions, 0, sizeof(g_sessions));
  memset(g_alias_ctxs, 0, sizeof(g_alias_ctxs));
  for (unsigned slot = 0U; slot < FLASHSCAN_MAX_SESSIONS; ++slot)
    g_session_owner_fd[slot] = -1;
}

unsigned int flashscan_slot_for_client(int client_fd) {
  unsigned int free_slot = FLASHSCAN_INVALID_SLOT;
  (void)pthread_mutex_lock(&g_session_owner_mutex);
  for (unsigned int slot = 0U; slot < FLASHSCAN_MAX_SESSIONS; ++slot) {
    if (g_session_owner_fd[slot] == client_fd) {
      (void)pthread_mutex_unlock(&g_session_owner_mutex);
      return slot;
    }
    if (free_slot == FLASHSCAN_INVALID_SLOT && g_session_owner_fd[slot] < 0)
      free_slot = slot;
  }
  if (free_slot != FLASHSCAN_INVALID_SLOT)
    g_session_owner_fd[free_slot] = client_fd;
  (void)pthread_mutex_unlock(&g_session_owner_mutex);
  return free_slot;
}

void flashscan_release_client(int client_fd) {
  (void)pthread_mutex_lock(&g_session_owner_mutex);
  for (unsigned int slot = 0U; slot < FLASHSCAN_MAX_SESSIONS; ++slot) {
    if (g_session_owner_fd[slot] != client_fd) continue;
    /* The connection handler is no longer dispatching requests, so its
       resident state can be reclaimed before making the slot reusable. */
    flashscan_free_slot(slot);
    g_session_owner_fd[slot] = -1;
    break;
  }
  (void)pthread_mutex_unlock(&g_session_owner_mutex);
}

void flashscan_cleanup_orphans(void) {
  char path[96];
  const char *tags[] = {"qs_snap_", "qs_first_", "qs_prev_", NULL};
  for (unsigned slot = 0; slot < FLASHSCAN_MAX_SESSIONS; slot++) {
    for (const char **t = tags; *t; t++) {
      snapshot_store_path(slot, path, *t);
      unlink(path);
    }
  }
}

void flashscan_free_slot(unsigned int slot) {
  if (slot >= FLASHSCAN_MAX_SESSIONS) return;
  alias_context_free_slot(slot);
  struct flashscan_sess *s = &g_sessions[slot];
  munmap_anonymous(s->buf,      s->buf_cap);
  munmap_anonymous(s->snap_ram, s->snap_bytes);
  munmap_anonymous(s->bitmap,   s->bitmap_bytes);
  if (s->seg) { free(s->seg); s->seg = NULL; }
  if (s->mode == FLASHSCAN_MODE_SNAPSHOT) {
    if (s->snap_fd > 0) { close(s->snap_fd); s->snap_fd = -1; }
    char path[96];
    snapshot_store_path(slot, path, "qs_snap_");  unlink(path);
    if (s->first_fd > 0) { close(s->first_fd); s->first_fd = -1; }
    snapshot_store_path(slot, path, "qs_first_"); unlink(path);
    if (s->prev_fd > 0)  { close(s->prev_fd);  s->prev_fd  = -1; }
    snapshot_store_path(slot, path, "qs_prev_");  unlink(path);
  }
  memset(s, 0, sizeof(*s));
}

inline void bitmap_clear(uint8_t *bm, uint64_t i) {
  /* Atomic clear: necessary because parallel rescan workers may clear
     different bits within the same byte concurrently.  Plain &= would
     lose one update when the read-modify-write races across threads.
     __sync_fetch_and_and provides a full barrier on all architectures. */
  (void)__sync_fetch_and_and(&bm[i >> 3], (uint8_t)~(1u << (i & 7)));
}

uint64_t bitmap_next_set(const uint8_t *bm, uint64_t from, uint64_t n) {
  uint64_t i = from;
  while (i < n) {
    if ((i & 63) == 0) {
      while (i + 64 <= n && *(const uint64_t *)(bm + (i >> 3)) == 0) i += 64;
      if (i >= n) break;
    }
    if ((bm[i >> 3] >> (i & 7)) & 1) return i;
    i++;
  }
  return n;
}

uint64_t slot_to_addr(const struct flashscan_sess *s, uint64_t i) {
  const struct fs_seg *seg = s->seg;
  uint32_t lo = 0, hi = s->nseg;
  while (lo + 1 < hi) {
    uint32_t mid = (lo + hi) >> 1;
    if (seg[mid].slot_start <= i) lo = mid; else hi = mid;
  }
  return seg[lo].addr + (i - seg[lo].slot_start) * s->stride;
}

struct flashscan_sess *session_alloc(unsigned slot, uint32_t pid,
                                            uint32_t vt, uint64_t vlen) {
  if (slot >= FLASHSCAN_MAX_SESSIONS) return NULL;
  flashscan_free_slot(slot);

  void *m = mmap_anonymous(FS_RESCAN_WIN_CAP * 2);
  if (!m) return NULL;

  struct flashscan_sess *s = &g_sessions[slot];
  s->in_use    = 1;
  s->mode      = FLASHSCAN_MODE_LIST;
  s->buf       = m;
  s->buf_cap   = FS_RESCAN_WIN_CAP * 2;
  s->count     = 0;
  s->rec_size  = 8 + vlen;
  s->value_len = vlen;
  s->pid       = pid;
  s->value_type = vt;
  return s;
}

int snapshot_create(int fd, unsigned slot,
                           const memdbg_quickscan_start_request_t *req,
                           uint64_t vlen, uint64_t step,
                           const memdbg_quickscan_segment_t *in_segs,
                           uint32_t in_nseg, int keep_first, int keep_prev) {
  flashscan_free_slot(slot);

  struct fs_seg *seg = (struct fs_seg *)malloc(
      (size_t)in_nseg * sizeof(struct fs_seg));
  if (!seg) {
    memdbg_quickscan_snapshot_plan_t plan = {0,0};
    socket_send_all(fd, &plan, sizeof(plan));
    uint64_t sent = 0xFFFFFFFFFFFFFFFFULL;
    socket_send_all(fd, &sent, 8);
    memdbg_quickscan_snapshot_summary_t sum = {0,0};
    socket_send_all(fd, &sum, sizeof(sum));
    return 0;
  }

  uint64_t slot_count = 0, total_bytes = 0;
  for (uint32_t g = 0; g < in_nseg; g++) {
    uint64_t len = in_segs[g].length;
    uint64_t ns  = (len >= vlen) ? ((len - vlen) / step + 1) : 0;
    seg[g].addr        = in_segs[g].address;
    seg[g].slot_start  = slot_count;
    seg[g].nslots      = ns;
    slot_count  += ns;
    total_bytes += len;
  }

  uint64_t snap_bytes   = slot_count * vlen;
  uint64_t bitmap_bytes = (slot_count + 7) >> 3;

  int include_zeros = !(req->request_flags & MEMDBG_QS_FL_SNAP_NOZERO);
  uint64_t survivors = include_zeros ? slot_count : 0;

  memdbg_quickscan_snapshot_plan_t plan;
  plan.slot_count  = slot_count;
  plan.total_bytes = total_bytes;
  socket_send_all(fd, &plan, sizeof(plan));

  if (slot_count == 0 || bitmap_bytes > FLASHSCAN_SNAPSHOT_BITMAP_MAX) {
    uint64_t sent = 0xFFFFFFFFFFFFFFFFULL;
    socket_send_all(fd, &sent, 8);
    memdbg_quickscan_snapshot_summary_t sum = {0,0};
    socket_send_all(fd, &sum, sizeof(sum));
    free(seg);
    return 0;
  }

  uint8_t *bitmap   = (uint8_t *)mmap_anonymous(bitmap_bytes);
  uint8_t *snap_ram = NULL;
  int      snap_fd  = -1;
  int      use_file = 0;
  uint64_t ram_bytes = 0;
  int      ok = 1, fail = 0;

  if (!bitmap) { ok = 0; }

  if (ok) {
    if (snap_bytes <= g_fs_ram_limit) {
      snap_ram = (uint8_t *)mmap_anonymous(snap_bytes);
      if (snap_ram) ram_bytes = snap_bytes;
      else use_file = 1;
    } else {
      use_file = 1;
    }
    if (use_file) {
      uint64_t cache = (g_fs_ram_limit / vlen) * vlen;
      if (cache > 0) {
        snap_ram = (uint8_t *)mmap_anonymous(cache);
        if (snap_ram) ram_bytes = cache;
      }
      char path[96];
      snapshot_store_path(slot, path, "qs_snap_");
      snap_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
      if (snap_fd < 0) ok = 0;
    }
  }

  int first_fd = -1, prev_fd = -1;
  if (ok && keep_first) {
    char path[96];
    snapshot_store_path(slot, path, "qs_first_");
    first_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (first_fd < 0) keep_first = 0;
  }
  if (ok && keep_prev) {
    char path[96];
    snapshot_store_path(slot, path, "qs_prev_");
    prev_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (prev_fd < 0) keep_prev = 0;
  }

  if (ok) memset(bitmap, 0xFF, bitmap_bytes);

  uint64_t chunk_size = 0x100000ULL;
  if (chunk_size % step) chunk_size = (chunk_size / step) * step;
  if (chunk_size == 0) chunk_size = step;
  uint8_t *read_buf = (uint8_t *)malloc(chunk_size);
  uint8_t *pack_buf = (step != vlen) ? (uint8_t *)malloc(chunk_size) : NULL;

  if (!read_buf || (step != vlen && !pack_buf)) {
    free(read_buf); free(pack_buf);
    ok = 0;
  }

  uint64_t prev_zeroes = include_zeros ? 0 : (uint64_t)-1;
  (void)prev_zeroes;

  uint64_t done_total = 0;
  for (uint32_t g = 0; ok && !fail && g < in_nseg; g++) {
    uint64_t seg_addr = seg[g].addr, seg_ns = seg[g].nslots, s0 = 0;
    while (ok && !fail && s0 < seg_ns) {
      if (g_fs_force_fail) { fail = 1; break; }
      uint64_t win_slots = chunk_size / step;
      if (win_slots == 0) win_slots = 1;
      if (s0 + win_slots > seg_ns) win_slots = seg_ns - s0;
      uint64_t gslot  = seg[g].slot_start + s0;
      uint64_t waddr  = seg_addr + s0 * step;
      uint64_t wbytes = (win_slots - 1) * step + vlen;
      memset(read_buf, 0, wbytes);
      { size_t __ro = 0; memdbg_memory_read((int)req->pid, waddr, read_buf, wbytes, &__ro); }

      uint64_t pbytes = win_slots * vlen;

      const uint8_t *psrc = NULL;
      if (step == vlen) {
        psrc = read_buf;
      } else if (pack_buf) {
        for (uint64_t k = 0; k < win_slots; k++)
          memcpy(pack_buf + k * vlen, read_buf + k * step, vlen);
        psrc = pack_buf;
      }

      if (use_file && psrc) {
        if (!snapshot_store_write(&g_sessions[slot], psrc, gslot * vlen, pbytes))
          { fail = 1; break; }
      } else if (step == vlen) {
        if (snap_ram)
          memcpy(snap_ram + gslot * vlen, read_buf, pbytes);
      } else if (pack_buf) {
        if (snap_ram)
          memcpy(snap_ram + gslot * vlen, pack_buf, pbytes);
      }
      if (!include_zeros && psrc) {
        for (uint64_t k = 0; k < win_slots; k++) {
          const uint8_t *v = psrc + k * vlen;
          uint64_t b = 0;
          while (b < vlen && v[b] == 0) b++;
          if (b == vlen) { bitmap_clear(bitmap, gslot + k); /* don't count yet */ }
        }
      }

      s0   += win_slots;
      done_total += wbytes;
      if ((done_total & 0x3FFFFFULL) == 0 || s0 >= seg_ns)
        socket_send_all(fd, &done_total, 8);
    }
  }

  if (!include_zeros) {
    survivors = 0;
    for (uint64_t i = 0; i < slot_count; i++)
      if ((bitmap[i >> 3] >> (i & 7)) & 1) survivors++;
  }

  uint64_t sentinel = 0xFFFFFFFFFFFFFFFFULL;
  socket_send_all(fd, &sentinel, 8);

  if (!ok || fail) {
    munmap_anonymous(bitmap, bitmap_bytes);
    munmap_anonymous(snap_ram, ram_bytes);
    if (snap_fd >= 0) { close(snap_fd); char p[96]; snapshot_store_path(slot, p, "qs_snap_"); unlink(p); }
    if (first_fd >= 0) { close(first_fd); char p[96]; snapshot_store_path(slot, p, "qs_first_"); unlink(p); }
    if (prev_fd >= 0)  { close(prev_fd);  char p[96]; snapshot_store_path(slot, p, "qs_prev_"); unlink(p); }
    free(read_buf);
    free(pack_buf);
    free(seg);
    memdbg_quickscan_snapshot_summary_t sum = {0,0};
    socket_send_all(fd, &sum, sizeof(sum));
    return 0;
  }

  struct flashscan_sess *s = &g_sessions[slot];
  memset(s, 0, sizeof(*s));
  s->in_use          = 1;
  s->mode            = FLASHSCAN_MODE_SNAPSHOT;
  s->bitmap          = bitmap;
  s->bitmap_bytes    = bitmap_bytes;
  s->slot_count      = slot_count;
  s->survivor_count  = survivors;
  s->stride          = step;
  s->snap_ram        = snap_ram;
  s->snap_fd         = snap_fd;
  s->snap_bytes      = ram_bytes;
  s->first_fd        = keep_first ? first_fd : -1;
  s->has_first       = keep_first ? 1 : 0;
  s->prev_fd         = keep_prev ? prev_fd : -1;
  s->has_prev        = keep_prev ? 1 : 0;
  s->seg             = seg;
  s->nseg            = in_nseg;
  s->value_len       = vlen;
  s->pid             = (uint32_t)req->pid;
  s->value_type      = req->value_type;

  free(read_buf);
  free(pack_buf);

  memdbg_quickscan_snapshot_summary_t sum;
  sum.ok             = 1;
  sum.survivor_count = survivors;
  socket_send_all(fd, &sum, sizeof(sum));
  return 1;
}

