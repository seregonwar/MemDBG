/*
 * memDBG - FlashScan engine implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/scanner/flashscan.h"
#include "memdbg/scanner/pt_walker.h"
#include "memdbg/scanner/page_alias.h"
#include "memdbg/scanner/scan_simd.h"
#include "memdbg/scanner/scan_partition.h"

#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/debug/memdbg_process.h"
#include "memdbg/pal/pal_network.h"
#include "memdbg/pal/pal_memory.h"

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>

static int socket_send_int32(socket_t fd, int32_t val) {
  return (int)pal_socket_write_all(fd, &val, sizeof(val));
}

static int socket_send_all(socket_t fd, const void *buf, size_t len) {
  return (len > 0U) ? (int)pal_socket_write_all(fd, buf, len) : 0;
}

static int socket_recv_all(socket_t fd, void *buf, size_t len) {
  return (len > 0U) ? (int)pal_socket_read_exact(fd, buf, len) : 0;
}

static inline void *mmap_anonymous(uint64_t n) {
  void *m = mmap(NULL, (size_t)n, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
  return (m == MAP_FAILED) ? NULL : m;
}

static inline void munmap_anonymous(void *p, uint64_t n) {
  if (p) munmap(p, (size_t)n);
}

#define FS_RESCAN_GAP_MAX    0x8000ULL
#define FS_RESCAN_WIN_CAP    0x100000ULL
#define FS_RESCAN_ALIAS_MIN  0x10000ULL
#define FLASHSCAN_SNAPSHOT_BITMAP_MAX   (448ULL << 20)
#define FLASHSCAN_WORKERS           4U
#define FLASHSCAN_PARALLEL_WORKERS       4U
#define FLASHSCAN_PARALLEL_MAX_WORKERS   4U
#define FLASHSCAN_PARALLEL_RESULT_CAP    (8ULL << 20)
#define FLASHSCAN_PARALLEL_ARENA         (16ULL << 20)

#define FLASHSCAN_MODE_NONE     0
#define FLASHSCAN_MODE_LIST     1
#define FLASHSCAN_MODE_SNAPSHOT 2

struct fs_seg {
  uint64_t addr;
  uint64_t slot_start;
  uint64_t nslots;
};

struct flashscan_sess {
  int      in_use;
  int      mode;

  void    *buf;
  uint64_t buf_cap;
  uint64_t count;
  uint64_t rec_size;

  uint8_t *bitmap;
  uint64_t bitmap_bytes;
  uint64_t slot_count;
  uint64_t survivor_count;
  uint64_t stride;

  uint8_t *snap_ram;
  int      snap_fd;
  uint64_t snap_bytes;

  int      first_fd;
  uint8_t  has_first;
  int      prev_fd;
  uint8_t  has_prev;

  struct fs_seg *seg;
  uint32_t nseg;

  uint64_t value_len;
  uint32_t pid;
  uint32_t value_type;
};

static struct flashscan_sess g_sessions[FLASHSCAN_MAX_SESSIONS];
static page_alias_ctx_t *g_alias_ctxs[FLASHSCAN_MAX_SESSIONS];
static int g_session_owner_fd[FLASHSCAN_MAX_SESSIONS];
static pthread_mutex_t g_session_owner_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint64_t g_fs_ram_limit     = 512ULL << 20;
static char     g_fs_spill_dir[64] = "/data";
static int      g_fs_force_fail    = 0;
static volatile int g_fs_cancel_requested = 0;
static uint64_t g_fs_mat_max       = 1ULL << 20;

static int flashscan_pread_all(int fd, void *buf, uint64_t len, uint64_t off) {
  uint8_t *p = (uint8_t *)buf;
  uint64_t pos = 0;
  while (pos < len) {
    ssize_t r = pread(fd, p + pos, (size_t)(len - pos), (off_t)(off + pos));
    if (r <= 0) return 0;
    pos += (uint64_t)r;
  }
  return 1;
}

static int flashscan_pwrite_all(int fd, const void *buf, uint64_t len, uint64_t off) {
  const uint8_t *p = (const uint8_t *)buf;
  uint64_t pos = 0;
  while (pos < len) {
    ssize_t w = pwrite(fd, p + pos, (size_t)(len - pos), (off_t)(off + pos));
    if (w <= 0) return 0;
    pos += (uint64_t)w;
  }
  return 1;
}

static int snapshot_store_read(struct flashscan_sess *s, uint8_t *dst,
                     uint64_t off, uint64_t len) {
  if (off >= s->snap_bytes)
    return flashscan_pread_all(s->snap_fd, dst, len, off - s->snap_bytes);
  if (off + len <= s->snap_bytes) {
    memcpy(dst, s->snap_ram + off, len);
    return 1;
  }
  uint64_t a = s->snap_bytes - off;
  memcpy(dst, s->snap_ram + off, a);
  return flashscan_pread_all(s->snap_fd, dst + a, len - a, 0);
}

static int snapshot_store_write(struct flashscan_sess *s, const uint8_t *src,
                      uint64_t off, uint64_t len) {
  if (off >= s->snap_bytes)
    return flashscan_pwrite_all(s->snap_fd, src, len, off - s->snap_bytes);
  if (off + len <= s->snap_bytes) {
    memcpy(s->snap_ram + off, src, len);
    return 1;
  }
  uint64_t a = s->snap_bytes - off;
  memcpy(s->snap_ram + off, src, a);
  return flashscan_pwrite_all(s->snap_fd, src + a, len - a, 0);
}

static void snapshot_store_path(unsigned slot, char *out, const char *tag) {
  int n = snprintf(out, 96, "%s/%s%02u.bin",
                   g_fs_spill_dir, tag, slot);
  (void)n;
}

static struct flashscan_sess *session_get(unsigned slot) {
  if (slot >= FLASHSCAN_MAX_SESSIONS) return NULL;
  return &g_sessions[slot];
}

static void alias_context_free_slot(unsigned slot) {
  if (slot >= FLASHSCAN_MAX_SESSIONS) return;
  if (g_alias_ctxs[slot]) {
    page_alias_end(g_alias_ctxs[slot]);
    g_alias_ctxs[slot] = NULL;
  }
}

static page_alias_ctx_t *alias_context_get(unsigned slot, uint32_t pid) {
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

static inline void bitmap_clear(uint8_t *bm, uint64_t i) {
  /* Atomic clear: necessary because parallel rescan workers may clear
     different bits within the same byte concurrently.  Plain &= would
     lose one update when the read-modify-write races across threads.
     __sync_fetch_and_and provides a full barrier on all architectures. */
  (void)__sync_fetch_and_and(&bm[i >> 3], (uint8_t)~(1u << (i & 7)));
}

static uint64_t bitmap_next_set(const uint8_t *bm, uint64_t from, uint64_t n) {
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

static uint64_t slot_to_addr(const struct flashscan_sess *s, uint64_t i) {
  const struct fs_seg *seg = s->seg;
  uint32_t lo = 0, hi = s->nseg;
  while (lo + 1 < hi) {
    uint32_t mid = (lo + hi) >> 1;
    if (seg[mid].slot_start <= i) lo = mid; else hi = mid;
  }
  return seg[lo].addr + (i - seg[lo].slot_start) * s->stride;
}

static struct flashscan_sess *session_alloc(unsigned slot, uint32_t pid,
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

static int snapshot_create(int fd, unsigned slot,
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

static const uint8_t *flashscan_window_read(page_alias_ctx_t *actx, uint32_t pid,
                                  uint64_t win_start, uint64_t read_size,
                                  uint8_t *fallback, int *aliased) {
  *aliased = 0;
  if (actx && read_size >= FS_RESCAN_ALIAS_MIN) {
    const void *ap = page_alias_map(actx, win_start, read_size, NULL);
    if (ap) { *aliased = 1; return (const uint8_t *)ap; }
  }
  memset(fallback, 0, read_size);
  { size_t __ro = 0; memdbg_memory_read((int)pid, win_start, fallback, read_size, &__ro); }
  return fallback;
}

static uint64_t snapshot_rescan(int fd, struct flashscan_sess *s,
                                uint32_t cmp_type, uint32_t val_type,
                                uint64_t vlen,
                                const uint8_t *pattern, const uint8_t *mask,
                                const uint8_t *between_hi, int includes_prev,
                                uint8_t *read_buf, uint8_t *bl_buf,
                                page_alias_ctx_t *actx) {
  (void)fd;
  (void)val_type;
  if (!s->bitmap || s->slot_count == 0) { s->survivor_count = 0; return 0; }
  uint64_t n = s->slot_count, survivors = 0;
  uint64_t rb = s->snap_bytes;

  for (uint64_t i = bitmap_next_set(s->bitmap, 0, n); i < n; ) {
    if (g_fs_cancel_requested) break;
    uint64_t win_start = slot_to_addr(s, i);
    uint64_t covered   = win_start + vlen;
    uint64_t last = i;
    for (uint64_t j = bitmap_next_set(s->bitmap, i + 1, n); j < n;
         j = bitmap_next_set(s->bitmap, j + 1, n)) {
      uint64_t na  = slot_to_addr(s, j);
      uint64_t gap = (na > covered) ? (na - covered) : 0;
      if (gap > FS_RESCAN_GAP_MAX) break;
      uint64_t ne = na + vlen;
      if (ne - win_start > FS_RESCAN_WIN_CAP) break;
      covered = ne; last = j;
    }
    uint64_t read_size = covered - win_start;
    int win_aliased;
    const uint8_t *win = flashscan_window_read(actx, s->pid, win_start, read_size,
                                     read_buf, &win_aliased);

    uint64_t bl_off = i * vlen, bl_len = (last - i + 1) * vlen;
    uint8_t *bl;
    int buffered = (bl_off + bl_len > rb);
    if (buffered) {
      if (!snapshot_store_read(s, bl_buf, bl_off, bl_len)) break;
      bl = bl_buf;
    } else {
      bl = s->snap_ram + bl_off;
    }

    int dirty = 0;
    for (uint64_t k = i; k <= last; k = bitmap_next_set(s->bitmap, k + 1, n)) {
      uint64_t addr = slot_to_addr(s, k);
      const uint8_t *mem_p  = win + (addr - win_start);
      uint8_t       *base_p = bl + (k - i) * vlen;
      const uint8_t *prev_p = includes_prev ? base_p : between_hi;

      int matched = snap_compare(mem_p, pattern, prev_p, mask, between_hi,
                                  cmp_type, vlen);

      if (matched) {
        if (s->has_prev)
          flashscan_pwrite_all(s->prev_fd, base_p, vlen, k * vlen);
        memcpy(base_p, mem_p, vlen);
        dirty = 1;
        survivors++;
      } else {
        bitmap_clear(s->bitmap, k);
      }
    }
    if (win_aliased) page_alias_release(actx);
    if (buffered && dirty)
      snapshot_store_write(s, bl, bl_off, bl_len);

    i = bitmap_next_set(s->bitmap, last + 1, n);
  }
  s->survivor_count = survivors;
  return survivors;
}

struct rescan_worker_ctx {
  struct flashscan_sess *s;
  uint32_t       cmp_type;
  uint32_t       val_type;
  uint64_t       vlen;
  const uint8_t *pattern;
  const uint8_t *mask;
  const uint8_t *between_hi;
  int            includes_prev;
  uint64_t       chunk_start;  /* first slot index for this worker */
  uint64_t       chunk_end;    /* one-past-last slot index for this worker */
  uint64_t      *survivors_out;
  uint32_t       worker_id;
};

static void *rescan_worker_thread(void *arg) {
  struct rescan_worker_ctx *c = (struct rescan_worker_ctx *)arg;
  struct flashscan_sess *s = c->s;
  uint64_t survivors = 0;
  uint64_t vlen = c->vlen, rb = s->snap_bytes;

  uint8_t *read_buf = (uint8_t *)malloc(FS_RESCAN_WIN_CAP);
  uint8_t *bl_buf   = (uint8_t *)malloc(FS_RESCAN_WIN_CAP);
  if (!read_buf || !bl_buf) {
    free(read_buf); free(bl_buf);
    if (c->survivors_out) *c->survivors_out = 0;
    return NULL;
  }

  page_alias_ctx_t *actx = page_alias_begin(s->pid, 0);

  uint64_t i = bitmap_next_set(s->bitmap, c->chunk_start, c->chunk_end);

  while (i < c->chunk_end) {
    if (g_fs_cancel_requested) break;
    uint64_t win_start = slot_to_addr(s, i);
    uint64_t covered   = win_start + vlen;
    uint64_t last = i;
    for (uint64_t j = bitmap_next_set(s->bitmap, i + 1, c->chunk_end);
         j < c->chunk_end;
         j = bitmap_next_set(s->bitmap, j + 1, c->chunk_end)) {
      uint64_t na  = slot_to_addr(s, j);
      uint64_t gap = (na > covered) ? (na - covered) : 0;
      if (gap > FS_RESCAN_GAP_MAX) break;
      uint64_t ne = na + vlen;
      if (ne - win_start > FS_RESCAN_WIN_CAP) break;
      covered = ne; last = j;
    }

    uint64_t read_size = covered - win_start;
    int win_aliased;
    const uint8_t *win = flashscan_window_read(actx, s->pid, win_start, read_size,
                                     read_buf, &win_aliased);

    uint64_t bl_off = i * vlen, bl_len = (last - i + 1) * vlen;
    uint8_t *bl;
    int buffered = (bl_off + bl_len > rb);
    if (buffered) {
      if (!snapshot_store_read(s, bl_buf, bl_off, bl_len)) break;
      bl = bl_buf;
    } else {
      bl = s->snap_ram + bl_off;
    }

    int dirty = 0;
    for (uint64_t k = i;
         k <= last;
         k = bitmap_next_set(s->bitmap, k + 1, c->chunk_end)) {
      uint64_t addr = slot_to_addr(s, k);
      const uint8_t *mem_p  = win + (addr - win_start);
      uint8_t       *base_p = bl + (k - i) * vlen;
      const uint8_t *prev_p = c->includes_prev ? base_p : c->between_hi;

      int matched = snap_compare(mem_p, c->pattern, prev_p, c->mask,
                                  c->between_hi, c->cmp_type, c->vlen);

      if (matched) {
        if (s->has_prev)
          flashscan_pwrite_all(s->prev_fd, base_p, vlen, k * vlen);
        memcpy(base_p, mem_p, vlen);
        dirty = 1;
        survivors++;
      } else {
        bitmap_clear(s->bitmap, k);
      }
    }
    if (win_aliased) page_alias_release(actx);
    if (buffered && dirty)
      snapshot_store_write(s, bl, bl_off, bl_len);

    i = bitmap_next_set(s->bitmap, last + 1, c->chunk_end);
  }

  if (actx) page_alias_end(actx);
  free(read_buf); free(bl_buf);

  if (c->survivors_out)
    *c->survivors_out = survivors;
  return NULL;
}

static uint64_t snapshot_rescan_parallel(int fd, struct flashscan_sess *s,
                                         uint32_t cmp_type, uint32_t val_type,
                                         uint64_t vlen,
                                         const uint8_t *pattern, const uint8_t *mask,
                                         const uint8_t *between_hi, int includes_prev) {
  if (!s->bitmap || s->slot_count == 0) { s->survivor_count = 0; return 0; }
  uint64_t n = s->slot_count;

  uint32_t nworkers = FLASHSCAN_PARALLEL_WORKERS;
  if (nworkers > FLASHSCAN_PARALLEL_MAX_WORKERS) nworkers = FLASHSCAN_PARALLEL_MAX_WORKERS;
  if (nworkers == 0) nworkers = 1;
  if (n < (uint64_t)nworkers * 64) nworkers = 1;  /* not worth parallelising */

  if (nworkers == 1) {
    uint8_t *rb = (uint8_t *)malloc(FS_RESCAN_WIN_CAP);
    uint8_t *bb = (uint8_t *)malloc(FS_RESCAN_WIN_CAP);
    if (!rb || !bb) {
      free(rb); free(bb);
      s->survivor_count = 0;
      return 0;
    }
    uint64_t nc = snapshot_rescan(fd, s, cmp_type, val_type, vlen,
                           pattern, mask, between_hi, includes_prev,
                           rb, bb, NULL);
    free(rb); free(bb);
    return nc;
  }

  struct rescan_worker_ctx *ctxs =
      (struct rescan_worker_ctx *)calloc(nworkers, sizeof(*ctxs));
  uint64_t *surv = (uint64_t *)calloc(nworkers, sizeof(uint64_t));
  pthread_t *tids = (pthread_t *)calloc(nworkers, sizeof(pthread_t));

  if (!ctxs || !surv || !tids) {
    free(ctxs); free(surv); free(tids);
    uint8_t *rb = (uint8_t *)malloc(FS_RESCAN_WIN_CAP);
    uint8_t *bb = (uint8_t *)malloc(FS_RESCAN_WIN_CAP);
    if (!rb || !bb) {
      free(rb); free(bb);
      s->survivor_count = 0;
      return 0;
    }
    uint64_t nc = snapshot_rescan(fd, s, cmp_type, val_type, vlen,
                           pattern, mask, between_hi, includes_prev,
                           rb, bb, NULL);
    free(rb); free(bb);
    return nc;
  }

  uint64_t chunk_size = (n + nworkers - 1) / nworkers;

  for (uint32_t w = 0; w < nworkers; w++) {
    ctxs[w].s             = s;
    ctxs[w].cmp_type      = cmp_type;
    ctxs[w].val_type      = val_type;
    ctxs[w].vlen          = vlen;
    ctxs[w].pattern       = pattern;
    ctxs[w].mask          = mask;
    ctxs[w].between_hi    = between_hi;
    ctxs[w].includes_prev = includes_prev;
    ctxs[w].chunk_start   = w * chunk_size;
    ctxs[w].chunk_end     = (w + 1 == nworkers) ? n : ((w + 1) * chunk_size);
    ctxs[w].survivors_out = &surv[w];
    ctxs[w].worker_id     = w;

    if (pthread_create(&tids[w], NULL, rescan_worker_thread, &ctxs[w]) != 0) {
      /* pthread_create failed -- mark this slot so the join loop runs
         it inline instead of calling pthread_join on an invalid tid. */
      ctxs[w].survivors_out = NULL;
      surv[w] = 0;
      tids[w] = (pthread_t)0;
    }
  }  // Workers launched; progress sent as workers finish via the join loop
  (void)fd;

  uint64_t total_survivors = 0;
  for (uint32_t w = 0; w < nworkers; w++) {
    if (ctxs[w].survivors_out != NULL) {
      pthread_join(tids[w], NULL);
      total_survivors += surv[w];
    } else {
      /* This worker was launched inline because pthread_create failed;
         run it synchronously now. */
      ctxs[w].survivors_out = &surv[w];
      rescan_worker_thread(&ctxs[w]);
      total_survivors += surv[w];
    }
  }

  free(ctxs); free(surv); free(tids);
  s->survivor_count = total_survivors;
  return total_survivors;
}

static uint32_t snapshot_fetch(int fd, struct flashscan_sess *s,
                               uint32_t start, uint32_t count,
                               uint8_t *out_buf, uint64_t out_cap) {
  uint64_t vlen = s->value_len, n = s->slot_count;
  int has_first = s->has_first;
  uint32_t actual = 0;

  if (start < s->survivor_count) {
    uint64_t avail = s->survivor_count - start;
    actual = (count < avail) ? count : (uint32_t)avail;
  }

  uint32_t hdr = actual | (has_first ? 0x80000000u : 0u);
  socket_send_all(fd, &hdr, 4);
  if (actual == 0 || !s->bitmap) return 0;

  uint64_t ent = 8 + vlen * (has_first ? 3 : 2);
  uint64_t out_len = 0, seen = 0, emitted = 0;

  for (uint64_t i = bitmap_next_set(s->bitmap, 0, n); i < n && emitted < actual;
       i = bitmap_next_set(s->bitmap, i + 1, n)) {
    if (seen < start) { seen++; continue; }
    uint64_t addr = slot_to_addr(s, i);
    if (out_len + ent > out_cap) {
      socket_send_all(fd, out_buf, (size_t)out_len);
      out_len = 0;
    }
    uint8_t *o = out_buf + out_len;
    memcpy(o, &addr, 8);
    snapshot_store_read(s, o + 8, i * vlen, vlen);
    if (s->has_prev)
      flashscan_pread_all(s->prev_fd, o + 8 + vlen, vlen, i * vlen);
    else
      memcpy(o + 8 + vlen, o + 8, vlen);
    if (has_first)
      flashscan_pread_all(s->first_fd, o + 8 + 2 * vlen, vlen, i * vlen);
    out_len += ent; emitted++; seen++;
  }
  if (out_len) socket_send_all(fd, out_buf, (size_t)out_len);
  return (uint32_t)emitted;
}

static int snapshot_materialize(unsigned slot, struct flashscan_sess *s) {
  uint64_t vlen = s->value_len;
  int has_first = s->has_first, has_prev = s->has_prev;

  uint64_t rec_size = 8 + vlen * (1 + (has_prev ? 1U : 0U) + (has_first ? 1U : 0U));
  uint64_t records = s->survivor_count;
  if (records == 0 || rec_size * records > FS_RESCAN_WIN_CAP * 2) return 0;

  uint64_t bytes = records * rec_size;
  void *buf = mmap_anonymous(bytes);
  if (!buf) return 0;

  uint64_t rb = s->snap_bytes;
  uint8_t *recs = (uint8_t *)buf;
  uint64_t n = s->slot_count, out = 0;

  for (uint64_t i = bitmap_next_set(s->bitmap, 0, n); i < n && out < records;
       i = bitmap_next_set(s->bitmap, i + 1, n)) {
    const uint8_t *val;
    uint64_t voff = i * vlen;
    uint8_t small_val[8];
    if (voff >= rb) {
      if (!flashscan_pread_all(s->snap_fd, small_val, vlen, voff - rb))
        { munmap_anonymous(buf, bytes); return 0; }
      val = small_val;
    } else {
      val = s->snap_ram + voff;
    }
    uint64_t addr = slot_to_addr(s, i);
    uint8_t *rec = recs + out * rec_size;
    memcpy(rec, &addr, 8);
    memcpy(rec + 8, val, vlen);
    uint64_t prev_off = 8 + vlen;
    uint64_t first_off = 8 + vlen + (has_prev ? vlen : 0);
    if (has_prev) {
      if (!flashscan_pread_all(s->prev_fd, rec + prev_off, vlen, voff))
        { munmap_anonymous(buf, bytes); return 0; }
    }
    if (has_first) {
      if (!flashscan_pread_all(s->first_fd, rec + first_off, vlen, voff))
        { munmap_anonymous(buf, bytes); return 0; }
    }
    out++;
  }

  munmap_anonymous(s->snap_ram, s->snap_bytes);
  munmap_anonymous(s->bitmap,   s->bitmap_bytes);
  if (s->snap_fd > 0) close(s->snap_fd);
  if (s->first_fd > 0) close(s->first_fd);
  if (s->prev_fd > 0) close(s->prev_fd);
  if (s->seg) free(s->seg);
  { char path[96];
    snapshot_store_path(slot, path, "qs_snap_");  unlink(path);
    if (has_first) { snapshot_store_path(slot, path, "qs_first_"); unlink(path); }
    if (has_prev)  { snapshot_store_path(slot, path, "qs_prev_");  unlink(path); }
  }

  uint32_t pid = s->pid; uint32_t vt = s->value_type;
  memset(s, 0, sizeof(*s));
  s->in_use     = 1;
  s->mode       = FLASHSCAN_MODE_LIST;
  s->buf        = buf;
  s->buf_cap    = bytes;
  s->count      = out;
  s->rec_size   = rec_size;
  s->value_len  = vlen;
  s->pid        = pid;
  s->value_type = vt;
  s->has_first  = (uint8_t)has_first;
  s->first_fd   = -1;
  s->has_prev   = (uint8_t)has_prev;
  s->prev_fd    = -1;
  return 1;
}

static int scan_range_stream(int fd,
                             const memdbg_quickscan_start_request_t *req,
                             uint64_t scan_addr, uint64_t scan_len,
                             uint64_t vlen, uint64_t step,
                             const uint8_t *pattern, const uint8_t *mask,
                             const uint8_t *between_hi, int simd_ok,
                             uint8_t *read_buf, uint64_t chunk_size,
                             uint8_t *result_buf, uint32_t *simd_offs,
                             uint64_t simd_max,
                             struct flashscan_sess *sess,
                             page_alias_ctx_t *actx) {
  uint64_t addr = scan_addr;
  uint64_t remaining = scan_len;
  uint64_t result_len = 0;
  uint64_t flush_thresh = 0x3FFE8ULL - vlen;

  while (remaining > 0) {
    uint64_t to_read = (remaining > chunk_size) ? chunk_size : remaining;

    const uint8_t *src;
    const void *aptr = actx ? page_alias_map(actx, addr, to_read, NULL) : NULL;
    if (aptr) {
      src = (const uint8_t *)aptr;
    } else {
      memset(read_buf, 0, to_read);
      { size_t __ro = 0; memdbg_memory_read((int)req->pid, addr, read_buf, to_read, &__ro); }
      src = read_buf;
    }

    if (simd_ok) {
      size_t nm = memdbg_simd_find_exact(req->value_type, src, to_read,
                                         pattern, (uint32_t)vlen, simd_offs, simd_max);
      for (size_t k = 0; k < nm; k++) {
        uint32_t coff = simd_offs[k];
        if (sess) {
          if ((sess->count + 1) * sess->rec_size > sess->buf_cap) {
            if (aptr) page_alias_release(actx);
            return 0;
          }
          uint8_t *rec = (uint8_t *)sess->buf + sess->count * sess->rec_size;
          uint64_t a = addr + coff;
          memcpy(rec, &a, 8);
          memcpy(rec + 8, &src[coff], vlen);
          sess->count++;
        } else {
          if (result_len > flush_thresh) {
            *(uint64_t *)result_buf = result_len;
            socket_send_all(fd, result_buf, (size_t)(result_len + 8));
            result_len = 0;
          }
          uint32_t offset = (uint32_t)((addr + coff) - req->address);
          memcpy(result_buf + 8 + result_len,     &offset, 4);
          memcpy(result_buf + 8 + result_len + 4, &src[coff], vlen);
          result_len += 4 + vlen;
        }
      }
    } else {
      uint64_t limit = (to_read >= vlen) ? to_read - vlen : 0;
      for (uint64_t j = 0; j <= limit; j += step) {
        int matched;
        if (req->compare_type == 0 && mask == NULL) {
          matched = (memcmp(&src[j], pattern, vlen) == 0);
        } else if (req->compare_type == 4 && between_hi) {
          matched = (memcmp(&src[j], pattern, vlen) >= 0 &&
                     memcmp(&src[j], between_hi, vlen) <= 0);
        } else {
          matched = (memcmp(&src[j], pattern, vlen) == 0);
        }

        if (matched) {
          if (sess) {
            if ((sess->count + 1) * sess->rec_size > sess->buf_cap) {
              if (aptr) page_alias_release(actx);
              return 0;
            }
            uint8_t *rec = (uint8_t *)sess->buf + sess->count * sess->rec_size;
            uint64_t a = addr + j;
            memcpy(rec, &a, 8);
            memcpy(rec + 8, &src[j], vlen);
            sess->count++;
          } else {
            if (result_len > flush_thresh) {
              *(uint64_t *)result_buf = result_len;
              socket_send_all(fd, result_buf, (size_t)(result_len + 8));
              result_len = 0;
            }
            uint32_t offset = (uint32_t)((addr + j) - req->address);
            memcpy(result_buf + 8 + result_len,     &offset, 4);
            memcpy(result_buf + 8 + result_len + 4, &src[j], vlen);
            result_len += 4 + vlen;
          }
        }
      }
    }

    if (aptr) page_alias_release(actx);

    uint64_t advance = to_read + step - vlen;
    if (advance == 0 || advance > to_read) advance = to_read;
    addr += advance;
    remaining = (remaining > advance) ? remaining - advance : 0;
  }

  if (!sess && result_len) {
    *(uint64_t *)result_buf = result_len;
    socket_send_all(fd, result_buf, (size_t)(result_len + 8));
  }
  return 1;
}

struct flashscan_parallel_worker {
  const memdbg_quickscan_start_request_t *req;
  uint64_t scan_addr;
  uint64_t scan_len;
  uint64_t value_len;
  uint64_t step;
  uint64_t chunk_size;
  uint64_t simd_max;
  const uint8_t *pattern;
  const uint8_t *mask;
  const uint8_t *between_hi;
  uint8_t *read_buf;
  uint32_t *simd_offsets;
  page_alias_ctx_t *alias_ctx;
  struct flashscan_sess result;
  int ok;
};

static void *flashscan_parallel_worker_run(void *arg) {
  struct flashscan_parallel_worker *worker =
      (struct flashscan_parallel_worker *)arg;
  worker->ok = scan_range_stream(
      -1, worker->req, worker->scan_addr, worker->scan_len,
      worker->value_len, worker->step, worker->pattern, worker->mask,
      worker->between_hi, 1, worker->read_buf, worker->chunk_size, NULL,
      worker->simd_offsets, worker->simd_max, &worker->result,
      worker->alias_ctx);
  return NULL;
}

static int flashscan_parallel_stream(
    int fd, const memdbg_quickscan_start_request_t *req,
    uint64_t value_len, uint64_t step, const uint8_t *pattern,
    const uint8_t *mask, const uint8_t *between_hi, int simd_ok,
    uint64_t chunk_size, uint64_t simd_max) {
  if ((req->request_flags & MEMDBG_QS_FL_PARALLEL) == 0U || !simd_ok ||
      req->length < value_len * 2U)
    return 0;

  uint32_t worker_count = FLASHSCAN_PARALLEL_WORKERS;
  if (worker_count > FLASHSCAN_PARALLEL_MAX_WORKERS)
    worker_count = FLASHSCAN_PARALLEL_MAX_WORKERS;
  uint64_t span = (req->length + worker_count - 1U) / worker_count;
  span = ((span + value_len - 1U) / value_len) * value_len;
  if (span == 0U) return 0;
  worker_count = (uint32_t)((req->length + span - 1U) / span);
  if (worker_count <= 1U || worker_count > FLASHSCAN_PARALLEL_MAX_WORKERS)
    return 0;

  struct flashscan_parallel_worker *workers =
      (struct flashscan_parallel_worker *)calloc(worker_count,
                                                  sizeof(*workers));
  pthread_t threads[FLASHSCAN_PARALLEL_MAX_WORKERS];
  uint8_t spawned[FLASHSCAN_PARALLEL_MAX_WORKERS] = {0U};
  if (workers == NULL) return 0;

  int allocation_ok = 1;
  uint32_t record_size = (uint32_t)(8U + value_len);
  for (uint32_t i = 0U; i < worker_count; ++i) {
    uint64_t offset = (uint64_t)i * span;
    uint64_t length = offset + span <= req->length
                          ? span
                          : req->length - offset;
    workers[i].req = req;
    workers[i].scan_addr = req->address + offset;
    workers[i].scan_len = length;
    workers[i].value_len = value_len;
    workers[i].step = step;
    workers[i].chunk_size = chunk_size;
    workers[i].simd_max = simd_max;
    workers[i].pattern = pattern;
    workers[i].mask = mask;
    workers[i].between_hi = between_hi;
    workers[i].read_buf = (uint8_t *)malloc(chunk_size);
    workers[i].simd_offsets =
        (uint32_t *)malloc((size_t)simd_max * sizeof(uint32_t));
    workers[i].result.buf = mmap_anonymous(FLASHSCAN_PARALLEL_RESULT_CAP);
    workers[i].result.buf_cap = FLASHSCAN_PARALLEL_RESULT_CAP;
    workers[i].result.rec_size = record_size;
    workers[i].result.value_len = value_len;
    workers[i].alias_ctx =
        page_alias_begin((uint32_t)req->pid, FLASHSCAN_PARALLEL_ARENA);
    /* PS5 normally reads through page aliases; PS4 has no DMAP alias engine
       and uses independent mdbg reads instead. A missing alias must therefore
       not disable the common parallel SIMD path. */
    if (workers[i].read_buf == NULL || workers[i].simd_offsets == NULL ||
        workers[i].result.buf == NULL)
      allocation_ok = 0;
  }

  int handled = 0;
  if (allocation_ok) {
    /* Keep one partition on the caller thread: four partitions require only
       three additional threads and avoid an unnecessary context switch. */
    for (uint32_t i = 1U; i < worker_count; ++i) {
      if (pthread_create(&threads[i], NULL, flashscan_parallel_worker_run,
                         &workers[i]) == 0)
        spawned[i] = 1U;
    }
    (void)flashscan_parallel_worker_run(&workers[0]);
    for (uint32_t i = 1U; i < worker_count; ++i) {
      if (spawned[i] != 0U)
        (void)pthread_join(threads[i], NULL);
      else
        (void)flashscan_parallel_worker_run(&workers[i]);
    }

    int all_ok = 1;
    for (uint32_t i = 0U; i < worker_count; ++i)
      if (!workers[i].ok) all_ok = 0;

    if (all_ok) {
      uint8_t *output = (uint8_t *)malloc(0x40000U);
      if (output != NULL) {
        uint64_t output_len = 0U;
        uint64_t flush_threshold = 0x3FFE8ULL - value_len;
        for (uint32_t i = 0U; i < worker_count; ++i) {
          uint8_t *records = (uint8_t *)workers[i].result.buf;
          for (uint64_t r = 0U; r < workers[i].result.count; ++r) {
            uint8_t *record = records + r * record_size;
            uint64_t address = 0U;
            memcpy(&address, record, sizeof(address));
            uint32_t offset = (uint32_t)(address - req->address);
            if (output_len > flush_threshold) {
              memcpy(output, &output_len, sizeof(output_len));
              (void)socket_send_all(fd, output,
                                    (size_t)(output_len + 8U));
              output_len = 0U;
            }
            memcpy(output + 8U + output_len, &offset, sizeof(offset));
            memcpy(output + 12U + output_len, record + 8U, value_len);
            output_len += 4U + value_len;
          }
        }
        if (output_len != 0U) {
          memcpy(output, &output_len, sizeof(output_len));
          (void)socket_send_all(fd, output, (size_t)(output_len + 8U));
        }
        free(output);
        /* Worker output has now been consumed.  Even a peer-side network
           failure must not trigger a duplicate serial scan/response. */
        handled = 1;
      }
    }
  }

  for (uint32_t i = 0U; i < worker_count; ++i) {
    if (workers[i].alias_ctx != NULL) page_alias_end(workers[i].alias_ctx);
    free(workers[i].read_buf);
    free(workers[i].simd_offsets);
    munmap_anonymous(workers[i].result.buf,
                     workers[i].result.buf_cap);
  }
  free(workers);
  return handled;
}

int flashscan_handle_caps(int fd) {
  memdbg_quickscan_caps_response_t resp;
  memset(&resp, 0, sizeof(resp));
  resp.protocol_vers = 1;
  resp.engine_flags  = MEMDBG_QS_F_SIMD | MEMDBG_QS_F_RESIDENT |
                       MEMDBG_QS_F_SNAPSHOT | MEMDBG_QS_F_SNAP_CONFIG |
                       MEMDBG_QS_F_SNAP_FIRST |
                       MEMDBG_QS_F_SNAP_PREVIOUS | MEMDBG_QS_F_PARALLEL |
                       MEMDBG_QS_F_ALIAS_RESCAN;
  resp.max_workers   = FLASHSCAN_WORKERS;
  socket_send_int32(fd, 0);
  socket_send_all(fd, &resp, sizeof(resp));
  return 0;
}

int flashscan_handle_config(int fd, const memdbg_quickscan_config_request_t *req,
                            const uint8_t *extra, uint32_t path_len) {
  g_fs_ram_limit = req->ram_limit_mb ? ((uint64_t)req->ram_limit_mb << 20)
                                     : (512ULL << 20);
  if (path_len > 0 && path_len < sizeof(g_fs_spill_dir)) {
    memcpy(g_fs_spill_dir, extra, path_len);
    g_fs_spill_dir[path_len] = 0;
  }
  socket_send_int32(fd, 0);
  return 0;
}

int flashscan_handle_regions(int fd, const memdbg_quickscan_regions_request_t *req) {
  memdbg_map_list_t map_list;
  if (memdbg_process_maps_cached(req->pid, &map_list) != 0 ||
      map_list.count <= 0) {
    socket_send_int32(fd, -1);
    return 1;
  }

  memdbg_map_entry_t *e = map_list.entries;
  int count = (int)map_list.count;
  uint32_t cap = req->region_max ? req->region_max : 1024;
  if (cap > 8192) cap = 8192;
  uint32_t probe_bytes = req->probe_bytes ? req->probe_bytes : 65536;
  if (probe_bytes > 0x100000) probe_bytes = 0x100000;

  memdbg_quickscan_region_info_t *out =
      (memdbg_quickscan_region_info_t *)malloc((size_t)cap * sizeof(*out));
  uint8_t *probe = (uint8_t *)malloc(probe_bytes);
  if (!out || !probe) { free(out); free(probe); memdbg_process_maps_free(&map_list); socket_send_int32(fd, -1); return 1; }

  uint32_t n = 0;
  for (int i = 0; i < count && n < cap; i++) {
    if (!(e[i].protection & 1)) continue;
    uint64_t st = e[i].start, en = e[i].end;
    if (en <= st) continue;

    // PCD check
    uint32_t rflags = 0;
    uint64_t pte = 0, ph = 0, pg = 0; int lv = -1;
    if (ptw_probe((uint32_t)req->pid, st, &ph, &lv, &pg, &pte) == 0)
      if ((pte >> 4) & 1) rflags |= 1u;

    // Throughput measurement
    uint64_t pb = (en - st) < probe_bytes ? (en - st) : probe_bytes;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    { size_t __ro = 0; memdbg_memory_read((int)req->pid, st, probe, pb, &__ro); }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double dt = (double)(t1.tv_sec - t0.tv_sec) +
                (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    double mbps = dt > 0 ? ((double)pb / 1e6) / dt : 0.0;
    if (mbps < 0.0) mbps = 0.0;
    if (mbps > 4294967295.0) mbps = 4294967295.0;

    out[n].start      = st;
    out[n].end        = en;
    out[n].protection = e[i].protection;
    out[n].flags      = rflags;
    out[n].read_mbps  = (uint32_t)mbps;
    out[n].reserved   = 0;
    n++;
  }

  socket_send_int32(fd, 0);
  socket_send_all(fd, &n, 4);
  if (n) socket_send_all(fd, out, (size_t)n * sizeof(*out));
  socket_send_int32(fd, 0);

  free(out); free(probe); memdbg_process_maps_free(&map_list);
  return 0;
}

int flashscan_handle_start(int fd,
                           const memdbg_quickscan_start_request_t *req,
                           const uint8_t *compare_data,
                           const uint8_t *mask,
                           unsigned int slot) {
  int want_snap = (req->request_flags & MEMDBG_QS_FL_SNAPSHOT) != 0;

  uint64_t vlen = req->value_length;
  if (vlen == 0) vlen = 4;
  if (vlen > 16 || (vlen == 0 && !want_snap)) {
    socket_send_int32(fd, -1); return 1;
  }

  int needs_data = ((1u << req->compare_type) & 0x114Fu) != 0;
  int is_between = (req->compare_type == 4);

  uint8_t *pattern = NULL;
  if (needs_data && vlen > 0) {
    pattern = (uint8_t *)malloc(vlen * 2);
    if (!pattern) { socket_send_int32(fd, -1); return 1; }
    memcpy(pattern, compare_data, vlen * (is_between ? 2 : 1));
  }

  uint64_t step = req->alignment ? req->alignment : vlen;
  uint64_t chunk_size = 0x100000ULL;
  if (chunk_size % vlen) chunk_size = (chunk_size / vlen) * vlen;
  if (chunk_size == 0) chunk_size = vlen;

  uint8_t *read_buf   = (uint8_t *)malloc(chunk_size);
  uint8_t *result_buf = (uint8_t *)malloc(0x40000);

  int simd_ok = (req->compare_type == 0) && mask == NULL && (step == vlen);
  uint32_t *simd_offs = NULL;
  uint64_t  simd_max  = 0;
  if (simd_ok) {
    simd_max = chunk_size / vlen;
    if (simd_max > MEMDBG_SIMD_MAX_OFFSETS) simd_max = MEMDBG_SIMD_MAX_OFFSETS;
    simd_offs = (uint32_t *)malloc((size_t)(simd_max * 4));
    if (!simd_offs) simd_ok = 0;
  }

  if (!read_buf || !result_buf) {
    free(read_buf); free(result_buf);
    free(simd_offs); free(pattern);
    socket_send_int32(fd, -1); return 1;
  }

  socket_send_int32(fd, 0);  /* ack 1 */
  socket_send_int32(fd, 0);  /* ack 2 */

  if (want_snap) {
    memdbg_quickscan_segment_t *segs = NULL;
    uint32_t nseg = 0;
    memdbg_quickscan_segment_t one;
    one.address = req->address;
    one.length  = (uint32_t)req->length;
    one.reserved = 0;

    int seg_ok = 1;

    if (req->request_flags & MEMDBG_QS_FL_SNAP_SEGMENTS) {
      /* Read segment list from client */
      socket_recv_all(fd, &nseg, 4);
      if (nseg >= 1 && nseg <= MEMDBG_QUICKSCAN_MAX_SEGMENTS) {
        segs = (memdbg_quickscan_segment_t *)malloc(
            (size_t)nseg * sizeof(*segs));
        if (segs)
          socket_recv_all(fd, segs, (size_t)(nseg * sizeof(*segs)));
        else
          seg_ok = 0;
      } else { seg_ok = 0; }
    } else {
      segs = &one;
      nseg = 1;
    }

    if (!seg_ok || vlen > 8 || vlen == 0) {
      memdbg_quickscan_snapshot_plan_t plan = {0,0};
      socket_send_all(fd, &plan, sizeof(plan));
      uint64_t sent = 0xFFFFFFFFFFFFFFFFULL;
      socket_send_all(fd, &sent, 8);
      memdbg_quickscan_snapshot_summary_t sum = {0,0};
      socket_send_all(fd, &sum, sizeof(sum));
    } else {
      int kf = (req->request_flags & MEMDBG_QS_FL_SNAP_FIRST) != 0;
      int kp = (req->request_flags & MEMDBG_QS_FL_SNAP_PREVIOUS) != 0;
      snapshot_create(fd, slot, req, vlen, step, segs, nseg, kf, kp);
    }
    if (segs && segs != &one) free(segs);
    free(read_buf); free(result_buf);
    free(simd_offs); free(pattern);
    socket_send_int32(fd, 0);
    return 0;
  }

  const uint8_t *between_hi = (is_between && pattern) ? (pattern + vlen) : NULL;

  page_alias_ctx_t *actx = (req->request_flags & MEMDBG_QS_FL_ALIAS_READ)
                           ? alias_context_get(slot, (uint32_t)req->pid) : NULL;

  int resident = (req->request_flags & MEMDBG_QS_FL_SERVER_KEEP) != 0;

  if (resident) {
    struct flashscan_sess *s = (vlen <= 0x1000)
        ? session_alloc(slot, (uint32_t)req->pid, req->value_type, vlen) : NULL;
    int stored = 0;
    if (s) {
      stored = scan_range_stream(fd, req, req->address, req->length,
                                 vlen, step, pattern, mask, between_hi,
                                 simd_ok, read_buf, chunk_size, result_buf,
                                 simd_offs, simd_max, s, actx);
    }
    if (stored) {
      memdbg_quickscan_resident_header_t hdr;
      hdr.stored    = 1;
      hdr.hit_count = s->count;
      socket_send_all(fd, &hdr, sizeof(hdr));
      free(read_buf); free(result_buf);
      free(simd_offs); free(pattern);
      if (actx) page_alias_release(actx);
      socket_send_int32(fd, 0);
      return 0;
    }
    flashscan_free_slot(slot);
    memdbg_quickscan_resident_header_t hdr;
    hdr.stored    = 0;
    hdr.hit_count = 0;
    socket_send_all(fd, &hdr, sizeof(hdr));
    /* Fall through to streaming */
  }

  int parallel_handled = flashscan_parallel_stream(
      fd, req, vlen, step, pattern, mask, between_hi, simd_ok,
      chunk_size, simd_max);
  if (!parallel_handled) {
    scan_range_stream(fd, req, req->address, req->length,
                      vlen, step, pattern, mask, between_hi,
                      simd_ok, read_buf, chunk_size, result_buf,
                      simd_offs, simd_max, NULL, actx);
  }

  uint64_t sentinel = 0xFFFFFFFFFFFFFFFFULL;
  socket_send_all(fd, &sentinel, 8);

  free(read_buf); free(result_buf);
  free(simd_offs); free(pattern);
  if (actx) page_alias_release(actx);
  socket_send_int32(fd, 0);
  return 0;
}

int flashscan_handle_count(int fd,
                           const memdbg_quickscan_count_request_t *req,
                           const uint8_t *compare_data,
                           const uint8_t *mask,
                           unsigned int slot) {
  uint64_t vlen = req->value_length;
  if (vlen == 0) vlen = 4;
  if (vlen > 0x1000) { socket_send_int32(fd, -1); return 1; }

  int is_between    = (req->compare_type == 4);
  int includes_prev = ((req->compare_type) >= 3 && (req->compare_type) <= 12);
  const uint8_t *between_hi = (is_between && compare_data && vlen > 0)
                              ? (compare_data + vlen) : NULL;

  socket_send_int32(fd, 0);

  int resident = (req->request_flags & MEMDBG_QS_FL_SERVER_KEEP) != 0;

  if (resident) {
    struct flashscan_sess *s = session_get(slot);

      if (s && s->in_use && s->mode == FLASHSCAN_MODE_SNAPSHOT) {
      if (s->value_len != vlen) {
        uint64_t nc = s->survivor_count;
        uint64_t sentinel = 0xFFFFFFFFFFFFFFFFULL;
        socket_send_all(fd, &sentinel, 8);
        socket_send_all(fd, &nc, 8);
        socket_send_int32(fd, 0);
        return 0;
      }
      page_alias_ctx_t *rsctx = (req->request_flags & MEMDBG_QS_FL_ALIAS_RESCAN)
                                ? alias_context_get(slot, s->pid) : NULL;

      int want_parallel = (req->request_flags & MEMDBG_QS_FL_PARALLEL) != 0;
      uint64_t nc;

      if (want_parallel) {
        nc = snapshot_rescan_parallel(fd, s, req->compare_type, req->value_type,
                                      vlen, compare_data, mask, between_hi,
                                      includes_prev);
      } else {
        uint8_t *read_buf = (uint8_t *)malloc(FS_RESCAN_WIN_CAP);
        uint8_t *bl_buf   = (uint8_t *)malloc(FS_RESCAN_WIN_CAP);
        nc = snapshot_rescan(fd, s, req->compare_type, req->value_type,
                             vlen, compare_data, mask, between_hi,
                             includes_prev, read_buf, bl_buf, rsctx);
        free(read_buf); free(bl_buf);
      }
      if (rsctx) page_alias_release(rsctx);

      uint64_t rsz = 8 + vlen * (1 + (s->has_prev ? 1U : 0U) + (s->has_first ? 1U : 0U));
      if (nc > 0 && nc <= g_fs_mat_max &&
          nc * 32 <= s->slot_count && nc * rsz <= FS_RESCAN_WIN_CAP * 2)
        snapshot_materialize(slot, s);

      uint64_t prog_sentinel = 0xFFFFFFFFFFFFFFFFULL;
      socket_send_all(fd, &prog_sentinel, 8);
      socket_send_all(fd, &nc, 8);
      socket_send_int32(fd, 0);
      return 0;
    }

    uint64_t new_count = 0;
    if (s && s->in_use && s->buf && s->value_len == vlen) {
      uint8_t  *recs     = (uint8_t *)s->buf;
      uint64_t  rec_size = s->rec_size;
      uint64_t  n        = s->count;
      uint64_t  win_start = 0, win_end = 0;
      uint8_t  *rw_buf = (uint8_t *)malloc(FS_RESCAN_WIN_CAP);
      if (!rw_buf) { s->count = 0; new_count = 0; }

      if (rw_buf) {
      page_alias_ctx_t *rsctx = (req->request_flags & MEMDBG_QS_FL_ALIAS_RESCAN)
                                ? alias_context_get(slot, s->pid) : NULL;
      const uint8_t *win_base = rw_buf;
      int            win_aliased = 0;

      for (uint64_t i = 0; i < n; i++) {
        uint8_t *rec = recs + i * rec_size;
        uint64_t addr;
        memcpy(&addr, rec, 8);
        const uint8_t *prev_p = includes_prev ? (rec + 8) : between_hi;
        (void)prev_p;

        if (addr < win_start || addr + vlen > win_end) {
          win_start = addr;
          uint64_t covered = addr + vlen;
          for (uint64_t k = i + 1; k < n; k++) {
            uint64_t na;
            memcpy(&na, recs + k * rec_size, 8);
            uint64_t gap = (na > covered) ? (na - covered) : 0;
            if (gap > FS_RESCAN_GAP_MAX) break;
            uint64_t ne = na + vlen;
            if (ne - win_start > FS_RESCAN_WIN_CAP) break;
            if (ne > covered) covered = ne;
          }
          uint64_t read_size = covered - win_start;
          if (win_aliased) { page_alias_release(rsctx); win_aliased = 0; }
          win_base = flashscan_window_read(rsctx, s->pid, win_start, read_size,
                                 rw_buf, &win_aliased);
          win_end = win_start + read_size;
        }

        const uint8_t *mem_p = win_base + (addr - win_start);
        int matched = (memcmp(mem_p, compare_data, vlen) == 0);
        if (req->compare_type == 4 && between_hi)
          matched = (memcmp(mem_p, compare_data, vlen) >= 0 &&
                     memcmp(mem_p, between_hi, vlen) <= 0);

        if (matched) {
          uint8_t *out = recs + new_count * rec_size;
          memcpy(out, &addr, 8);
          memcpy(out + 8, mem_p, vlen);
          if (s->has_prev) memcpy(out + 8 + vlen, rec + 8, vlen);
          uint64_t first_off = 8 + vlen + (s->has_prev ? vlen : 0);
          if (s->has_first) memcpy(out + first_off, rec + first_off, vlen);
          new_count++;
        }
      }
      if (win_aliased) page_alias_release(rsctx);
      s->count = new_count;
      free(rw_buf);
      }
    }

    uint64_t prog_sentinel = 0xFFFFFFFFFFFFFFFFULL;
    socket_send_all(fd, &prog_sentinel, 8);
    socket_send_all(fd, &new_count, 8);
    socket_send_int32(fd, 0);
    return 0;
  }

  uint64_t entry_size = 4 + vlen;
  uint64_t flush_thresh = 0x3FFE8ULL - 2 * vlen;
  uint8_t *chunk_buf  = (uint8_t *)malloc(0x40000);
  uint8_t *result_buf = (uint8_t *)malloc(0x40000);
  uint8_t *mem_buf    = (uint8_t *)malloc(FS_RESCAN_WIN_CAP);

  if (!chunk_buf || !result_buf || !mem_buf) {
    free(chunk_buf); free(result_buf); free(mem_buf);
    socket_send_int32(fd, -1);
    return 1;
  }

  page_alias_ctx_t *rsctx = (req->request_flags & MEMDBG_QS_FL_ALIAS_RESCAN)
                            ? alias_context_get(slot, (uint32_t)req->pid) : NULL;

  for (;;) {
    uint32_t chunk_len = 0;
    if (socket_recv_all(fd, &chunk_len, 4) <= 0) break;
    if (chunk_len == 0xFFFFFFFFu) break;
    if (chunk_len == 0) {
      uint64_t sentinel = 0xFFFFFFFFFFFFFFFFULL;
      socket_send_all(fd, &sentinel, 8);
      continue;
    }
    if (chunk_len > 0x40000u) break;

    socket_recv_all(fd, chunk_buf, (size_t)chunk_len);

    uint64_t win_start = 0, win_end = 0, result_len = 0;
    const uint8_t *win_base = mem_buf;
    int waliased = 0;

    for (uint64_t off = 0; off + entry_size <= chunk_len; off += entry_size) {
      uint32_t eoff;
      memcpy(&eoff, chunk_buf + off, 4);
      uint64_t addr = req->base_address + eoff;
      const uint8_t *prev_p = includes_prev ? (chunk_buf + off + 4) : between_hi;
      (void)prev_p;

      if (addr < win_start || addr + vlen > win_end) {
        win_start = addr;
        uint64_t covered = addr + vlen;
        for (uint64_t k = off + entry_size; k + entry_size <= chunk_len; k += entry_size) {
          uint32_t noff;
          memcpy(&noff, chunk_buf + k, 4);
          uint64_t na = req->base_address + noff;
          uint64_t gap = (na > covered) ? (na - covered) : 0;
          if (gap > FS_RESCAN_GAP_MAX) break;
          uint64_t ne = na + vlen;
          if (ne - win_start > FS_RESCAN_WIN_CAP) break;
          if (ne > covered) covered = ne;
        }
        uint64_t read_size = covered - win_start;
        if (waliased) { page_alias_release(rsctx); waliased = 0; }
        win_base = flashscan_window_read(rsctx, (uint32_t)req->pid, win_start, read_size,
                               mem_buf, &waliased);
        win_end = win_start + read_size;
      }

      const uint8_t *mem_p = win_base + (addr - win_start);
      int matched = (memcmp(mem_p, compare_data, vlen) == 0);

      if (matched) {
        if (result_len > flush_thresh) {
          *(uint64_t *)result_buf = result_len;
          socket_send_all(fd, result_buf, (size_t)(result_len + 8));
          result_len = 0;
        }
        memcpy(result_buf + 8 + result_len,     &eoff, 4);
        memcpy(result_buf + 8 + result_len + 4, mem_p, vlen);
        result_len += 4 + vlen;
      }
    }
    if (waliased) page_alias_release(rsctx);

    if (result_len) {
      *(uint64_t *)result_buf = result_len;
      socket_send_all(fd, result_buf, (size_t)(result_len + 8));
    }

    uint64_t sentinel = 0xFFFFFFFFFFFFFFFFULL;
    socket_send_all(fd, &sentinel, 8);
  }

  free(chunk_buf); free(result_buf); free(mem_buf);
  socket_send_int32(fd, 0);
  return 0;
}

int flashscan_handle_fetch(int fd,
                           const memdbg_quickscan_fetch_request_t *req,
                           unsigned int slot) {
  struct flashscan_sess *s = session_get(slot);
  if (!s || !s->in_use || (s->mode == FLASHSCAN_MODE_LIST && !s->buf)) {
    socket_send_int32(fd, 0);
    socket_send_all(fd, &(uint32_t){0}, 4);
    socket_send_int32(fd, 0);
    return 0;
  }

  if (s->mode == FLASHSCAN_MODE_SNAPSHOT) {
    uint8_t *out_buf = (uint8_t *)malloc(0x40000);
    if (!out_buf) { socket_send_int32(fd, -1); return 1; }
    socket_send_int32(fd, 0);
    snapshot_fetch(fd, s, req->start_index, req->count, out_buf, 0x40000);
    free(out_buf);
    socket_send_int32(fd, 0);
    return 0;
  }

  uint64_t vlen     = s->value_len;
  uint64_t rec_size = s->rec_size;
  uint64_t total    = s->count;
  uint64_t start    = req->start_index;
  uint64_t want     = req->count;
  if (start > total) start = total;
  uint64_t end = start + want;
  if (end > total || end < start) end = total;
  uint32_t actual = (uint32_t)(end - start);

  uint8_t *out_buf = (uint8_t *)malloc(0x40000);
  if (!out_buf) { socket_send_int32(fd, -1); return 1; }

  int has_first = s->has_first, has_prev = s->has_prev;
  uint64_t prev_off  = has_prev ? (8 + vlen) : 8;
  uint64_t first_off = 8 + vlen + (has_prev ? vlen : 0);

  socket_send_int32(fd, 0);
  uint32_t hdr = actual | (has_first ? 0x80000000u : 0u);
  socket_send_all(fd, &hdr, 4);

  uint8_t  *recs = (uint8_t *)s->buf;
  uint64_t  ent_size = 8 + vlen * (has_first ? 3 : 2);
  uint64_t  out_len = 0;
  uint64_t  out_cap = 0x40000;

  for (uint64_t i = start; i < end; i++) {
    uint8_t *rec = recs + i * rec_size;
    if (out_len + ent_size > out_cap) {
      socket_send_all(fd, out_buf, (size_t)out_len);
      out_len = 0;
    }
    uint8_t *o = out_buf + out_len;
    memcpy(o,               rec,                 8);
    memcpy(o + 8,           rec + 8,             vlen);
    memcpy(o + 8 + vlen,    rec + prev_off,      vlen);
    if (has_first)
      memcpy(o + 8 + 2 * vlen, rec + first_off, vlen);
    out_len += ent_size;
  }
  if (out_len) socket_send_all(fd, out_buf, (size_t)out_len);

  free(out_buf);
  socket_send_int32(fd, 0);
  return 0;
}

int flashscan_handle_end(int fd, unsigned int slot) {
  flashscan_free_slot(slot);
  socket_send_int32(fd, 0);
  return 0;
}

int flashscan_handle_cancel(int fd, unsigned int slot) {
  g_fs_cancel_requested = 1;
  flashscan_free_slot(slot);
  socket_send_int32(fd, 0);
  g_fs_cancel_requested = 0;
  return 0;
}
