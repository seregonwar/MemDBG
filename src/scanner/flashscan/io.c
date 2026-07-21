/*
 * memDBG - FlashScan I/O helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "flashscan_internal.h"

int socket_send_int32(socket_t fd, int32_t val) {
  return (int)pal_socket_write_all(fd, &val, sizeof(val));
}

int socket_send_all(socket_t fd, const void *buf, size_t len) {
  return (len > 0U) ? (int)pal_socket_write_all(fd, buf, len) : 0;
}

int socket_recv_all(socket_t fd, void *buf, size_t len) {
  return (len > 0U) ? (int)pal_socket_read_exact(fd, buf, len) : 0;
}

inline void *mmap_anonymous(uint64_t n) {
  void *m = mmap(NULL, (size_t)n, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
  return (m == MAP_FAILED) ? NULL : m;
}

inline void munmap_anonymous(void *p, uint64_t n) {
  if (p) munmap(p, (size_t)n);
}

int flashscan_pread_all(int fd, void *buf, uint64_t len, uint64_t off) {
  uint8_t *p = (uint8_t *)buf;
  uint64_t pos = 0;
  while (pos < len) {
    ssize_t r = pread(fd, p + pos, (size_t)(len - pos), (off_t)(off + pos));
    if (r <= 0) return 0;
    pos += (uint64_t)r;
  }
  return 1;
}

int flashscan_pwrite_all(int fd, const void *buf, uint64_t len, uint64_t off) {
  const uint8_t *p = (const uint8_t *)buf;
  uint64_t pos = 0;
  while (pos < len) {
    ssize_t w = pwrite(fd, p + pos, (size_t)(len - pos), (off_t)(off + pos));
    if (w <= 0) return 0;
    pos += (uint64_t)w;
  }
  return 1;
}

int snapshot_store_read(struct flashscan_sess *s, uint8_t *dst,
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

int snapshot_store_write(struct flashscan_sess *s, const uint8_t *src,
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


const uint8_t *flashscan_window_read(page_alias_ctx_t *actx, uint32_t pid,
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

