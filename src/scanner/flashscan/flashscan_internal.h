/*
 * memDBG - FlashScan internal state and helpers.
 * Shared across flashscan.c, flashscan_io.c, flashscan_session.c, flashscan_worker.c.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef FLASHSCAN_INTERNAL_H
#define FLASHSCAN_INTERNAL_H

#include "memdbg/scanner/flashscan.h"
#include "memdbg/scanner/walker.h"
#include "memdbg/scanner/alias.h"
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

/* ---- Defines ---- */

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

/* ---- Structs ---- */

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

struct rescan_worker_ctx {
  struct flashscan_sess *s;
  uint32_t       cmp_type;
  uint32_t       val_type;
  uint64_t       vlen;
  const uint8_t *pattern;
  const uint8_t *mask;
  const uint8_t *between_hi;
  int            includes_prev;
  uint64_t       chunk_start;
  uint64_t       chunk_end;
  uint64_t      *survivors_out;
  uint32_t       worker_id;
};

/* ---- Global state ---- */

extern struct flashscan_sess g_sessions[FLASHSCAN_MAX_SESSIONS];
extern page_alias_ctx_t *g_alias_ctxs[FLASHSCAN_MAX_SESSIONS];
extern int g_session_owner_fd[FLASHSCAN_MAX_SESSIONS];
extern pthread_mutex_t g_session_owner_mutex;

extern uint64_t g_fs_ram_limit;
extern char     g_fs_spill_dir[64];
extern int      g_fs_force_fail;
extern volatile int g_fs_cancel_requested;
extern uint64_t g_fs_mat_max;

/* ---- I/O helpers (flashscan_io.c) ---- */

int socket_send_int32(socket_t fd, int32_t val);
int socket_send_all(socket_t fd, const void *buf, size_t len);
int socket_recv_all(socket_t fd, void *buf, size_t len);
void *mmap_anonymous(uint64_t n);
void munmap_anonymous(void *p, uint64_t n);

int flashscan_pread_all(int fd, void *buf, uint64_t len, uint64_t off);
int flashscan_pwrite_all(int fd, const void *buf, uint64_t len, uint64_t off);

int snapshot_store_read(struct flashscan_sess *s, uint8_t *dst,
                        uint64_t off, uint64_t len);
int snapshot_store_write(struct flashscan_sess *s, const uint8_t *src,
                         uint64_t off, uint64_t len);
void snapshot_store_path(unsigned slot, char *out, const char *tag);

const uint8_t *flashscan_window_read(page_alias_ctx_t *actx, uint32_t pid,
                                     uint64_t win_start, uint64_t read_size,
                                     uint8_t *fallback, int *aliased);

/* ---- Session management (flashscan_session.c) ---- */

struct flashscan_sess *session_get(unsigned slot);
void alias_context_free_slot(unsigned slot);
page_alias_ctx_t *alias_context_get(unsigned slot, uint32_t pid);
struct flashscan_sess *session_alloc(unsigned slot, uint32_t pid,
                                     uint32_t vt, uint64_t vlen);

void bitmap_clear(uint8_t *bm, uint64_t i);
uint64_t bitmap_next_set(const uint8_t *bm, uint64_t from, uint64_t n);
uint64_t slot_to_addr(const struct flashscan_sess *s, uint64_t i);

int snapshot_create(int fd, unsigned slot,
                    const memdbg_quickscan_start_request_t *req,
                    uint64_t vlen, uint64_t step,
                    const memdbg_quickscan_segment_t *in_segs,
                    uint32_t in_nseg, int keep_first, int keep_prev);

/* ---- Worker functions (flashscan_worker.c) ---- */

uint64_t snapshot_rescan(int fd, struct flashscan_sess *s,
                         uint32_t cmp_type, uint32_t val_type,
                         uint64_t vlen,
                         const uint8_t *pattern, const uint8_t *mask,
                         const uint8_t *between_hi, int includes_prev,
                         uint8_t *read_buf, uint8_t *bl_buf,
                         page_alias_ctx_t *actx);

uint64_t snapshot_rescan_parallel(int fd, struct flashscan_sess *s,
                                  uint32_t cmp_type, uint32_t val_type,
                                  uint64_t vlen,
                                  const uint8_t *pattern, const uint8_t *mask,
                                  const uint8_t *between_hi, int includes_prev);

uint32_t snapshot_fetch(int fd, struct flashscan_sess *s,
                        uint32_t start, uint32_t count,
                        uint8_t *out_buf, uint64_t out_cap);

int snapshot_materialize(unsigned slot, struct flashscan_sess *s);

int scan_range_stream(int fd,
                      const memdbg_quickscan_start_request_t *req,
                      uint64_t scan_addr, uint64_t scan_len,
                      uint64_t vlen, uint64_t step,
                      const uint8_t *pattern, const uint8_t *mask,
                      const uint8_t *between_hi, int simd_ok,
                      uint8_t *read_buf, uint64_t chunk_size,
                      uint8_t *result_buf, uint32_t *simd_offs,
                      uint64_t simd_max,
                      struct flashscan_sess *sess,
                      page_alias_ctx_t *actx);

int flashscan_parallel_stream(
    int fd, const memdbg_quickscan_start_request_t *req,
    uint64_t value_len, uint64_t step, const uint8_t *pattern,
    const uint8_t *mask, const uint8_t *between_hi, int simd_ok,
    uint64_t chunk_size, uint64_t simd_max);

#endif /* FLASHSCAN_INTERNAL_H */
