/*
 * memDBG - FlashScan worker threads and parallel scan.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "flashscan_internal.h"

uint64_t snapshot_rescan(int fd, struct flashscan_sess *s,
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


void *rescan_worker_thread(void *arg) {
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

uint64_t snapshot_rescan_parallel(int fd, struct flashscan_sess *s,
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

uint32_t snapshot_fetch(int fd, struct flashscan_sess *s,
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

int snapshot_materialize(unsigned slot, struct flashscan_sess *s) {
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



void *flashscan_parallel_worker_run(void *arg) {
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

int flashscan_parallel_stream(
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

