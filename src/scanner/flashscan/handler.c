/*
 * memDBG - FlashScan protocol handlers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * I/O helpers      → flashscan_io.c
 * Session mgmt     → flashscan_session.c
 * Worker threads   → flashscan_worker.c
 * Shared internals → flashscan_internal.h
 */

#include "flashscan_internal.h"

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
