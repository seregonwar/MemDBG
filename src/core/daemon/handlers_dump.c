/*
 * memDBG - Process dump (JSON) protocol handler.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Uses sJson (https://github.com/seregonwar/sJson) for high-performance,
 * arena-allocated, type-safe JSON tree building.
 */

#include "daemon_internal.h"
#include "memdbg/sjson.h"

#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/debug/memdbg_process.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DUMP_REGION_PREVIEW  256U
#define DUMP_ARENA_BLOCK_SIZE (256U * 1024U)

/* ---- Helpers for building typed JSON values from the payload domain ---- */

/* Write a uint64_t as a "0x" prefixed hex string into a stack buffer,
 * then copy it into the arena. */
static JsonValue *json_hex_u64(JsonArena *arena, uint64_t value) {
  char buf[20]; /* "0x" + 16 hex digits + NUL */
  int n = snprintf(buf, sizeof(buf), "0x%016" PRIx64, value);
  return json_make_string(arena, buf, (uint32_t)(n > 0 ? n : 0));
}

/* Same, with a stack-allocated hex buffer to avoid waste. */
static JsonValue *json_hex_preview(JsonArena *arena,
                                   const uint8_t *data, size_t len) {
  /* Use a stack buffer instead of arena-allocating twice. */
  char hex[DUMP_REGION_PREVIEW * 2U + 1U];
  for (size_t i = 0U; i < len; i++)
    snprintf(hex + i * 2U, 3U, "%02x", data[i]);
  hex[len * 2U] = '\0';
  return json_make_string(arena, hex, (uint32_t)(len * 2U));
}

/* ---- Step 3 helpers: build sub-objects of the JSON tree ---- */

static bool add_regs_object(JsonArena *arena, JsonValue *thread_obj,
                            int32_t lwp) {
  memdbg_debug_regs_t regs;
  memset(&regs, 0, sizeof(regs));
  if (memdbg_debugger_get_regs(lwp, &regs) != MEMDBG_OK)
    return false;

  JsonValue *robj = json_make_object(arena);
  (void)json_obj_setz(robj, arena, "rax", json_hex_u64(arena, (uint64_t)regs.r_rax));
  (void)json_obj_setz(robj, arena, "rbx", json_hex_u64(arena, (uint64_t)regs.r_rbx));
  (void)json_obj_setz(robj, arena, "rcx", json_hex_u64(arena, (uint64_t)regs.r_rcx));
  (void)json_obj_setz(robj, arena, "rdx", json_hex_u64(arena, (uint64_t)regs.r_rdx));
  (void)json_obj_setz(robj, arena, "rsi", json_hex_u64(arena, (uint64_t)regs.r_rsi));
  (void)json_obj_setz(robj, arena, "rdi", json_hex_u64(arena, (uint64_t)regs.r_rdi));
  (void)json_obj_setz(robj, arena, "rbp", json_hex_u64(arena, (uint64_t)regs.r_rbp));
  (void)json_obj_setz(robj, arena, "rsp", json_hex_u64(arena, (uint64_t)regs.r_rsp));
  (void)json_obj_setz(robj, arena, "rip", json_hex_u64(arena, (uint64_t)regs.r_rip));
  (void)json_obj_setz(robj, arena, "rflags", json_hex_u64(arena, (uint64_t)regs.r_rflags));
  return json_obj_setz(thread_obj, arena, "regs", robj) == JSON_OK;
}

static void add_stack_frames(JsonArena *arena, JsonValue *thread_obj,
                             int pid, int32_t lwp) {
  memdbg_debug_regs_t regs;
  memset(&regs, 0, sizeof(regs));
  if (memdbg_debugger_get_regs(lwp, &regs) != MEMDBG_OK)
    return;

  JsonValue *frames = json_make_array(arena);
  uint64_t fp  = (uint64_t)regs.r_rbp;
  uint64_t rip = (uint64_t)regs.r_rip;
  uint32_t idx = 0U;
  const uint32_t max_frames = 32U;

  /* Frame 0: current RIP */
  {
    JsonValue *f0 = json_make_object(arena);
    (void)json_obj_setz(f0, arena, "idx", json_make_int(arena, (int64_t)idx));
    (void)json_obj_setz(f0, arena, "fp",  json_hex_u64(arena, fp));
    (void)json_obj_setz(f0, arena, "ret", json_hex_u64(arena, rip));
    (void)json_obj_setz(f0, arena, "sp",  json_hex_u64(arena, (uint64_t)regs.r_rsp));
    (void)json_arr_push(frames, arena, f0);
    idx++;
  }

  /* Walk RBP chain */
  while (idx < max_frames && fp != 0U) {
    uint64_t next_fp = 0U, ret_addr = 0U;
    size_t ro = 0U;
    if (memdbg_memory_read(pid, fp, &next_fp, sizeof(next_fp), &ro) != MEMDBG_OK ||
        ro != sizeof(next_fp) ||
        memdbg_memory_read(pid, fp + 8U, &ret_addr, sizeof(ret_addr), &ro) != MEMDBG_OK ||
        ro != sizeof(ret_addr))
      break;
    if (ret_addr == 0U || next_fp <= fp)
      break;

    JsonValue *fn = json_make_object(arena);
    (void)json_obj_setz(fn, arena, "idx", json_make_int(arena, (int64_t)idx));
    (void)json_obj_setz(fn, arena, "fp",  json_hex_u64(arena, next_fp));
    (void)json_obj_setz(fn, arena, "ret", json_hex_u64(arena, ret_addr));
    (void)json_obj_setz(fn, arena, "sp",  json_hex_u64(arena, fp + 16U));
    (void)json_arr_push(frames, arena, fn);

    fp = next_fp;
    idx++;
  }

  (void)json_obj_setz(thread_obj, arena, "stack", frames);
}

/* ---- Main handler ---- */

memdbg_status_t handle_process_dump(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_process_dump_request_t))
    return MEMDBG_ERR_PROTOCOL;

  const memdbg_process_dump_request_t *dr =
      (const memdbg_process_dump_request_t *)body;

  int pid = (int)dr->pid;
  if (pid <= 0) return MEMDBG_ERR_PARAM;

  bool want_regs    = (dr->flags & 1U) != 0U;
  bool want_stacks  = (dr->flags & 2U) != 0U;
  bool want_preview = (dr->flags & 4U) != 0U;

  /* ---- Step 1: attach debugger ---- */
  bool need_detach = false;
  {
    memdbg_status_t st = memdbg_debugger_conditional_attach(
        (int32_t)pid, &need_detach);
    if (st != MEMDBG_OK) return st;
  }

  /* Stop the target so we can read its state. */
  {
    memdbg_status_t st = memdbg_debugger_stop();
    if (st != MEMDBG_OK) {
      if (need_detach) (void)memdbg_debugger_detach();
      return st;
    }
  }
  (void)memdbg_debugger_poll_events();  /* best-effort; errors surfaced below */

  /* ---- Step 2: collect data ---- */

  memdbg_process_info_response_t info;
  memset(&info, 0, sizeof(info));

  memdbg_map_list_t maps;
  memset(&maps, 0, sizeof(maps));

  int32_t  lwps[MEMDBG_DEBUGGER_MAX_THREADS];
  char     tnames[MEMDBG_DEBUGGER_MAX_THREADS][24];
  uint32_t tstates[MEMDBG_DEBUGGER_MAX_THREADS];
  uint32_t tcount = 0U;

  (void)memdbg_process_info(pid, &info);
  (void)memdbg_process_maps(pid, &maps);
  (void)memdbg_debugger_get_threads(lwps, tnames, tstates, &tcount,
                                    MEMDBG_DEBUGGER_MAX_THREADS);

  /* ---- Step 3: build JSON tree with sJson ---- */

  JsonArena *arena = json_arena_create(NULL, DUMP_ARENA_BLOCK_SIZE);
  if (arena == NULL) {
    memdbg_process_maps_free(&maps);
    if (need_detach) (void)memdbg_debugger_detach();
    return MEMDBG_ERR_NOMEM;
  }

  JsonValue *root = json_make_object(arena);

  /* --- Header fields --- */
  (void)json_obj_setz(root, arena, "pid",
      json_make_int(arena, (int64_t)pid));
  (void)json_obj_setz(root, arena, "name",
      json_make_stringz(arena, info.name[0] ? info.name : "unknown"));
  if (info.path[0])
    (void)json_obj_setz(root, arena, "path",
        json_make_stringz(arena, info.path));
  if (info.title_id[0])
    (void)json_obj_setz(root, arena, "title_id",
        json_make_stringz(arena, info.title_id));
  if (info.content_id[0])
    (void)json_obj_setz(root, arena, "content_id",
        json_make_stringz(arena, info.content_id));

  /* --- Threads array --- */
  {
    JsonValue *threads_arr = json_make_array(arena);

    for (uint32_t ti = 0U; ti < tcount; ti++) {
      JsonValue *tobj = json_make_object(arena);
      (void)json_obj_setz(tobj, arena, "lwp",
          json_make_int(arena, (int64_t)lwps[ti]));
      (void)json_obj_setz(tobj, arena, "state",
          json_make_int(arena, (int64_t)tstates[ti]));
      (void)json_obj_setz(tobj, arena, "name",
          json_make_stringz(arena, tnames[ti]));

      if (want_regs)
        (void)add_regs_object(arena, tobj, lwps[ti]);

      if (want_stacks)
        add_stack_frames(arena, tobj, pid, lwps[ti]);

      (void)json_arr_push(threads_arr, arena, tobj);
    }

    (void)json_obj_setz(root, arena, "threads", threads_arr);
  }

  /* --- Memory maps array --- */
  {
    JsonValue *maps_arr = json_make_array(arena);

    for (size_t mi = 0U; mi < maps.count; mi++) {
      const memdbg_map_entry_t *m = &maps.entries[mi];
      JsonValue *mobj = json_make_object(arena);

      (void)json_obj_setz(mobj, arena, "start", json_hex_u64(arena, m->start));
      (void)json_obj_setz(mobj, arena, "end",   json_hex_u64(arena, m->end));
      (void)json_obj_setz(mobj, arena, "size",  json_make_int(arena,
          (int64_t)(m->end - m->start)));
      (void)json_obj_setz(mobj, arena, "prot",  json_make_int(arena,
          (int64_t)m->protection));
      (void)json_obj_setz(mobj, arena, "flags", json_make_int(arena,
          (int64_t)m->flags));
      (void)json_obj_setz(mobj, arena, "name",
          json_make_stringz(arena, m->name[0] ? m->name : ""));

      if (want_preview && m->end > m->start) {
        uint8_t preview[DUMP_REGION_PREVIEW];
        size_t plen = m->end - m->start;
        if (plen > DUMP_REGION_PREVIEW) plen = DUMP_REGION_PREVIEW;
        size_t ro = 0U;
        if (memdbg_memory_read(pid, m->start, preview, plen,
                               &ro) == MEMDBG_OK && ro > 0U) {
          (void)json_obj_setz(mobj, arena, "preview",
              json_hex_preview(arena, preview, ro));
        }
      }

      (void)json_arr_push(maps_arr, arena, mobj);
    }

    (void)json_obj_setz(root, arena, "maps", maps_arr);
  }

  memdbg_process_maps_free(&maps);

  /* ---- Step 4: serialize and send ---- */

  /* Resume target before detaching. */
  (void)memdbg_debugger_continue();
  if (need_detach)
    (void)memdbg_debugger_detach();

  /* Measure the output size first, then serialize into a malloc'd buffer. */
  size_t json_len = 0U;
  JsonError measure_err = json_measure(root, &json_len, NULL);
  if (measure_err != JSON_OK) {
    json_arena_destroy(arena);
    return MEMDBG_ERR_NOMEM;
  }

  char *json_buf = (char *)malloc(json_len + 1U);
  if (json_buf == NULL) {
    json_arena_destroy(arena);
    return MEMDBG_ERR_NOMEM;
  }

  size_t written = 0U;
  JsonError write_err = json_write(root, json_buf, json_len + 1U,
                                   &written, NULL);

  if (write_err != JSON_OK) {
    json_arena_destroy(arena);
    free(json_buf);
    return MEMDBG_ERR_NOMEM;
  }
  json_arena_destroy(arena);

  /* Frame and send. */
  {
    memdbg_status_t st;
    unsigned char *framed = NULL;
    uint32_t framed_len = 0U;
    memdbg_status_t fst = build_framed_payload(
        json_buf, (uint32_t)written, &framed, &framed_len);
    (void)fst;
    int rc = send_response(fd, req, MEMDBG_OK,
                           framed ? framed : (const void *)json_buf,
                           framed ? framed_len : (uint32_t)written);
    st = (rc == 0) ? MEMDBG_OK : MEMDBG_ERR_NET;
    free(framed);
    free(json_buf);
    return st;
  }
}
