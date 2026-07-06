/*
 * memDBG - Process protect/alloc/free/stack/elf load protocol handlers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from src/core/daemon/memdbg.c.
 */

#include "daemon_internal.h"

#include "memdbg/core/memdbg.h"
#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/pal/pal_memory.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* External: elf load helper from features.c */
extern int memdbg_elf_load_enhanced(int pid, const uint8_t *elf, uint64_t elf_size,
                                    const char *region, uint32_t match_flags,
                                    uint64_t *entry, uint64_t *base);

/* ---- PROCESS_PROTECT / ALLOC / FREE ---- */

memdbg_status_t handle_process_protect(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_process_protect_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_process_protect_request_t *pr =
      (const memdbg_process_protect_request_t *)body;
  if (pr->pid <= 1 || pr->address == 0U || pr->length == 0U)
    return MEMDBG_ERR_PARAM;
  if ((pr->protection & ~(MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_WRITE |
                          MEMDBG_MAP_PROT_EXEC)) != 0U)
    return MEMDBG_ERR_PARAM;

  uint32_t old_prot = 0U;
  memdbg_status_t st = pal_memory_protect(
      pr->pid, pr->address, (size_t)pr->length, pr->protection, &old_prot);
  memdbg_process_protect_response_t resp;
  memset(&resp, 0, sizeof(resp));
  resp.old_protection = old_prot;
  resp.new_protection = pr->protection;
  return send_response(fd, req, st, st == MEMDBG_OK ? &resp : NULL,
                       st == MEMDBG_OK ? (uint32_t)sizeof(resp) : 0U) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}

memdbg_status_t handle_process_alloc(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_process_alloc_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_process_alloc_request_t *ar =
      (const memdbg_process_alloc_request_t *)body;
  if (ar->pid <= 1 || ar->length == 0U)
    return MEMDBG_ERR_PARAM;

  uint64_t address = 0U;
  memdbg_status_t st = pal_memory_alloc(ar->pid, ar->hint, (size_t)ar->length,
                                        ar->protection, ar->flags, &address);
  memdbg_process_alloc_response_t resp;
  memset(&resp, 0, sizeof(resp));
  resp.address = address;
  resp.length = ar->length;
  return send_response(fd, req, st, st == MEMDBG_OK ? &resp : NULL,
                       st == MEMDBG_OK ? (uint32_t)sizeof(resp) : 0U) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}

memdbg_status_t handle_process_free(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_process_free_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_process_free_request_t *fr =
      (const memdbg_process_free_request_t *)body;
  if (fr->pid <= 1 || fr->address == 0U || fr->length == 0U)
    return MEMDBG_ERR_PARAM;
  memdbg_status_t st =
      pal_memory_free(fr->pid, fr->address, (size_t)fr->length);
  return send_response(fd, req, st, NULL, 0U) == 0 ? MEMDBG_OK
                                                   : MEMDBG_ERR_NET;
}

/* ---- Stack helpers ---- */

static uint32_t stack_read_best_effort(int32_t pid, uint64_t address,
                                       uint8_t *out, uint32_t length) {
  if (length == 0U) return 0U;
  size_t got = 0U;
  if (pal_memory_read(pid, address, out, length, &got) != MEMDBG_OK)
    return 0U;
  return got > UINT32_MAX ? UINT32_MAX : (uint32_t)got;
}

static bool stack_append_blob(uint8_t *blob, uint32_t blob_capacity,
                              uint32_t *blob_size, const uint8_t *data,
                              uint32_t data_size, uint32_t *offset_out) {
  if (offset_out == NULL || blob_size == NULL) return false;
  *offset_out = *blob_size;
  if (data_size == 0U) return true;
  if (blob == NULL || data == NULL || data_size > blob_capacity - *blob_size)
    return false;
  memcpy(blob + *blob_size, data, data_size);
  *blob_size += data_size;
  return true;
}

/* ---- PROCESS_STACK ---- */

memdbg_status_t handle_process_stack(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_process_stack_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_process_stack_request_t *sr =
      (const memdbg_process_stack_request_t *)body;
  if (sr->pid <= 1) return MEMDBG_ERR_PARAM;

  uint32_t max_frames = sr->max_frames == 0U ? MEMDBG_STACK_MAX_FRAMES
                                             : sr->max_frames;
  if (max_frames > MEMDBG_STACK_MAX_FRAMES)
    max_frames = MEMDBG_STACK_MAX_FRAMES;
  uint32_t max_frame_bytes =
      sr->max_bytes_per_frame == 0U ? 256U : sr->max_bytes_per_frame;
  if (max_frame_bytes > MEMDBG_STACK_MAX_FRAME_BYTES)
    max_frame_bytes = MEMDBG_STACK_MAX_FRAME_BYTES;
  uint32_t code_window =
      sr->code_window == 0U ? MEMDBG_STACK_DEFAULT_CODE_WINDOW
                            : sr->code_window;
  if (code_window > MEMDBG_STACK_DEFAULT_CODE_WINDOW)
    code_window = MEMDBG_STACK_DEFAULT_CODE_WINDOW;

  uint64_t fp = sr->frame_pointer;
  uint64_t sp = sr->stack_pointer;
  if (fp == 0U && sr->lwp != 0 &&
      memdbg_debugger_is_attached() &&
      memdbg_debugger_attached_pid() == sr->pid) {
    memdbg_debug_regs_t regs;
    memset(&regs, 0, sizeof(regs));
    if (memdbg_debugger_get_regs(sr->lwp, &regs) == MEMDBG_OK) {
      fp = (uint64_t)regs.r_rbp;
      sp = (uint64_t)regs.r_rsp;
    }
  }
  if (fp == 0U) return MEMDBG_ERR_PARAM;

  const uint32_t blob_capacity =
      max_frames * (max_frame_bytes + code_window);
  if (blob_capacity > MEMDBG_PROTOCOL_MAX_PACKET / 2U)
    return MEMDBG_ERR_OVERFLOW;

  memdbg_process_stack_frame_t frames[MEMDBG_STACK_MAX_FRAMES];
  memset(frames, 0, sizeof(frames));
  uint8_t *blob = (uint8_t *)malloc(blob_capacity == 0U ? 1U : blob_capacity);
  uint8_t *scratch = (uint8_t *)malloc(max_frame_bytes > code_window
                                           ? max_frame_bytes
                                           : code_window);
  if (blob == NULL || scratch == NULL) {
    free(blob);
    free(scratch);
    return MEMDBG_ERR_NOMEM;
  }

  uint32_t blob_size = 0U;
  uint32_t count = 0U;
  uint32_t truncated = 0U;
  uint64_t current_fp = fp;
  uint64_t current_sp = sp;

  for (; count < max_frames && current_fp != 0U; ++count) {
    uint64_t pair[2] = {0U, 0U};
    size_t got = 0U;
    if (pal_memory_read(sr->pid, current_fp, pair, sizeof(pair), &got) !=
            MEMDBG_OK ||
        got != sizeof(pair)) {
      break;
    }

    memdbg_process_stack_frame_t *fr = &frames[count];
    fr->frame_pointer = current_fp;
    fr->saved_frame_pointer = pair[0];
    fr->return_address = pair[1];

    uint64_t stack_addr = current_fp;
    uint32_t stack_len = 16U;
    if (count == 0U && current_sp != 0U && current_sp < current_fp) {
      uint64_t span = (current_fp - current_sp) + 16U;
      stack_addr = current_sp;
      stack_len = span > max_frame_bytes ? max_frame_bytes : (uint32_t)span;
    } else if (pair[0] > current_fp) {
      uint64_t span = pair[0] - current_fp;
      stack_len = span > max_frame_bytes ? max_frame_bytes : (uint32_t)span;
      if (stack_len < 16U) stack_len = 16U;
    }

    uint32_t got_stack =
        stack_read_best_effort(sr->pid, stack_addr, scratch, stack_len);
    fr->stack_address = stack_addr;
    fr->stack_size = got_stack;
    uint32_t stack_data_offset = 0U;
    if (!stack_append_blob(blob, blob_capacity, &blob_size, scratch,
                           got_stack, &stack_data_offset)) {
      truncated = 1U;
      break;
    }
    fr->stack_data_offset = stack_data_offset;

    if (pair[1] != 0U && code_window != 0U) {
      uint64_t code_addr = pair[1] > 10U ? pair[1] - 10U : pair[1];
      uint32_t got_code =
          stack_read_best_effort(sr->pid, code_addr, scratch, code_window);
      fr->code_address = code_addr;
      fr->code_size = got_code;
      uint32_t code_data_offset = 0U;
      if (!stack_append_blob(blob, blob_capacity, &blob_size, scratch,
                             got_code, &code_data_offset)) {
        truncated = 1U;
        break;
      }
      fr->code_data_offset = code_data_offset;
    }

    if (pair[0] <= current_fp) break;
    current_sp = current_fp + 16U;
    current_fp = pair[0];
  }

  size_t entries_size = count * sizeof(memdbg_process_stack_frame_t);
  size_t payload_len = sizeof(memdbg_process_stack_response_prefix_t) +
                       entries_size + blob_size;
  if (payload_len > MEMDBG_PROTOCOL_MAX_PACKET) {
    free(blob);
    free(scratch);
    return MEMDBG_ERR_OVERFLOW;
  }
  uint8_t *payload = (uint8_t *)malloc(payload_len == 0U ? 1U : payload_len);
  if (payload == NULL) {
    free(blob);
    free(scratch);
    return MEMDBG_ERR_NOMEM;
  }

  memdbg_process_stack_response_prefix_t prefix;
  memset(&prefix, 0, sizeof(prefix));
  prefix.count = count;
  prefix.truncated = truncated;
  prefix.entry_size = (uint32_t)sizeof(memdbg_process_stack_frame_t);
  prefix.data_size = blob_size;
  memcpy(payload, &prefix, sizeof(prefix));
  if (entries_size != 0U)
    memcpy(payload + sizeof(prefix), frames, entries_size);
  if (blob_size != 0U)
    memcpy(payload + sizeof(prefix) + entries_size, blob, blob_size);

  int rc = send_response(fd, req, MEMDBG_OK, payload, (uint32_t)payload_len);
  free(payload);
  free(blob);
  free(scratch);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- PROCESS_ELF_LOAD ---- */

memdbg_status_t handle_process_elf_load(int fd,
    const memdbg_packet_header_t *req, const void *body, uint32_t body_len) {
  if (body_len < sizeof(memdbg_process_elf_load_request_t))
    return MEMDBG_ERR_PROTOCOL;

  const memdbg_process_elf_load_request_t *elf_req =
      (const memdbg_process_elf_load_request_t *)body;
  uint64_t elf_size = elf_req->image_size;

  if (elf_size == 0U || elf_size > (64ULL << 20))
    return MEMDBG_ERR_PARAM;
  if (body_len < sizeof(*elf_req) + elf_size)
    return MEMDBG_ERR_PROTOCOL;
  if (elf_req->pid <= 1 || (pid_t)elf_req->pid == getpid())
    return MEMDBG_ERR_PERMISSION;

  const uint8_t *elf_data = (const uint8_t *)body + sizeof(*elf_req);
  uint64_t entry = 0U, base = 0U;

  char region_buf[45];
  memcpy(region_buf, elf_req->target_region, sizeof(elf_req->target_region));
  region_buf[44] = '\0';
  const char *region = region_buf[0] ? region_buf : NULL;

  int rc = memdbg_elf_load_enhanced(
      elf_req->pid, elf_data, elf_size, region, elf_req->match_flags,
      &entry, &base);

  if (rc != 0)
    return MEMDBG_ERR_IO;

  memdbg_process_elf_load_response_t resp;
  memset(&resp, 0, sizeof(resp));
  resp.entry_address = entry;
  resp.load_base     = base;

  return send_response(fd, req, MEMDBG_OK, &resp, sizeof(resp)) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}
