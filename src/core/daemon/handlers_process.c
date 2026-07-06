/*
 * memDBG - Process protocol handlers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from include/memdbg/core/memdbg_protocol_process_handlers.h.
 * Originally static inline; now compiled once as a regular function to
 * reduce compilation duplication across translation units.
 */

#include "daemon_internal.h"
#include "memdbg/core/memdbg_protocol_process_handlers.h"

#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/debug/memdbg_process.h"
#include "memdbg/pal/pal_time.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- Process list ---- */

memdbg_status_t handle_process_list(int fd,
    const memdbg_packet_header_t *req) {
  memdbg_process_list_t list;
  memset(&list, 0, sizeof(list));
  memdbg_status_t st = memdbg_process_list(&list);
  if (st != MEMDBG_OK) return st;

  size_t entries_size = list.count * sizeof(memdbg_process_entry_t);
  size_t payload_len = sizeof(uint32_t) + entries_size;
  if (list.count > UINT32_MAX ||
      entries_size / sizeof(memdbg_process_entry_t) != list.count ||
      payload_len > UINT32_MAX) {
    memdbg_process_list_free(&list);
    return MEMDBG_ERR_OVERFLOW;
  }

  uint8_t *payload = (uint8_t *)malloc(payload_len);
  if (payload == NULL) {
    memdbg_process_list_free(&list);
    return MEMDBG_ERR_NOMEM;
  }

  uint32_t count32 = (uint32_t)list.count;
  memcpy(payload, &count32, sizeof(count32));
  if (entries_size != 0U)
    memcpy(payload + sizeof(count32), list.entries, entries_size);

  int rc = send_response(fd, req, MEMDBG_OK, payload, (uint32_t)payload_len);
  free(payload);
  memdbg_process_list_free(&list);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Process maps ---- */

memdbg_status_t handle_process_maps(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_process_maps_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_process_maps_request_t *mr =
      (const memdbg_process_maps_request_t *)body;

  memdbg_map_list_t list;
  memset(&list, 0, sizeof(list));
  memdbg_status_t st = memdbg_process_maps(mr->pid, &list);
  if (st != MEMDBG_OK) return st;

  size_t entries_size = list.count * sizeof(memdbg_map_entry_t);
  size_t payload_len = sizeof(uint32_t) + entries_size;
  if (list.count > UINT32_MAX ||
      entries_size / sizeof(memdbg_map_entry_t) != list.count ||
      payload_len > UINT32_MAX) {
    memdbg_process_maps_free(&list);
    return MEMDBG_ERR_OVERFLOW;
  }

  uint8_t *payload = (uint8_t *)malloc(payload_len);
  if (payload == NULL) {
    memdbg_process_maps_free(&list);
    return MEMDBG_ERR_NOMEM;
  }

  uint32_t count32 = (uint32_t)list.count;
  memcpy(payload, &count32, sizeof(count32));
  if (entries_size != 0U)
    memcpy(payload + sizeof(count32), list.entries, entries_size);

  int rc = send_response(fd, req, MEMDBG_OK, payload, (uint32_t)payload_len);
  free(payload);
  memdbg_process_maps_free(&list);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Process info ---- */

memdbg_status_t handle_process_info(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len) {
  if (body_len != sizeof(memdbg_process_info_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_process_info_request_t *ir =
      (const memdbg_process_info_request_t *)body;

  memdbg_process_info_response_t info;
  memset(&info, 0, sizeof(info));
  memdbg_status_t st = memdbg_process_info(ir->pid, &info);
  return send_response(fd, req, st,
      st == MEMDBG_OK ? &info : NULL,
      st == MEMDBG_OK ? (uint32_t)sizeof(info) : 0U) == 0
      ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Batch process info ---- */

memdbg_status_t handle_batch_process_info(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len) {
  if (body_len < sizeof(memdbg_batch_process_info_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_batch_process_info_request_t *br =
      (const memdbg_batch_process_info_request_t *)body;

  uint32_t count = br->count;
  if (count == 0U || count > 64U) return MEMDBG_ERR_PARAM;
  if (body_len < sizeof(*br) + count * sizeof(int32_t))
    return MEMDBG_ERR_PROTOCOL;

  const int32_t *pids = (const int32_t *)((const uint8_t *)body + sizeof(*br));
  size_t entries_size = count * sizeof(memdbg_process_info_response_t);
  uint8_t *payload = (uint8_t *)malloc(
      sizeof(memdbg_batch_process_info_response_t) + entries_size);
  if (payload == NULL) return MEMDBG_ERR_NOMEM;

  memdbg_batch_process_info_response_t *resp =
      (memdbg_batch_process_info_response_t *)payload;
  resp->count = count;
  resp->reserved = 0;
  memdbg_process_info_response_t *entries =
      (memdbg_process_info_response_t *)(payload + sizeof(*resp));

  memdbg_status_t overall = MEMDBG_OK;
  for (uint32_t i = 0U; i < count; ++i) {
    memset(&entries[i], 0, sizeof(entries[i]));
    memdbg_status_t st = memdbg_process_info(pids[i], &entries[i]);
    if (st != MEMDBG_OK) overall = st;
  }

  uint32_t payload_len = (uint32_t)(sizeof(*resp) + entries_size);
  int rc = send_response(fd, req, overall, payload, payload_len);
  free(payload);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Foreground app ---- */

memdbg_status_t handle_foreground_app(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len) {
  (void)body; (void)body_len;
  memdbg_foreground_app_response_t fg;
  memset(&fg, 0, sizeof(fg));
  (void)fg;
  memdbg_status_t st = MEMDBG_ERR_UNSUPPORTED;
  return send_response(fd, req, st,
      st == MEMDBG_OK ? &fg : NULL,
      st == MEMDBG_OK ? (uint32_t)sizeof(fg) : 0U) == 0
      ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Process control (stop/continue/kill) ---- */

memdbg_status_t handle_process_control(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    uint32_t expected_action) {
  if (body_len != sizeof(memdbg_process_control_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_process_control_request_t *cr =
      (const memdbg_process_control_request_t *)body;
  if (cr->action != expected_action) return MEMDBG_ERR_PARAM;

  (void)cr;
  (void)expected_action;
  memdbg_status_t st = MEMDBG_ERR_UNSUPPORTED;
  return send_response(fd, req, st, NULL, 0U) == 0
      ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Remote function call (ptrace trampoline) ---- */

memdbg_status_t handle_process_call(int fd,
    const memdbg_packet_header_t *req,
    const void *body, uint32_t body_len,
    memdbg_send_response_fn send_response_fn,
    void (*sleep_ms_fn)(uint32_t)) {
  if (sleep_ms_fn == NULL) sleep_ms_fn = memdbg_sleep_ms;
  if (body_len != sizeof(memdbg_process_call_request_t))
    return MEMDBG_ERR_PROTOCOL;
  const memdbg_process_call_request_t *cr =
      (const memdbg_process_call_request_t *)body;
  if (cr->pid <= 1 || cr->function_address == 0U)
    return MEMDBG_ERR_PARAM;
  if ((pid_t)cr->pid == getpid())
    return MEMDBG_ERR_PERMISSION;

  bool was_attached = memdbg_debugger_is_attached();
  int32_t prev_pid = was_attached ? memdbg_debugger_attached_pid() : 0;
  bool need_detach = false;

  if (!was_attached || prev_pid != cr->pid) {
    if (was_attached)
      (void)memdbg_debugger_detach();
    memdbg_status_t st = memdbg_debugger_attach(cr->pid);
    if (st != MEMDBG_OK) return st;
    need_detach = true;
  }

  memdbg_status_t st = memdbg_debugger_stop();
  if (st != MEMDBG_OK) {
    if (need_detach) (void)memdbg_debugger_detach();
    return st;
  }

  int32_t lwps[1] = {0};
  char names_buf[1][24];
  uint32_t states[1];
  uint32_t count = 1U;
  memdbg_debugger_get_threads(lwps, names_buf, states, &count, 1U);
  if (count == 0U) {
    if (need_detach) (void)memdbg_debugger_detach();
    return MEMDBG_ERR_STATE;
  }
  int32_t lwp = lwps[0];

  memdbg_debug_regs_t orig_regs;
  memset(&orig_regs, 0, sizeof(orig_regs));
  st = memdbg_debugger_get_regs(lwp, &orig_regs);
  if (st != MEMDBG_OK) {
    if (need_detach) (void)memdbg_debugger_detach();
    return st;
  }

  uint64_t stub_addr = 0U;
  st = pal_memory_alloc(cr->pid, 0U, (size_t)4096U,
      MEMDBG_MAP_PROT_READ | MEMDBG_MAP_PROT_EXEC, 0U, &stub_addr);
  if (st != MEMDBG_OK) {
    if (need_detach) (void)memdbg_debugger_detach();
    return MEMDBG_ERR_NOMEM;
  }

  {
    uint8_t cc = 0xCCU;
    size_t written = 0U;
    st = pal_memory_write(cr->pid, stub_addr, &cc, 1U, &written);
    if (st != MEMDBG_OK || written != 1U) {
      (void)pal_memory_free(cr->pid, stub_addr, (size_t)4096U);
      if (need_detach) (void)memdbg_debugger_detach();
      return MEMDBG_ERR_IO;
    }
  }

  memdbg_debug_regs_t call_regs = orig_regs;
  call_regs.r_rsp = (orig_regs.r_rsp & ~0xFULL) - 8U;
  call_regs.r_rdi  = (int64_t)cr->args[0];
  call_regs.r_rsi  = (int64_t)cr->args[1];
  call_regs.r_rdx  = (int64_t)cr->args[2];
  call_regs.r_rcx  = (int64_t)cr->args[3];
  call_regs.r_r8   = (int64_t)cr->args[4];
  call_regs.r_r9   = (int64_t)cr->args[5];
  call_regs.r_rip  = (int64_t)cr->function_address;

  {
    size_t written = 0U;
    st = pal_memory_write(cr->pid, (uint64_t)call_regs.r_rsp,
        &stub_addr, 8U, &written);
    if (st != MEMDBG_OK || written != 8U) {
      (void)pal_memory_free(cr->pid, stub_addr, (size_t)4096U);
      (void)memdbg_debugger_set_regs(lwp, &orig_regs);
      if (need_detach) (void)memdbg_debugger_detach();
      return MEMDBG_ERR_IO;
    }
  }

  st = memdbg_debugger_set_regs(lwp, &call_regs);
  if (st != MEMDBG_OK) {
    (void)pal_memory_free(cr->pid, stub_addr, (size_t)4096U);
    if (need_detach) (void)memdbg_debugger_detach();
    return st;
  }

  st = memdbg_debugger_continue();
  if (st != MEMDBG_OK) {
    (void)pal_memory_free(cr->pid, stub_addr, (size_t)4096U);
    (void)memdbg_debugger_set_regs(lwp, &orig_regs);
    if (need_detach) (void)memdbg_debugger_detach();
    return st;
  }

  {
    const uint32_t max_wait_ms = 5000U;
    uint32_t waited_ms = 0U;
    while (!memdbg_debugger_is_stopped() && waited_ms < max_wait_ms) {
      (void)memdbg_debugger_poll_events();
      sleep_ms_fn(10U);
      waited_ms += 10U;
    }
    if (!memdbg_debugger_is_stopped()) {
      (void)memdbg_debugger_stop();
      (void)memdbg_debugger_set_regs(lwp, &orig_regs);
      (void)pal_memory_free(cr->pid, stub_addr, (size_t)4096U);
      if (need_detach) (void)memdbg_debugger_detach();
      return MEMDBG_ERR_STATE;
    }
  }

  memdbg_debug_regs_t ret_regs;
  memset(&ret_regs, 0, sizeof(ret_regs));
  st = memdbg_debugger_get_regs(lwp, &ret_regs);

  (void)memdbg_debugger_set_regs(lwp, &orig_regs);
  (void)pal_memory_free(cr->pid, stub_addr, (size_t)4096U);

  if (need_detach)
    (void)memdbg_debugger_detach();

  memdbg_process_call_response_t resp;
  memset(&resp, 0, sizeof(resp));
  if (st == MEMDBG_OK)
    resp.rax = (uint64_t)ret_regs.r_rax;

  return send_response_fn(fd, req, st, &resp,
      st == MEMDBG_OK ? (uint32_t)sizeof(resp) : 0U) == 0
             ? MEMDBG_OK
             : MEMDBG_ERR_NET;
}
