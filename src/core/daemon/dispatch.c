/*
 * memDBG - Protocol dispatch and hello/telemetry handlers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Extracted from src/core/daemon/memdbg.c.
 */

#include "daemon_internal.h"

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"

#include "memdbg/debug/memdbg_disasm.h"
#include "memdbg/debug/memdbg_assembler.h"
#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/debug/memdbg_process.h"
#include "memdbg/tracer/memdbg_tracer_daemon.h"
#include "memdbg/pal/pal_notification.h"
#include "memdbg/pal/pal_time.h"
#include "memdbg/scanner/flashscan.h"
#include "memdbg/scanner/pt_walker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- External declarations for features without dedicated headers ---- */

extern int memdbg_auth_handle(int fd, const memdbg_auth_key_request_t *req);
extern int memdbg_arena_config_handle(int fd, const memdbg_arena_config_request_t *req);
extern int memdbg_batch_write_adv_handle(int fd, const memdbg_batch_write_adv_request_t *req,
                                         const uint8_t *body, uint32_t body_len);
extern int memdbg_hijack_handle(int fd, const memdbg_process_hijack_request_t *req,
                                const uint8_t *body, uint32_t body_len);

/* ---- Platform helper ---- */

static uint16_t memdbg_platform_id(void) {
#if defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
  return (uint16_t)MEMDBG_PLATFORM_PS4;
#elif defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
  return (uint16_t)MEMDBG_PLATFORM_PS5;
#else
  return (uint16_t)MEMDBG_PLATFORM_HOST;
#endif
}

/* ---- HELLO ---- */

memdbg_status_t handle_hello(const memdbg_config_t *cfg,
                             memdbg_hello_response_t *out) {
  if (cfg == NULL || out == NULL) return MEMDBG_ERR_PARAM;
  memset(out, 0, sizeof(*out));
  out->protocol_version = MEMDBG_PROTOCOL_VERSION;
  out->platform_id      = memdbg_platform_id();
  out->capabilities     = memdbg_capabilities(cfg);
  out->debug_port       = cfg->debug_port;
  out->udp_log_port     = cfg->enable_udp_log ? cfg->udp_log_port : 0U;
  size_t version_len = sizeof(MEMDBG_VERSION_STRING) - 1U;
  if (version_len >= sizeof(out->version)) version_len = sizeof(out->version) - 1U;
  memcpy(out->version, MEMDBG_VERSION_STRING, version_len);
  (void)snprintf(out->name, sizeof(out->name), "MemDBG");
  return MEMDBG_OK;
}

/* ---- TELEMETRY ---- */

memdbg_status_t handle_telemetry(int fd, const memdbg_packet_header_t *req) {
  memdbg_telemetry_response_t telemetry;
  memset(&telemetry, 0, sizeof(telemetry));

  memdbg_memory_telemetry(&telemetry);

  uint64_t now = monotonic_seconds();
  telemetry.uptime_seconds     = now >= g_start_ticks ? now - g_start_ticks : 0U;
  telemetry.active_connections = atomic_load_explicit(&g_active_connections, memory_order_relaxed);
  telemetry.thread_pool_size   = MEMDBG_THREAD_POOL_SIZE;

  uint32_t hits = 0U, misses = 0U;
  memdbg_process_cache_stats(&hits, &misses);
  telemetry.scan_cache_hits   = hits;
  telemetry.scan_cache_misses = misses;

  return send_response(fd, req, MEMDBG_OK, &telemetry, sizeof(telemetry)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

/* ---- Dispatch ---- */

memdbg_status_t dispatch_packet(int fd, const memdbg_config_t *cfg,
                                const memdbg_packet_header_t *req,
                                const void *body) {
  switch ((memdbg_command_t)req->command) {
  case MEMDBG_CMD_HELLO: {
    memdbg_hello_response_t hello;
    memdbg_status_t status = handle_hello(cfg, &hello);
    if (status != MEMDBG_OK) return status;
    return send_response(fd, req, MEMDBG_OK, &hello, sizeof(hello)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }
  case MEMDBG_CMD_PING:
    return send_response(fd, req, MEMDBG_OK, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  case MEMDBG_CMD_PROCESS_LIST:       return handle_process_list(fd, req);
  case MEMDBG_CMD_PROCESS_MAPS:       return handle_process_maps(fd, req, body, req->length);
  case MEMDBG_CMD_PROCESS_INFO:       return handle_process_info(fd, req, body, req->length);
  case MEMDBG_CMD_MEMORY_READ:        return handle_memory_read(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_MEMORY_WRITE:       return handle_memory_write(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_BATCH_READ:         return handle_batch_read(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_BATCH_WRITE:        return handle_batch_write(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_BATCH_PROCESS_INFO: return handle_batch_process_info(fd, req, body, req->length);
  case MEMDBG_CMD_SCAN_EXACT:         return handle_scan_exact_v2(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_PROCESS_EXACT: return handle_scan_process_exact(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_AOB:           return handle_scan_aob(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_PROCESS_AOB:
    return handle_scan_process_aob(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_POINTER:       return handle_scan_pointer(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_SCAN_UNKNOWN:       return handle_scan_unknown(fd, req, cfg, body, req->length);
  case MEMDBG_CMD_FOREGROUND_APP:     return handle_foreground_app(fd, req, body, req->length);
  case MEMDBG_CMD_PROCESS_STOP:       return handle_process_control(fd, req, body, req->length, 1U);
  case MEMDBG_CMD_PROCESS_CONTINUE:   return handle_process_control(fd, req, body, req->length, 2U);
  case MEMDBG_CMD_PROCESS_KILL:       return handle_process_control(fd, req, body, req->length, 3U);
  case MEMDBG_CMD_PROCESS_PROTECT:    return handle_process_protect(fd, req, body, req->length);
  case MEMDBG_CMD_PROCESS_ALLOC:      return handle_process_alloc(fd, req, body, req->length);
  case MEMDBG_CMD_PROCESS_FREE:       return handle_process_free(fd, req, body, req->length);
  case MEMDBG_CMD_PROCESS_STACK:      return handle_process_stack(fd, req, body, req->length);
  case MEMDBG_CMD_PROCESS_CALL:       return handle_process_call(fd, req, body, req->length, send_response, memdbg_sleep_ms);
  case MEMDBG_CMD_PROCESS_ELF_LOAD:   return handle_process_elf_load(fd, req, body, req->length);
  case MEMDBG_CMD_PROCESS_HIJACK: {
    if (req->length < sizeof(memdbg_process_hijack_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_process_hijack_request_t *hj = (const memdbg_process_hijack_request_t *)body;
    int r = memdbg_hijack_handle(fd, hj, (const uint8_t *)body, req->length);
    return (r == 0) ? MEMDBG_OK : MEMDBG_ERR_PROTOCOL;
  }
  case MEMDBG_CMD_PROCESS_DUMP:
    return handle_process_dump(fd, req, body, req->length);
  case MEMDBG_CMD_KERNEL_BASE:        return handle_kernel_base(fd, req);
  case MEMDBG_CMD_KERNEL_READ:        return handle_kernel_read(fd, req, body, req->length);
  case MEMDBG_CMD_KERNEL_WRITE:       return handle_kernel_write(fd, req, body, req->length);
  case MEMDBG_CMD_CONSOLE_NOTIFY:     return handle_console_notify(fd, req, body, req->length);
  case MEMDBG_CMD_CONSOLE_PRINT:      return handle_console_print(fd, req, body, req->length);
  case MEMDBG_CMD_CONSOLE_REBOOT:     return handle_console_reboot(fd, req);
  case MEMDBG_CMD_DEBUG_ATTACH:
    memdbg_tracer_daemon_stop();
    return handle_debug_attach(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_DETACH:       return handle_debug_detach(fd, req, send_response);
  case MEMDBG_CMD_DEBUG_STOP:         return handle_debug_stop(fd, req, send_response);
  case MEMDBG_CMD_DEBUG_CONTINUE:     return handle_debug_continue(fd, req, send_response);
  case MEMDBG_CMD_DEBUG_STEP:         return handle_debug_step(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_GET_THREADS:  return handle_debug_get_threads(fd, req, send_response);
  case MEMDBG_CMD_DEBUG_GET_REGS:     return handle_debug_get_regs(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_SET_REGS:     return handle_debug_set_regs(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_GET_DBREGS:   return handle_debug_get_dbregs(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_SET_DBREGS:   return handle_debug_set_dbregs(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_GET_FPREGS:   return handle_debug_get_fpregs(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_SET_FPREGS:   return handle_debug_set_fpregs(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_GET_FSGSBASE: return handle_debug_get_fsgsbase(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_SET_FSGSBASE: return handle_debug_set_fsgsbase(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_SET_BREAKPOINT: return handle_debug_set_breakpoint(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_SET_BREAKPOINT_COND: return handle_debug_set_breakpoint_cond(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_CLEAR_BREAKPOINT: return handle_debug_clear_breakpoint(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_SET_WATCHPOINT: return handle_debug_set_watchpoint(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_CLEAR_WATCHPOINT: return handle_debug_clear_watchpoint(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_DEBUG_SUSPEND_THREAD: return handle_debug_thread_control(fd, req, body, req->length, true, send_response);
  case MEMDBG_CMD_DEBUG_RESUME_THREAD:  return handle_debug_thread_control(fd, req, body, req->length, false, send_response);
  case MEMDBG_CMD_DEBUG_POLL_EVENTS:    return handle_debug_poll_events(fd, req, send_response);
  case MEMDBG_CMD_DEBUG_GET_BREAKPOINTS: return handle_debug_get_breakpoints(fd, req, send_response);
  case MEMDBG_CMD_DEBUG_GET_WATCHPOINTS: return handle_debug_get_watchpoints(fd, req, send_response);
  case MEMDBG_CMD_DEBUG_CLEAR_ALL_BREAKPOINTS: return handle_debug_clear_all_breakpoints(fd, req, send_response);
  case MEMDBG_CMD_DEBUG_CLEAR_ALL_WATCHPOINTS:  return handle_debug_clear_all_watchpoints(fd, req, send_response);
  case MEMDBG_CMD_TRACER_ATTACH:       return handle_tracer_attach(fd, req, body, req->length, send_response);
  case MEMDBG_CMD_TRACER_DETACH:       return handle_tracer_detach(fd, req, send_response);
  case MEMDBG_CMD_TRACER_POLL:         return handle_tracer_poll(fd, req, send_response);
  case MEMDBG_CMD_TRACER_STATUS:       return handle_tracer_status(fd, req, send_response);
  case MEMDBG_CMD_TELEMETRY:          return handle_telemetry(fd, req);
  case MEMDBG_CMD_SHUTDOWN:
    pal_notification_send("MemDBG remote termination");
    memdbg_daemon_request_stop();
    return send_response(fd, req, MEMDBG_OK, NULL, 0U) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;

  /* ---- Assembler / disassembler ---- */
  case MEMDBG_CMD_ASM_ENCODE:
    return memdbg_asm_encode(fd, (const uint8_t *)body, req->length);

  case MEMDBG_CMD_DISASM: {
    if (req->length < sizeof(memdbg_disasm_request_t)) return MEMDBG_ERR_PROTOCOL;
    int r = memdbg_disasm_multiple(fd, (const uint8_t *)body, req->length);
    return (r == 0) ? MEMDBG_OK : MEMDBG_ERR_PROTOCOL;
  }

  case MEMDBG_CMD_XREFS_TO: {
    if (req->length < sizeof(memdbg_xrefs_to_request_t)) return MEMDBG_ERR_PROTOCOL;
    int r = memdbg_xrefs_multiple(fd, (const uint8_t *)body, req->length);
    return (r == 0) ? MEMDBG_OK : MEMDBG_ERR_PROTOCOL;
  }

  /* ---- FlashScan engine ---- */
  case MEMDBG_CMD_QUICKSCAN_CAPS:
    flashscan_handle_caps(fd);
    return MEMDBG_OK;

  case MEMDBG_CMD_QUICKSCAN_START: {
    if (req->length < sizeof(memdbg_quickscan_start_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_quickscan_start_request_t *qs = (const memdbg_quickscan_start_request_t *)body;
    uint32_t data_off = (uint32_t)sizeof(*qs);
    uint32_t data_len = qs->value_length;
    int is_bet = (qs->compare_type == 4);
    const uint8_t *cmp_data = (data_off + data_len * (is_bet ? 2 : 1) <= req->length)
                              ? ((const uint8_t *)body + data_off) : NULL;
    const uint8_t *qs_mask = NULL;
    if (qs->value_type == 10) {
      uint32_t moff = data_off + data_len * (is_bet ? 2 : 1);
      if (moff + data_len <= req->length) qs_mask = (const uint8_t *)body + moff;
    }
    flashscan_handle_start(fd, qs, cmp_data, qs_mask, 0);
    return MEMDBG_OK;
  }

  case MEMDBG_CMD_QUICKSCAN_COUNT: {
    if (req->length < sizeof(memdbg_quickscan_count_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_quickscan_count_request_t *qc = (const memdbg_quickscan_count_request_t *)body;
    uint32_t d_off = (uint32_t)sizeof(*qc);
    uint32_t d_len = qc->value_length;
    const uint8_t *cmp_d = (d_off + d_len <= req->length) ? ((const uint8_t *)body + d_off) : NULL;
    const uint8_t *qc_mask = NULL;
    if (qc->value_type == 10) {
      uint32_t mo = d_off + d_len;
      if (mo + d_len <= req->length) qc_mask = (const uint8_t *)body + mo;
    }
    flashscan_handle_count(fd, qc, cmp_d, qc_mask, 0);
    return MEMDBG_OK;
  }

  case MEMDBG_CMD_QUICKSCAN_FETCH: {
    if (req->length < sizeof(memdbg_quickscan_fetch_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_quickscan_fetch_request_t *qf = (const memdbg_quickscan_fetch_request_t *)body;
    flashscan_handle_fetch(fd, qf, 0);
    return MEMDBG_OK;
  }

  case MEMDBG_CMD_QUICKSCAN_END:
    flashscan_handle_end(fd, 0);
    return MEMDBG_OK;

  case MEMDBG_CMD_QUICKSCAN_CONFIG: {
    if (req->length < sizeof(memdbg_quickscan_config_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_quickscan_config_request_t *qc = (const memdbg_quickscan_config_request_t *)body;
    uint32_t plen = qc->spill_path_len;
    const uint8_t *pextra = (sizeof(*qc) + plen <= req->length) ? ((const uint8_t *)body + sizeof(*qc)) : NULL;
    flashscan_handle_config(fd, qc, pextra, plen);
    return MEMDBG_OK;
  }

  case MEMDBG_CMD_QUICKSCAN_REGIONS: {
    if (req->length < sizeof(memdbg_quickscan_regions_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_quickscan_regions_request_t *qr = (const memdbg_quickscan_regions_request_t *)body;
    flashscan_handle_regions(fd, qr);
    return MEMDBG_OK;
  }

  /* ---- Page-table walk ---- */
  case MEMDBG_CMD_PTWALK_DISCOVER: {
    uint64_t dmap = 0, p_off = 0;
    int rc = ptw_discover(&dmap, &p_off);
    memdbg_ptwalk_discover_response_t resp;
    resp.status      = (uint32_t)rc;
    resp.dmap_base   = dmap;
    resp.pmap_offset = p_off;
    return send_response(fd, req, MEMDBG_OK, &resp, sizeof(resp)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  case MEMDBG_CMD_PTWALK_AUGMENT: {
    if (req->length < sizeof(memdbg_ptwalk_augment_request_t)) return MEMDBG_ERR_PROTOCOL;
    return handle_process_maps(fd, req, body, req->length);
  }

  case MEMDBG_CMD_PTWALK_READ: {
    if (req->length < sizeof(memdbg_ptwalk_io_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_ptwalk_io_request_t *pr = (const memdbg_ptwalk_io_request_t *)body;
    uint8_t *buf = (uint8_t *)malloc(pr->length);
    if (!buf) return MEMDBG_ERR_NOMEM;
    int rc = ptw_read((uint32_t)pr->pid, pr->address, pr->length, buf);
    memdbg_status_t st = (rc == 0) ? MEMDBG_OK : MEMDBG_ERR_IO;
    int sr = send_response(fd, req, st, buf, (uint32_t)pr->length);
    free(buf);
    return sr == 0 ? st : MEMDBG_ERR_NET;
  }

  case MEMDBG_CMD_PTWALK_WRITE: {
    if (req->length < sizeof(memdbg_ptwalk_io_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_ptwalk_io_request_t *pw = (const memdbg_ptwalk_io_request_t *)body;
    uint32_t data_len = req->length - (uint32_t)sizeof(*pw);
    const uint8_t *data_ptr = (const uint8_t *)body + sizeof(*pw);
    int rc = ptw_write((uint32_t)pw->pid, pw->address, data_len, data_ptr);
    return send_response(fd, req, (rc == 0) ? MEMDBG_OK : MEMDBG_ERR_IO, NULL, 0) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  case MEMDBG_CMD_PTWALK_PROBE: {
    if (req->length < sizeof(memdbg_ptwalk_probe_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_ptwalk_probe_request_t *pp = (const memdbg_ptwalk_probe_request_t *)body;
    memdbg_ptwalk_probe_response_t resp;
    memset(&resp, 0, sizeof(resp));
    uint64_t phys_address = 0U;
    int page_level = 0;
    uint64_t page_size = 0U;
    uint64_t pte_value = 0U;
    int rc = ptw_probe((uint32_t)pp->pid, pp->address, &phys_address,
                       &page_level, &page_size, &pte_value);
    resp.phys_address = phys_address;
    resp.page_level = (int32_t)page_level;
    resp.page_size = page_size;
    resp.pte_value = pte_value;
    if (rc == 0) resp.cached = (resp.pte_value >> 4) & 1;
    return send_response(fd, req, (rc == 0) ? MEMDBG_OK : MEMDBG_ERR_IO, &resp, sizeof(resp)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  /* ---- Auth ---- */
  case MEMDBG_CMD_AUTH_KEY: {
    if (req->length < sizeof(memdbg_auth_key_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_auth_key_request_t *ak = (const memdbg_auth_key_request_t *)body;
    int r = memdbg_auth_handle(fd, ak);
    return (r == 0) ? MEMDBG_OK : MEMDBG_ERR_PROTOCOL;
  }

  /* ---- Arena config ---- */
  case MEMDBG_CMD_ARENA_CONFIG: {
    if (req->length < sizeof(memdbg_arena_config_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_arena_config_request_t *ac = (const memdbg_arena_config_request_t *)body;
    memdbg_arena_config_handle(fd, ac);
    return MEMDBG_OK;
  }

  /* ---- Bulk write advanced ---- */
  case MEMDBG_CMD_BATCH_WRITE_ADV: {
    if (req->length < sizeof(memdbg_batch_write_adv_request_t)) return MEMDBG_ERR_PROTOCOL;
    const memdbg_batch_write_adv_request_t *bwa = (const memdbg_batch_write_adv_request_t *)body;
    int r = memdbg_batch_write_adv_handle(fd, bwa, (const uint8_t *)body, req->length);
    return (r == 0) ? MEMDBG_OK : MEMDBG_ERR_PROTOCOL;
  }

  /* ---- Klog stream connect ---- */
  case MEMDBG_CMD_KLOG_CONNECT: {
    if (req->length < sizeof(memdbg_klog_connect_request_t)) return MEMDBG_ERR_PROTOCOL;
#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
    uint32_t klog_port = 0xA00CU;
    return send_response(fd, req, MEMDBG_OK, &klog_port, sizeof(klog_port)) == 0
               ? MEMDBG_OK
               : MEMDBG_ERR_NET;
#else
    return send_response(fd, req, MEMDBG_ERR_UNSUPPORTED, NULL, 0U) == 0
               ? MEMDBG_OK
               : MEMDBG_ERR_NET;
#endif
  }

  default:
    return MEMDBG_ERR_PROTOCOL;
  }
}
