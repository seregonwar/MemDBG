/*
 * memDBG - ps5debug legacy: dispatch, client handler, listener, lifecycle.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "legacy_internal.h"

/* ---- Shared globals ---- */

atomic_bool g_legacy_running  = ATOMIC_VAR_INIT(false);
socket_t    g_legacy_listen_fd = PAL_INVALID_SOCKET;
pthread_t   g_legacy_thread;
bool        g_legacy_thread_started = false;
memdbg_config_t g_legacy_cfg;

/* ---- Dispatch ---- */

memdbg_status_t legacy_dispatch(socket_t fd, const memdbg_config_t *cfg,
                                const legacy_packet_header_t *header, const void *body) {
  if (header == NULL || !legacy_is_valid_command(header->command))
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;

  switch (header->command) {
  case LEGACY_CMD_VERSION:     return legacy_handle_version(fd);
  case LEGACY_CMD_FW_VERSION:  return legacy_handle_fw_version(fd);
  case LEGACY_CMD_BRANDING:    return legacy_handle_branding(fd);
  case LEGACY_CMD_PLATFORM_ID: return legacy_handle_platform_id_cmd(fd);
  case LEGACY_CMD_PROC_NOP:
  case LEGACY_CMD_PROC_AUTH:
    return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  case LEGACY_CMD_PROC_LIST:        return legacy_handle_process_list(fd);
  case LEGACY_CMD_PROC_READ:        return legacy_handle_memory_read(fd, cfg, body, header->data_len);
  case LEGACY_CMD_PROC_WRITE:       return legacy_handle_memory_write(fd, cfg, body, header->data_len);
  case LEGACY_CMD_PROC_WRITE_MULTI: return legacy_handle_write_multi(fd, cfg, body, header->data_len);
  case LEGACY_CMD_PROC_MAPS:        return legacy_handle_process_maps(fd, body, header->data_len);
  case LEGACY_CMD_PROC_INSTALL:     return legacy_handle_install(fd);
  case LEGACY_CMD_PROC_PROTECT:     return legacy_handle_process_protect(fd, body, header->data_len);
  case LEGACY_CMD_PROC_INFO:        return legacy_handle_process_info(fd, body, header->data_len);
  case LEGACY_CMD_PROC_ALLOC:       return legacy_handle_process_alloc(fd, body, header->data_len, false);
  case LEGACY_CMD_PROC_FREE:        return legacy_handle_process_free(fd, body, header->data_len);
  case LEGACY_CMD_PROC_FIRST_MAP:   return legacy_handle_first_map(fd, body, header->data_len);
  case LEGACY_CMD_PROC_ALLOC_HINTED:return legacy_handle_process_alloc(fd, body, header->data_len, true);

  case LEGACY_CMD_SCAN:       return legacy_handle_scan_exact(fd, body, header->data_len);
  case LEGACY_CMD_SCAN_AOB:   return legacy_handle_scan_aob_start(fd, body, header->data_len);
  case LEGACY_CMD_SCAN_CONT:
  case LEGACY_CMD_SCAN_FETCH: return legacy_handle_scan_cont(fd);

  case LEGACY_CMD_DEBUG_ATTACH: {
    struct sockaddr_storage peer_ss; socklen_t peer_len = (socklen_t)sizeof(peer_ss);
    (void)getpeername(fd, (struct sockaddr *)&peer_ss, &peer_len);
    return legacy_handle_debug_attach(fd, body, header->data_len, &peer_ss);
  }
  case LEGACY_CMD_DEBUG_DETACH:        return legacy_handle_debug_detach(fd);
  case LEGACY_CMD_DEBUG_STOP:          return legacy_handle_debug_stop_cmd(fd);
  case LEGACY_CMD_DEBUG_CONTINUE:      return legacy_handle_debug_continue_cmd(fd);
  case LEGACY_CMD_DEBUG_STEP:          return legacy_handle_debug_step_cmd(fd, body, header->data_len);
  case LEGACY_CMD_DEBUG_GET_REGS:      return legacy_handle_debug_get_regs(fd, body, header->data_len);
  case LEGACY_CMD_DEBUG_SET_REGS:      return legacy_handle_debug_set_regs(fd, body, header->data_len);
  case LEGACY_CMD_DEBUG_SET_BP:        return legacy_handle_debug_set_bp(fd, body, header->data_len);
  case LEGACY_CMD_DEBUG_CLEAR_BP:      return legacy_handle_debug_clear_bp(fd, body, header->data_len);
  case LEGACY_CMD_DEBUG_SET_WP:        return legacy_handle_debug_set_wp(fd, body, header->data_len);
  case LEGACY_CMD_DEBUG_CLEAR_WP:      return legacy_handle_debug_clear_wp(fd, body, header->data_len);
  case LEGACY_CMD_DEBUG_GET_THREADS:   return legacy_handle_debug_get_threads(fd);
  case LEGACY_CMD_DEBUG_SUSPEND_TID:   return legacy_handle_debug_suspend_thread(fd, body, header->data_len);
  case LEGACY_CMD_DEBUG_RESUME_TID:    return legacy_handle_debug_resume_thread(fd, body, header->data_len);

  case LEGACY_CMD_KERN_BASE:  return legacy_handle_kern_base(fd);
  case LEGACY_CMD_KERN_READ:  return legacy_handle_kern_read(fd, cfg, body, header->data_len);
  case LEGACY_CMD_KERN_WRITE: return legacy_handle_kern_write(fd, cfg, body, header->data_len);

  /* Analysis: disasm, xrefs, remote call, ELF load */
  case LEGACY_CMD_DISASM:        return legacy_handle_disasm(fd, body, header->data_len);
  case LEGACY_CMD_XREFS:         return legacy_handle_xrefs(fd, body, header->data_len);
  case LEGACY_CMD_PROC_CALL:     return legacy_handle_proc_call(fd, body, header->data_len);
  case LEGACY_CMD_PROC_ELF_LOAD: return legacy_handle_proc_elf_load(fd, body, header->data_len);

  /* FlashScan: server-resident scanning with snapshots */
  case LEGACY_CMD_QUICKSCAN_CAPS:    return legacy_handle_quickscan_caps(fd);
  case LEGACY_CMD_QUICKSCAN_START:   return legacy_handle_quickscan_start(fd, body, header->data_len);
  case LEGACY_CMD_QUICKSCAN_COUNT:   return legacy_handle_quickscan_count(fd, body, header->data_len);
  case LEGACY_CMD_QUICKSCAN_FETCH:   return legacy_handle_quickscan_fetch(fd, body, header->data_len);
  case LEGACY_CMD_QUICKSCAN_END:     return legacy_handle_quickscan_end(fd);
  case LEGACY_CMD_QUICKSCAN_CONFIG:  return legacy_handle_quickscan_config(fd, body, header->data_len);
  case LEGACY_CMD_QUICKSCAN_REGIONS: return legacy_handle_quickscan_regions(fd, body, header->data_len);

  default:
    return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  }
}

/* ---- Client handler ---- */

static void legacy_handle_client(socket_t fd, const memdbg_config_t *cfg) {
  (void)pal_socket_set_nonblocking(fd, false);
  (void)pal_socket_configure(fd);

  while (atomic_load_explicit(&g_legacy_running, memory_order_relaxed) && !memdbg_daemon_should_stop()) {
    legacy_packet_header_t header; void *body = NULL;
    int ready = legacy_wait_for_fd(fd);
    if (ready == 0) continue; if (ready < 0) break;
    if (pal_socket_read_exact(fd, &header, sizeof(header)) < 0) break;
    if (header.magic != LEGACY_PACKET_MAGIC) { (void)legacy_send_status(fd, LEGACY_CMD_ERROR); break; }
    if (header.data_len > cfg->max_packet_bytes) { (void)legacy_send_status(fd, LEGACY_CMD_ERROR); break; }
    if (header.data_len != 0U) {
      body = malloc(header.data_len);
      if (body == NULL) { (void)legacy_send_status(fd, LEGACY_CMD_DATA_NULL); break; }
      if (pal_socket_read_exact(fd, body, header.data_len) < 0) { free(body); break; }
    }
    if (legacy_dispatch(fd, cfg, &header, body) == MEMDBG_ERR_NET) { free(body); break; }
    free(body);
  }

  pthread_mutex_lock(&g_debugger_mutex); bool dbg_active = g_debugger.attached; pthread_mutex_unlock(&g_debugger_mutex);
  if (dbg_active) { memdbg_log_write(MEMDBG_LOG_INFO, "ps5debug-legacy: client disconnected, cleaning up debugger session"); debugger_session_cleanup(); }
  (void)pal_socket_close(fd);
}

static void *legacy_client_thread(void *arg) {
  legacy_client_args_t *c = (legacy_client_args_t *)arg; socket_t fd = c->fd; memdbg_config_t cfg = c->cfg;
  free(c); legacy_handle_client(fd, &cfg); return NULL;
}

static void legacy_spawn_client(socket_t fd, const memdbg_config_t *cfg) {
  legacy_client_args_t *args = (legacy_client_args_t *)malloc(sizeof(*args));
  if (args == NULL) { (void)pal_socket_close(fd); return; }
  args->fd = fd; args->cfg = *cfg;
  pthread_t tid; pthread_attr_t attr;
  (void)pthread_attr_init(&attr); (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  if (pthread_create(&tid, &attr, legacy_client_thread, args) != 0) { free(args); (void)pal_socket_close(fd); }
  (void)pthread_attr_destroy(&attr);
}

/* ---- Listener ---- */

static void *legacy_listener_thread(void *arg) {
  (void)arg;
  while (atomic_load_explicit(&g_legacy_running, memory_order_relaxed) && !memdbg_daemon_should_stop()) {
    struct sockaddr_storage ss; socklen_t slen = (socklen_t)sizeof(ss);
    int ready = legacy_wait_for_fd(g_legacy_listen_fd);
    if (ready == 0) continue;
    if (ready < 0) {
      if (atomic_load_explicit(&g_legacy_running, memory_order_relaxed) && !memdbg_daemon_should_stop())
        memdbg_log_write(MEMDBG_LOG_WARN, "ps5debug-legacy: listener wait failed: %s", pal_socket_last_error());
      break;
    }
    socket_t client_fd = accept(g_legacy_listen_fd, (struct sockaddr *)&ss, &slen);
    if (client_fd < 0) { if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue; if (memdbg_daemon_should_stop()) break; memdbg_log_write(MEMDBG_LOG_WARN, "ps5debug-legacy: accept failed: %s", pal_socket_last_error()); continue; }
    if (!legacy_peer_allowed(&g_legacy_cfg, &ss)) { (void)pal_socket_close(client_fd); continue; }
    legacy_spawn_client(client_fd, &g_legacy_cfg);
  }
  return NULL;
}

/* ---- Start / Stop ---- */

memdbg_status_t memdbg_legacy_start(const memdbg_config_t *cfg) {
  socket_t listen_fd = PAL_INVALID_SOCKET;
  if (cfg == NULL || cfg->legacy_port == 0U) return MEMDBG_ERR_PARAM;
  if (atomic_exchange_explicit(&g_legacy_running, true, memory_order_relaxed)) return MEMDBG_OK;
  if (pal_tcp_listen(cfg->bind_host, cfg->legacy_port, 12, &listen_fd) != 0) { atomic_store_explicit(&g_legacy_running, false, memory_order_relaxed); return MEMDBG_ERR_NET; }
  g_legacy_cfg = *cfg; g_legacy_listen_fd = listen_fd;
  if (pthread_create(&g_legacy_thread, NULL, legacy_listener_thread, NULL) != 0) { (void)pal_socket_close(g_legacy_listen_fd); g_legacy_listen_fd = PAL_INVALID_SOCKET; atomic_store_explicit(&g_legacy_running, false, memory_order_relaxed); return MEMDBG_ERR_NET; }
  g_legacy_thread_started = true; return MEMDBG_OK;
}

void memdbg_legacy_stop(void) {
  debugger_session_cleanup(); scan_session_reset();
  if (!atomic_exchange_explicit(&g_legacy_running, false, memory_order_relaxed)) return;
  if (g_legacy_listen_fd != PAL_INVALID_SOCKET) { (void)shutdown(g_legacy_listen_fd, SHUT_RDWR); (void)pal_socket_close(g_legacy_listen_fd); g_legacy_listen_fd = PAL_INVALID_SOCKET; }
  if (g_legacy_thread_started) { (void)pthread_join(g_legacy_thread, NULL); g_legacy_thread_started = false; }
}
