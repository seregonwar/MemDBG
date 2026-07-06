/*
 * memDBG - ps5debug compat: debugger bridge.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "legacy_internal.h"
#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/pal/pal_time.h"

legacy_debugger_session_t g_debugger;
pthread_mutex_t g_debugger_mutex = PTHREAD_MUTEX_INITIALIZER;

void debugger_session_init(void) {
  memset(&g_debugger, 0, sizeof(g_debugger));
  g_debugger.intr_fd = PAL_INVALID_SOCKET;
  atomic_store_explicit(&g_debugger.stop_requested, false, memory_order_relaxed);
}

void debugger_intr_disconnect(void) {
  if (g_debugger.intr_fd != PAL_INVALID_SOCKET) {
    (void)shutdown(g_debugger.intr_fd, SHUT_RDWR);
    (void)pal_socket_close(g_debugger.intr_fd);
    g_debugger.intr_fd = PAL_INVALID_SOCKET;
  }
}

void debugger_session_cleanup(void) {
  pthread_mutex_lock(&g_debugger_mutex);
  atomic_store_explicit(&g_debugger.stop_requested, true, memory_order_relaxed);
  bool was_running = g_debugger.intr_thread_running;
  bool was_attached = g_debugger.attached;
  pthread_t intr_t = g_debugger.intr_thread;
  g_debugger.intr_thread_running = false;
  g_debugger.attached = false; g_debugger.pid = 0; g_debugger.peer_host[0] = '\0';
  pthread_mutex_unlock(&g_debugger_mutex);
  if (was_running) (void)pthread_join(intr_t, NULL);
  debugger_intr_disconnect();
  if (was_attached) (void)memdbg_debugger_detach();
}

static bool debugger_connect_intr_socket(void) {
  if (g_debugger.peer_host[0] == '\0') return false;
  socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return false;
  struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET; addr.sin_port = htons(LEGACY_DEBUGGER_INT_PORT);
  if (inet_pton(AF_INET, g_debugger.peer_host, &addr.sin_addr) != 1) { (void)pal_socket_close(fd); return false; }
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    memdbg_log_write(MEMDBG_LOG_WARN, "ps5debug-compat: cannot connect interrupt socket to %s:%u", g_debugger.peer_host, LEGACY_DEBUGGER_INT_PORT);
    (void)pal_socket_close(fd); return false;
  }
  g_debugger.intr_fd = fd;
  memdbg_log_write(MEMDBG_LOG_INFO, "ps5debug-compat: interrupt socket connected to %s:%u", g_debugger.peer_host, LEGACY_DEBUGGER_INT_PORT);
  return true;
}

int legacy_debugger_send_intr(int32_t lwp) {
  uint32_t wire[2]; wire[0] = legacy_bitswap32(LEGACY_CMD_INTERRUPT); wire[1] = (uint32_t)lwp;
  if (g_debugger.intr_fd == PAL_INVALID_SOCKET) return -1;
  return pal_socket_write_all(g_debugger.intr_fd, wire, sizeof(wire)) < 0 ? -1 : 0;
}

static void *legacy_debugger_intr_thread(void *arg) {
  (void)arg; bool was_stopped = false;
  while (!atomic_load_explicit(&g_debugger.stop_requested, memory_order_relaxed) && !memdbg_daemon_should_stop()) {
    memdbg_sleep_ms(100U);
    pthread_mutex_lock(&g_debugger_mutex);
    bool attached = g_debugger.attached; socket_t fd = g_debugger.intr_fd;
    pthread_mutex_unlock(&g_debugger_mutex);
    if (fd == PAL_INVALID_SOCKET || !attached) continue;
    (void)memdbg_debugger_poll_events();
    bool stopped = memdbg_debugger_is_stopped();
    if (stopped && !was_stopped) { int32_t lwp = memdbg_debugger_get_stop_lwp(); if (lwp >= 0) (void)legacy_debugger_send_intr(lwp); }
    was_stopped = stopped;
  }
  return NULL;
}

memdbg_status_t legacy_handle_debug_attach(socket_t fd, const void *body, uint32_t body_len, const struct sockaddr_storage *peer_ss) {
  if (!legacy_has_body(body, body_len, sizeof(legacy_debug_attach_request_t)))
    return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  const legacy_debug_attach_request_t *req = (const legacy_debug_attach_request_t *)body;
  if (!memdbg_debugger_supported()) return legacy_send_status(fd, LEGACY_CMD_ERROR) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  debugger_session_cleanup(); debugger_session_init();
  memdbg_status_t st = memdbg_debugger_attach((int32_t)req->pid);
  if (st != MEMDBG_OK) return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  if (peer_ss != NULL) (void)legacy_sockaddr_ipv4_host(peer_ss, g_debugger.peer_host, sizeof(g_debugger.peer_host));
  if (!debugger_connect_intr_socket())
    memdbg_log_write(MEMDBG_LOG_WARN, "ps5debug-compat: debugger attached but interrupt socket failed");
  if (pthread_create(&g_debugger.intr_thread, NULL, legacy_debugger_intr_thread, NULL) == 0) g_debugger.intr_thread_running = true;
  pthread_mutex_lock(&g_debugger_mutex); g_debugger.attached = true; g_debugger.pid = (int32_t)req->pid; pthread_mutex_unlock(&g_debugger_mutex);
  return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_debug_detach(socket_t fd) { debugger_session_cleanup(); return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }
memdbg_status_t legacy_handle_debug_stop_cmd(socket_t fd) { return legacy_send_memdbg_status(fd, memdbg_debugger_stop()) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }
memdbg_status_t legacy_handle_debug_continue_cmd(socket_t fd) { return legacy_send_memdbg_status(fd, memdbg_debugger_continue()) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET; }

memdbg_status_t legacy_handle_debug_step_cmd(socket_t fd, const void *body, uint32_t body_len) {
  if (!legacy_has_body(body, body_len, sizeof(legacy_debug_step_request_t))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  return legacy_send_memdbg_status(fd, memdbg_debugger_step(((const legacy_debug_step_request_t *)body)->lwp)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_debug_get_regs(socket_t fd, const void *body, uint32_t body_len) {
  if (!legacy_has_body(body, body_len, sizeof(legacy_debug_thread_request_t))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  memdbg_debug_regs_t mr; memdbg_status_t st = memdbg_debugger_get_regs(((const legacy_debug_thread_request_t *)body)->lwp, &mr);
  if (st != MEMDBG_OK) return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  legacy_debug_regs_t lr; memset(&lr, 0, sizeof(lr));
  lr.r15=(uint64_t)mr.r_r15; lr.r14=(uint64_t)mr.r_r14; lr.r13=(uint64_t)mr.r_r13; lr.r12=(uint64_t)mr.r_r12;
  lr.r11=(uint64_t)mr.r_r11; lr.r10=(uint64_t)mr.r_r10; lr.r9=(uint64_t)mr.r_r9; lr.r8=(uint64_t)mr.r_r8;
  lr.rdi=(uint64_t)mr.r_rdi; lr.rsi=(uint64_t)mr.r_rsi; lr.rbp=(uint64_t)mr.r_rbp; lr.rbx=(uint64_t)mr.r_rbx;
  lr.rdx=(uint64_t)mr.r_rdx; lr.rcx=(uint64_t)mr.r_rcx; lr.rax=(uint64_t)mr.r_rax;
  lr.rip=(uint64_t)mr.r_rip; lr.rflags=(uint64_t)mr.r_rflags; lr.rsp=(uint64_t)mr.r_rsp;
  lr.trapno=mr.r_trapno; lr.fs=mr.r_fs; lr.gs=mr.r_gs; lr.err=mr.r_err; lr.es=mr.r_es; lr.ds=mr.r_ds;
  lr.cs=(uint64_t)mr.r_cs; lr.ss=(uint64_t)mr.r_ss;
  return (legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 && legacy_send_blob(fd, &lr, sizeof(lr)) == 0) ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_debug_set_regs(socket_t fd, const void *body, uint32_t body_len) {
  if (body_len < sizeof(legacy_debug_thread_request_t) + sizeof(legacy_debug_regs_t)) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  const legacy_debug_thread_request_t *thr = (const legacy_debug_thread_request_t *)body;
  const legacy_debug_regs_t *lr = (const legacy_debug_regs_t *)((const uint8_t *)body + sizeof(*thr));
  memdbg_debug_regs_t mr; memset(&mr, 0, sizeof(mr));
  mr.r_r15=(int64_t)lr->r15; mr.r_r14=(int64_t)lr->r14; mr.r_r13=(int64_t)lr->r13; mr.r_r12=(int64_t)lr->r12;
  mr.r_r11=(int64_t)lr->r11; mr.r_r10=(int64_t)lr->r10; mr.r_r9=(int64_t)lr->r9; mr.r_r8=(int64_t)lr->r8;
  mr.r_rdi=(int64_t)lr->rdi; mr.r_rsi=(int64_t)lr->rsi; mr.r_rbp=(int64_t)lr->rbp; mr.r_rbx=(int64_t)lr->rbx;
  mr.r_rdx=(int64_t)lr->rdx; mr.r_rcx=(int64_t)lr->rcx; mr.r_rax=(int64_t)lr->rax;
  mr.r_rip=(int64_t)lr->rip; mr.r_rflags=(int64_t)lr->rflags; mr.r_rsp=(int64_t)lr->rsp;
  mr.r_trapno=lr->trapno; mr.r_fs=lr->fs; mr.r_gs=lr->gs; mr.r_err=lr->err; mr.r_es=lr->es; mr.r_ds=lr->ds;
  mr.r_cs=(int64_t)lr->cs; mr.r_ss=(int64_t)lr->ss;
  return legacy_send_memdbg_status(fd, memdbg_debugger_set_regs(thr->lwp, &mr)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_debug_set_bp(socket_t fd, const void *body, uint32_t body_len) {
  if (!legacy_has_body(body, body_len, sizeof(legacy_debug_bp_request_t))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  const legacy_debug_bp_request_t *r = (const legacy_debug_bp_request_t *)body;
  return legacy_send_memdbg_status(fd, memdbg_debugger_set_breakpoint(r->address, r->kind)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_debug_clear_bp(socket_t fd, const void *body, uint32_t body_len) {
  if (!legacy_has_body(body, body_len, sizeof(legacy_debug_bp_request_t))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  return legacy_send_memdbg_status(fd, memdbg_debugger_clear_breakpoint(((const legacy_debug_bp_request_t *)body)->address)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_debug_set_wp(socket_t fd, const void *body, uint32_t body_len) {
  if (!legacy_has_body(body, body_len, sizeof(legacy_debug_wp_request_t))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  const legacy_debug_wp_request_t *r = (const legacy_debug_wp_request_t *)body;
  return legacy_send_memdbg_status(fd, memdbg_debugger_set_watchpoint(r->address, r->length, r->type)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_debug_clear_wp(socket_t fd, const void *body, uint32_t body_len) {
  if (!legacy_has_body(body, body_len, sizeof(legacy_debug_wp_request_t))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  return legacy_send_memdbg_status(fd, memdbg_debugger_clear_watchpoint(((const legacy_debug_wp_request_t *)body)->address)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_debug_get_threads(socket_t fd) {
  int32_t lwps[MEMDBG_DEBUGGER_MAX_THREADS]; char names[MEMDBG_DEBUGGER_MAX_THREADS][24]; uint32_t states[MEMDBG_DEBUGGER_MAX_THREADS]; uint32_t count = MEMDBG_DEBUGGER_MAX_THREADS;
  memdbg_status_t st = memdbg_debugger_get_threads(lwps, names, states, &count, MEMDBG_DEBUGGER_MAX_THREADS);
  if (st != MEMDBG_OK) return legacy_send_memdbg_status(fd, st) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0 || legacy_send_blob(fd, &count, sizeof(count)) != 0) return MEMDBG_ERR_NET;
  for (uint32_t i = 0U; i < count; ++i) {
    legacy_debug_thread_entry_t ent; memset(&ent, 0, sizeof(ent));
    ent.lwp = lwps[i]; ent.state = states[i]; legacy_copy_fixed(ent.name, sizeof(ent.name), names[i]);
    if (legacy_send_blob(fd, &ent, sizeof(ent)) != 0) return MEMDBG_ERR_NET;
  }
  return MEMDBG_OK;
}

memdbg_status_t legacy_handle_debug_suspend_thread(socket_t fd, const void *body, uint32_t body_len) {
  if (!legacy_has_body(body, body_len, sizeof(legacy_debug_thread_request_t))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  return legacy_send_memdbg_status(fd, memdbg_debugger_suspend_thread(((const legacy_debug_thread_request_t *)body)->lwp)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

memdbg_status_t legacy_handle_debug_resume_thread(socket_t fd, const void *body, uint32_t body_len) {
  if (!legacy_has_body(body, body_len, sizeof(legacy_debug_thread_request_t))) return legacy_send_status(fd, LEGACY_CMD_DATA_NULL) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  return legacy_send_memdbg_status(fd, memdbg_debugger_resume_thread(((const legacy_debug_thread_request_t *)body)->lwp)) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}
