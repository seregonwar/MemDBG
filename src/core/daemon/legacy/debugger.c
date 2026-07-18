/*
 * memDBG - ps5debug compat: debugger bridge.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "internal.h"
#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/pal/pal_time.h"

#include <errno.h>
#include <signal.h>

legacy_debugger_session_t g_debugger;
pthread_mutex_t g_debugger_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint64_t g_legacy_breakpoints[30];
static uint64_t g_legacy_watchpoints[4];

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
  if (g_debugger.intr_fd == PAL_INVALID_SOCKET) return -1;
  uint8_t packet[1184];
  memset(packet, 0, sizeof(packet));
  memcpy(packet, &lwp, sizeof(lwp));

  int32_t lwps[MEMDBG_DEBUGGER_MAX_THREADS];
  char names[MEMDBG_DEBUGGER_MAX_THREADS][24];
  uint32_t count = MEMDBG_DEBUGGER_MAX_THREADS;
  if (memdbg_debugger_get_threads(lwps, names, NULL, &count,
                                  MEMDBG_DEBUGGER_MAX_THREADS) == MEMDBG_OK) {
    for (uint32_t i = 0U; i < count; ++i) {
      if (lwps[i] == lwp) {
        legacy_copy_fixed((char *)packet + 8U, 40U, names[i]);
        break;
      }
    }
  }

  memdbg_debug_regs_t regs;
  memdbg_debug_fpregs_t fpregs;
  memdbg_debug_dbregs_t dbregs;
  memset(&regs, 0, sizeof(regs));
  memset(&fpregs, 0, sizeof(fpregs));
  memset(&dbregs, 0, sizeof(dbregs));
  (void)memdbg_debugger_get_regs(lwp, &regs);
  (void)memdbg_debugger_get_fpregs(lwp, &fpregs);
  (void)memdbg_debugger_get_dbregs(lwp, &dbregs);
  memcpy(packet + 0x30U, &regs, sizeof(regs));
  memcpy(packet + 0xE0U, fpregs.data,
         fpregs.length < 832U ? fpregs.length : 832U);
  memcpy(packet + 0x420U, &dbregs, sizeof(dbregs));
  return pal_socket_write_all(g_debugger.intr_fd, packet, sizeof(packet)) < 0
             ? -1 : 0;
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
  if (memdbg_debugger_is_attached())
    return legacy_send_status(fd, LEGACY_CMD_ALREADY_DEBUG) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
  debugger_session_init();
  memset(g_legacy_breakpoints, 0, sizeof(g_legacy_breakpoints));
  memset(g_legacy_watchpoints, 0, sizeof(g_legacy_watchpoints));
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

typedef struct legacy_debug_indexed_breakpoint {
  uint32_t index;
  uint32_t enabled;
  uint64_t address;
} LEGACY_PACKED legacy_debug_indexed_breakpoint_t;

typedef struct legacy_debug_indexed_watchpoint {
  uint32_t index;
  uint32_t enabled;
  uint32_t length;
  uint32_t break_type;
  uint64_t address;
} LEGACY_PACKED legacy_debug_indexed_watchpoint_t;

typedef struct legacy_debug_blob_request {
  uint32_t lwp;
  uint32_t length;
} LEGACY_PACKED legacy_debug_blob_request_t;

typedef struct legacy_debug_thread_info {
  uint32_t lwp;
  uint32_t priority;
  char name[32];
} LEGACY_PACKED legacy_debug_thread_info_t;

static memdbg_status_t legacy_debug_send_result(socket_t fd,
                                                 memdbg_status_t status) {
  return legacy_send_memdbg_status(fd, status) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
}

static memdbg_status_t legacy_debug_get_blob(socket_t fd, uint32_t command,
                                             int32_t lwp) {
  memdbg_status_t st;
  if (command == LEGACY_CMD_DEBUG_GET_REGS) {
    memdbg_debug_regs_t regs;
    st = memdbg_debugger_get_regs(lwp, &regs);
    return st == MEMDBG_OK && legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 &&
                   legacy_send_blob(fd, &regs, sizeof(regs)) == 0
               ? MEMDBG_OK : (st == MEMDBG_OK ? MEMDBG_ERR_NET
                                               : legacy_debug_send_result(fd, st));
  }
  if (command == LEGACY_CMD_DEBUG_GET_DBREGS) {
    memdbg_debug_dbregs_t regs;
    st = memdbg_debugger_get_dbregs(lwp, &regs);
    return st == MEMDBG_OK && legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 &&
                   legacy_send_blob(fd, &regs, sizeof(regs)) == 0
               ? MEMDBG_OK : (st == MEMDBG_OK ? MEMDBG_ERR_NET
                                               : legacy_debug_send_result(fd, st));
  }
  if (command == LEGACY_CMD_DEBUG_GET_FPREGS) {
    memdbg_debug_fpregs_t regs;
    uint8_t wire[832];
    memset(&regs, 0, sizeof(regs));
    memset(wire, 0, sizeof(wire));
    st = memdbg_debugger_get_fpregs(lwp, &regs);
    if (st == MEMDBG_OK)
      memcpy(wire, regs.data, regs.length < sizeof(wire) ? regs.length : sizeof(wire));
    return st == MEMDBG_OK && legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 &&
                   legacy_send_blob(fd, wire, sizeof(wire)) == 0
               ? MEMDBG_OK : (st == MEMDBG_OK ? MEMDBG_ERR_NET
                                               : legacy_debug_send_result(fd, st));
  }
  if (command == LEGACY_CMD_DEBUG_GET_FSGSBASE) {
    memdbg_debug_fsgsbase_t base;
    st = memdbg_debugger_get_fsgsbase(lwp, &base);
    return st == MEMDBG_OK && legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 &&
                   legacy_send_blob(fd, &base, sizeof(base)) == 0
               ? MEMDBG_OK : (st == MEMDBG_OK ? MEMDBG_ERR_NET
                                               : legacy_debug_send_result(fd, st));
  }
  return legacy_debug_send_result(fd, MEMDBG_ERR_UNSUPPORTED);
}

static memdbg_status_t legacy_debug_set_blob(socket_t fd, uint32_t command,
                                             const legacy_debug_blob_request_t *req) {
  uint32_t expected = 0U;
  if (command == LEGACY_CMD_DEBUG_SET_REGS) expected = (uint32_t)sizeof(memdbg_debug_regs_t);
  else if (command == LEGACY_CMD_DEBUG_SET_DBREGS) expected = (uint32_t)sizeof(memdbg_debug_dbregs_t);
  else if (command == LEGACY_CMD_DEBUG_SET_FPREGS) {
    if (req->length != 512U && req->length != 832U)
      return legacy_debug_send_result(fd, MEMDBG_ERR_PARAM);
    expected = req->length;
  } else if (command == LEGACY_CMD_DEBUG_SET_FSGSBASE) {
    expected = (uint32_t)sizeof(memdbg_debug_fsgsbase_t);
  }
  if (expected == 0U || req->length != expected)
    return legacy_debug_send_result(fd, MEMDBG_ERR_PARAM);

  uint8_t *blob = (uint8_t *)malloc(expected);
  if (blob == NULL) return legacy_debug_send_result(fd, MEMDBG_ERR_NOMEM);
  if (legacy_send_status(fd, LEGACY_CMD_SUCCESS) != 0) { free(blob); return MEMDBG_ERR_NET; }
  if (pal_socket_read_exact(fd, blob, expected) < 0) { free(blob); return MEMDBG_ERR_NET; }

  memdbg_status_t st = MEMDBG_ERR_UNSUPPORTED;
  if (command == LEGACY_CMD_DEBUG_SET_REGS)
    st = memdbg_debugger_set_regs((int32_t)req->lwp,
                                  (const memdbg_debug_regs_t *)blob);
  else if (command == LEGACY_CMD_DEBUG_SET_DBREGS)
    st = memdbg_debugger_set_dbregs((int32_t)req->lwp,
                                    (const memdbg_debug_dbregs_t *)blob);
  else if (command == LEGACY_CMD_DEBUG_SET_FSGSBASE)
    st = memdbg_debugger_set_fsgsbase((int32_t)req->lwp,
                                      (const memdbg_debug_fsgsbase_t *)blob);
  else {
    memdbg_debug_fpregs_t regs;
    memset(&regs, 0, sizeof(regs));
    regs.length = expected;
    memcpy(regs.data, blob, expected);
    st = memdbg_debugger_set_fpregs((int32_t)req->lwp, &regs);
  }
  free(blob);
  return legacy_debug_send_result(fd, st);
}

memdbg_status_t legacy_handle_debug_command(socket_t fd, uint32_t command,
                                            const void *body,
                                            uint32_t body_len) {
  if (command == LEGACY_CMD_DEBUG_DETACH) return legacy_handle_debug_detach(fd);

  if (command == LEGACY_CMD_DEBUG_GET_THREADS) {
    int32_t lwps[MEMDBG_DEBUGGER_MAX_THREADS];
    uint32_t count = MEMDBG_DEBUGGER_MAX_THREADS;
    memdbg_status_t st = memdbg_debugger_get_threads(
        lwps, NULL, NULL, &count, MEMDBG_DEBUGGER_MAX_THREADS);
    if (st != MEMDBG_OK) return legacy_debug_send_result(fd, st);
    return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 &&
                   legacy_send_blob(fd, &count, sizeof(count)) == 0 &&
                   legacy_send_blob(fd, lwps, (size_t)count * sizeof(lwps[0])) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }

  if (command == LEGACY_CMD_DEBUG_STEP) {
    int32_t lwp = memdbg_debugger_get_stop_lwp();
    if (lwp <= 0) lwp = memdbg_debugger_attached_pid();
    return legacy_debug_send_result(fd, memdbg_debugger_step(lwp));
  }

  if (command == LEGACY_CMD_DEBUG_SET_BP) {
    if (!legacy_has_body(body, body_len, sizeof(legacy_debug_indexed_breakpoint_t)))
      return legacy_debug_send_result(fd, MEMDBG_ERR_PARAM);
    const legacy_debug_indexed_breakpoint_t *req =
        (const legacy_debug_indexed_breakpoint_t *)body;
    if (req->index >= 30U)
      return legacy_send_status(fd, LEGACY_CMD_INVALID_INDEX) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
    memdbg_status_t st;
    if (req->enabled != 0U) {
      st = memdbg_debugger_set_breakpoint(req->address, MEMDBG_BP_SOFTWARE);
      if (st == MEMDBG_OK) g_legacy_breakpoints[req->index] = req->address;
    } else {
      uint64_t address = g_legacy_breakpoints[req->index];
      st = address != 0U ? memdbg_debugger_clear_breakpoint(address) : MEMDBG_OK;
      if (st == MEMDBG_OK) g_legacy_breakpoints[req->index] = 0U;
    }
    return legacy_debug_send_result(fd, st);
  }

  if (command == LEGACY_CMD_DEBUG_SET_WP) {
    if (!legacy_has_body(body, body_len, sizeof(legacy_debug_indexed_watchpoint_t)))
      return legacy_debug_send_result(fd, MEMDBG_ERR_PARAM);
    const legacy_debug_indexed_watchpoint_t *req =
        (const legacy_debug_indexed_watchpoint_t *)body;
    if (req->index >= 4U)
      return legacy_send_status(fd, LEGACY_CMD_INVALID_INDEX) == 0 ? MEMDBG_OK : MEMDBG_ERR_NET;
    static const uint32_t lengths[4] = {1U, 2U, 8U, 4U};
    memdbg_status_t st;
    if (req->enabled != 0U) {
      uint32_t type = req->break_type == 0U ? 0U :
                      req->break_type == 1U ? 1U : 3U;
      st = memdbg_debugger_set_watchpoint(req->address,
                                          lengths[req->length & 3U], type);
      if (st == MEMDBG_OK) g_legacy_watchpoints[req->index] = req->address;
    } else {
      uint64_t address = g_legacy_watchpoints[req->index];
      st = address != 0U ? memdbg_debugger_clear_watchpoint(address) : MEMDBG_OK;
      if (st == MEMDBG_OK) g_legacy_watchpoints[req->index] = 0U;
    }
    return legacy_debug_send_result(fd, st);
  }

  if (command == LEGACY_CMD_DEBUG_CONTINUE) {
    if (!legacy_has_body(body, body_len, sizeof(uint32_t)))
      return legacy_debug_send_result(fd, MEMDBG_ERR_PARAM);
    uint32_t action = *(const uint32_t *)body;
    if (action == 0U) return legacy_debug_send_result(fd, memdbg_debugger_continue());
    if (action == 1U) return legacy_debug_send_result(fd, memdbg_debugger_stop());
    if (action == 2U) {
      int32_t pid = memdbg_debugger_attached_pid();
      return legacy_debug_send_result(fd,
          pid > 0 && kill((pid_t)pid, SIGKILL) == 0 ? MEMDBG_OK : MEMDBG_ERR_IO);
    }
    return legacy_debug_send_result(fd, MEMDBG_ERR_PARAM);
  }

  if (command == LEGACY_CMD_DEBUG_PROCESS_STOP) {
    if (body == NULL || body_len != 5U) return legacy_debug_send_result(fd, MEMDBG_ERR_PARAM);
    uint32_t pid; memcpy(&pid, body, sizeof(pid));
    uint8_t action = ((const uint8_t *)body)[4];
    static const int signals[3] = {SIGCONT, SIGSTOP, SIGKILL};
    if (pid == 0U || action > 2U) return legacy_debug_send_result(fd, MEMDBG_ERR_PARAM);
    return legacy_debug_send_result(fd,
        kill((pid_t)pid, signals[action]) == 0 ? MEMDBG_OK : MEMDBG_ERR_IO);
  }

  if (!legacy_has_body(body, body_len, sizeof(uint32_t)))
    return legacy_debug_send_result(fd, MEMDBG_ERR_PARAM);
  int32_t lwp = (int32_t)*(const uint32_t *)body;

  if (command == LEGACY_CMD_DEBUG_GET_REGS ||
      command == LEGACY_CMD_DEBUG_GET_FPREGS ||
      command == LEGACY_CMD_DEBUG_GET_DBREGS ||
      command == LEGACY_CMD_DEBUG_GET_FSGSBASE)
    return legacy_debug_get_blob(fd, command, lwp);

  if (command == LEGACY_CMD_DEBUG_SET_REGS ||
      command == LEGACY_CMD_DEBUG_SET_FPREGS ||
      command == LEGACY_CMD_DEBUG_SET_DBREGS ||
      command == LEGACY_CMD_DEBUG_SET_FSGSBASE) {
    if (!legacy_has_body(body, body_len, sizeof(legacy_debug_blob_request_t)))
      return legacy_debug_send_result(fd, MEMDBG_ERR_PARAM);
    return legacy_debug_set_blob(fd, command,
        (const legacy_debug_blob_request_t *)body);
  }

  if (command == LEGACY_CMD_DEBUG_SUSPEND_TID)
    return legacy_debug_send_result(fd, memdbg_debugger_suspend_thread(lwp));
  if (command == LEGACY_CMD_DEBUG_RESUME_TID)
    return legacy_debug_send_result(fd, memdbg_debugger_resume_thread(lwp));
  if (command == LEGACY_CMD_DEBUG_STEP_THREAD)
    return legacy_debug_send_result(fd, memdbg_debugger_step(lwp));
  if (command == LEGACY_CMD_DEBUG_THREAD_INFO) {
    int32_t lwps[MEMDBG_DEBUGGER_MAX_THREADS];
    char names[MEMDBG_DEBUGGER_MAX_THREADS][24];
    uint32_t count = MEMDBG_DEBUGGER_MAX_THREADS;
    legacy_debug_thread_info_t info;
    memset(&info, 0, sizeof(info));
    info.lwp = (uint32_t)lwp;
    memdbg_status_t st = memdbg_debugger_get_threads(
        lwps, names, NULL, &count, MEMDBG_DEBUGGER_MAX_THREADS);
    if (st != MEMDBG_OK) return legacy_debug_send_result(fd, st);
    for (uint32_t i = 0U; i < count; ++i)
      if (lwps[i] == lwp) { legacy_copy_fixed(info.name, sizeof(info.name), names[i]); break; }
    return legacy_send_status(fd, LEGACY_CMD_SUCCESS) == 0 &&
                   legacy_send_blob(fd, &info, sizeof(info)) == 0
               ? MEMDBG_OK : MEMDBG_ERR_NET;
  }
  return legacy_debug_send_result(fd, MEMDBG_ERR_UNSUPPORTED);
}
