/*
 * MemDBG - ShellUI IPC client v2 (persistent connection, async).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "shellui_internal.h"
#include "shellui_monoutils.h"

#ifdef PLATFORM_PS5
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <errno.h>
#include <stdio.h>
#include <string.h>
#endif

/* ---- Persistent IPC state ---- */
shellui_ipc_state_t g_ipc = { -1, false, 0 };

/* ---- One-shot connect (for backward compat / testing) ---- */
int shellui_ipc_connect(void) {
#ifdef PLATFORM_PS5
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct sockaddr_in addr = { 0 };
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(SHELLUI_IPC_PORT);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(fd);
    return -1;
  }
  return fd;
#else
  (void)errno;
  return 42; /* mock */
#endif
}

void shellui_ipc_disconnect(int fd) {
  if (fd < 0) return;
#ifdef PLATFORM_PS5
  close(fd);
#else
  if (fd == g_ipc.fd || fd == 42) g_ipc.fd = -1;
  (void)fd;
#endif
}

/* ---- One-shot send (for backward compat) ---- */
bool shellui_ipc_send(int fd, const shellui_ipc_request_t *req,
                      shellui_ipc_response_t *resp) {
  if (fd < 0 || !req) return false;
#ifdef PLATFORM_PS5
  ssize_t n = send(fd, req, sizeof(*req), 0);
  if (n != (ssize_t)sizeof(*req)) return false;
  if (resp) {
    n = recv(fd, resp, sizeof(*resp), 0);
    if (n != (ssize_t)sizeof(*resp)) {
      memset(resp, 0, sizeof(*resp));
      resp->result = -EBADF;
    }
  }
  return true;
#else
  if (resp) {
    resp->command = req->command;
    resp->result  = 0;
    resp->value   = req->value;
  }
  return true;
#endif
}

/* ---- Persistent connection management ---- */

bool shellui_ipc_is_alive(void) {
  return g_ipc.connected && g_ipc.fd >= 0;
}

/* Fire-and-forget: send without waiting for a response */
bool shellui_ipc_fire(const shellui_ipc_request_t *req) {
  if (!req) return false;

  /* Lazy-connect on first use */
  if (!g_ipc.connected) {
    g_ipc.fd = shellui_ipc_connect();
    if (g_ipc.fd < 0) return false;
    g_ipc.connected = true;
  }

#ifdef PLATFORM_PS5
  ssize_t n = send(g_ipc.fd, req, sizeof(*req), MSG_NOSIGNAL);
  if (n != (ssize_t)sizeof(*req)) {
    /* Connection lost — mark disconnected for reconnect next time */
    close(g_ipc.fd);
    g_ipc.fd = -1;
    g_ipc.connected = false;
    return false;
  }
  return true;
#else
  (void)req;
  return true;
#endif
}

/* Poll daemon: send GET_STATUS and read response (blocking).
 * TODO: respect timeout_ms via setsockopt(SO_RCVTIMEO). */
bool shellui_ipc_poll(shellui_ipc_response_t *resp, int timeout_ms) {
  (void)timeout_ms;
  shellui_ipc_request_t req = { SHIPC_GET_STATUS, 0, { 0, 0 } };
  return shellui_ipc_send(shellui_ipc_connect(), &req, resp);
}
