/*
 * memDBG - Memory debugger payload for jailbroken consoles.
 * Copyright (C) 2026 SeregonWar
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_PAL_NETWORK_H
#define MEMDBG_PAL_NETWORK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Platform auto-detection (used by all PAL modules). */
#if defined(PLATFORM_PS4) || defined(__ORBIS__) || defined(PS4)
#  define MEMDBG_PAL_PLATFORM_PS4 1
#elif defined(PLATFORM_PS5) || defined(__PROSPERO__) || defined(PS5)
#  define MEMDBG_PAL_PLATFORM_PS5 1
#elif defined(__linux__)
#  define MEMDBG_PAL_PLATFORM_LINUX 1
#elif defined(__APPLE__)
#  define MEMDBG_PAL_PLATFORM_MACOS 1
#elif defined(__FreeBSD__)
#  define MEMDBG_PAL_PLATFORM_FREEBSD 1
#endif

typedef int socket_t;

#define PAL_INVALID_SOCKET (-1)

int pal_network_init(void);
void pal_network_fini(void);
int pal_socket_close(socket_t fd);
int pal_socket_configure(socket_t fd);
int pal_socket_set_nonblocking(socket_t fd, bool enabled);
int pal_socket_set_timeouts(socket_t fd, uint32_t recv_ms, uint32_t send_ms);
int pal_tcp_listen(const char *bind_host, uint16_t port, int backlog,
                   socket_t *out_fd);
int pal_tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms,
                    socket_t *out_fd);
ssize_t pal_socket_read_exact(socket_t fd, void *buffer, size_t count);
ssize_t pal_socket_write_all(socket_t fd, const void *buffer, size_t count);

/* Zero-copy scatter-gather write: sends header+payload in one syscall.
 * Uses writev() under the hood. Returns total bytes written or -1 on error. */
ssize_t pal_socket_writev_all(socket_t fd,
                              const void *iov0, size_t iov0_len,
                              const void *iov1, size_t iov1_len);

/* Enable/disable TCP_CORK (Linux) or TCP_NOPUSH (FreeBSD/PS4/PS5).
 * When corked, the kernel delays sending until the buffer is full or
 * cork is disabled — reducing packet count for small writes. */
int pal_socket_set_cork(socket_t fd, bool enabled);

/* Set send buffer size (SO_SNDBUF). Larger buffers improve throughput
 * for bulk transfers by reducing TCP stalls. */
int pal_socket_set_sndbuf(socket_t fd, int bytes);
const char *pal_socket_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PAL_NETWORK_H */
