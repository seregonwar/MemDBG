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

#include "memdbg/pal/pal_network.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

int pal_network_init(void) { return 0; }

void pal_network_fini(void) {}

int pal_socket_close(socket_t fd) {
  if (fd < 0) {
    errno = EBADF;
    return -1;
  }
  int rc;
  do {
    rc = close(fd);
  } while (rc < 0 && errno == EINTR);
  return rc;
}

int pal_socket_set_nonblocking(socket_t fd, bool enabled) {
  int flags;
  if (fd < 0) {
    errno = EBADF;
    return -1;
  }
  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  if (enabled) {
    flags |= O_NONBLOCK;
  } else {
    flags &= ~O_NONBLOCK;
  }
  return fcntl(fd, F_SETFL, flags);
}

int pal_socket_set_timeouts(socket_t fd, uint32_t recv_ms, uint32_t send_ms) {
  if (fd < 0) {
    errno = EBADF;
    return -1;
  }

  struct timeval tv;
  tv.tv_sec = (time_t)(recv_ms / 1000U);
  tv.tv_usec = (suseconds_t)((recv_ms % 1000U) * 1000U);
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
    return -1;
  }

  tv.tv_sec = (time_t)(send_ms / 1000U);
  tv.tv_usec = (suseconds_t)((send_ms % 1000U) * 1000U);
  return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int pal_socket_configure(socket_t fd) {
  if (fd < 0) {
    errno = EBADF;
    return -1;
  }

  int one = 1;
  (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
  (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  /* Default send buffer: 256KB for bulk transfer throughput (matches zftpd). */
  (void)pal_socket_set_sndbuf(fd, 262144);
  return 0;
}

int pal_tcp_listen(const char *bind_host, uint16_t port, int backlog,
                   socket_t *out_fd) {
  socket_t fd;
  struct sockaddr_in addr;
  int one = 1;

  if (out_fd == NULL || port == 0U) {
    errno = EINVAL;
    return -1;
  }
  *out_fd = PAL_INVALID_SOCKET;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }

  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (bind_host == NULL || bind_host[0] == '\0' ||
      strcmp(bind_host, "0.0.0.0") == 0 || strcmp(bind_host, "*") == 0) {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  } else if (inet_pton(AF_INET, bind_host, &addr.sin_addr) != 1) {
    (void)pal_socket_close(fd);
    errno = EINVAL;
    return -1;
  }

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int saved = errno;
    (void)pal_socket_close(fd);
    errno = saved;
    return -1;
  }
  if (listen(fd, backlog) != 0) {
    int saved = errno;
    (void)pal_socket_close(fd);
    errno = saved;
    return -1;
  }
  if (pal_socket_set_nonblocking(fd, true) != 0) {
    int saved = errno;
    (void)pal_socket_close(fd);
    errno = saved;
    return -1;
  }

  *out_fd = fd;
  return 0;
}

int pal_tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms,
                    socket_t *out_fd) {
  socket_t fd;
  struct sockaddr_in addr;
  int rc;
  int saved;

  if (out_fd == NULL || host == NULL || host[0] == '\0' || port == 0U) {
    errno = EINVAL;
    return -1;
  }
  *out_fd = PAL_INVALID_SOCKET;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
    (void)pal_socket_close(fd);
    errno = EINVAL;
    return -1;
  }

  if (timeout_ms == 0U) {
    timeout_ms = 3000U;
  }

  if (pal_socket_set_nonblocking(fd, true) != 0) {
    saved = errno;
    (void)pal_socket_close(fd);
    errno = saved;
    return -1;
  }

  rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (rc != 0 && errno == EINPROGRESS) {
    fd_set wfds;
    struct timeval tv;

    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    tv.tv_sec = (time_t)(timeout_ms / 1000U);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000U) * 1000U);

    do {
      rc = select(fd + 1, NULL, &wfds, NULL, &tv);
    } while (rc < 0 && errno == EINTR);

    if (rc > 0) {
      int err = 0;
      socklen_t err_len = (socklen_t)sizeof(err);
      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) != 0) {
        rc = -1;
      } else if (err != 0) {
        errno = err;
        rc = -1;
      } else {
        rc = 0;
      }
    } else if (rc == 0) {
      errno = ETIMEDOUT;
      rc = -1;
    }
  }

  if (rc != 0) {
    saved = errno;
    (void)pal_socket_close(fd);
    errno = saved;
    return -1;
  }

  if (pal_socket_set_nonblocking(fd, false) != 0) {
    saved = errno;
    (void)pal_socket_close(fd);
    errno = saved;
    return -1;
  }
  (void)pal_socket_configure(fd);
  (void)pal_socket_set_timeouts(fd, timeout_ms, timeout_ms);

  *out_fd = fd;
  return 0;
}

ssize_t pal_socket_read_exact(socket_t fd, void *buffer, size_t count) {
  unsigned char *cursor = (unsigned char *)buffer;
  size_t total = 0U;

  if (fd < 0 || (buffer == NULL && count != 0U)) {
    errno = EINVAL;
    return -1;
  }

  while (total < count) {
    ssize_t n = recv(fd, cursor + total, count - total, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (n == 0) {
      errno = ECONNRESET;
      return -1;
    }
    total += (size_t)n;
  }

  return (ssize_t)total;
}

ssize_t pal_socket_write_all(socket_t fd, const void *buffer, size_t count) {
  const unsigned char *cursor = (const unsigned char *)buffer;
  size_t total = 0U;

  if (fd < 0 || (buffer == NULL && count != 0U)) {
    errno = EINVAL;
    return -1;
  }

  while (total < count) {
#ifdef MSG_NOSIGNAL
    ssize_t n = send(fd, cursor + total, count - total, MSG_NOSIGNAL);
#else
    ssize_t n = send(fd, cursor + total, count - total, 0);
#endif
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (n == 0) {
      errno = EPIPE;
      return -1;
    }
    total += (size_t)n;
  }

  return (ssize_t)total;
}

const char *pal_socket_last_error(void) { return strerror(errno); }

/* ---- Zero-copy scatter-gather write using writev() ---- */

static ssize_t pal_socket_writev_n(socket_t fd, struct iovec *iov, int count) {
  size_t total = 0U;
  size_t written = 0U;

  if (fd < 0 || iov == NULL || count <= 0 || count > 3) {
    errno = EINVAL;
    return -1;
  }
  for (int i = 0; i < count; ++i) {
    if (iov[i].iov_len != 0U && iov[i].iov_base == NULL) {
      errno = EINVAL;
      return -1;
    }
    if (iov[i].iov_len > SIZE_MAX - total) {
      errno = EOVERFLOW;
      return -1;
    }
    total += iov[i].iov_len;
  }
  if (total == 0U) {
    errno = EINVAL;
    return -1;
  }

  while (written < total) {
    struct iovec cur[3];
    int iovcnt = 0;
    for (int i = 0; i < count; ++i)
      if (iov[i].iov_len > 0U) cur[iovcnt++] = iov[i];

    if (iovcnt == 0) break;

    ssize_t n = writev(fd, cur, iovcnt);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (n == 0) {
      errno = EPIPE;
      return -1;
    }

    written += (size_t)n;

    size_t remain = (size_t)n;
    for (int i = 0; i < count && remain > 0U; ++i) {
      if (iov[i].iov_len <= remain) {
        remain -= iov[i].iov_len;
        iov[i].iov_len = 0U;
      } else {
        iov[i].iov_base = (uint8_t *)iov[i].iov_base + remain;
        iov[i].iov_len -= remain;
        remain = 0U;
      }
    }
  }

  return (ssize_t)total;
}

ssize_t pal_socket_writev_all(socket_t fd,
                              const void *iov0, size_t iov0_len,
                              const void *iov1, size_t iov1_len) {
  struct iovec iov[2] = {{(void *)iov0, iov0_len},
                         {(void *)iov1, iov1_len}};
  return pal_socket_writev_n(fd, iov, 2);
}

ssize_t pal_socket_writev3_all(socket_t fd,
                               const void *iov0, size_t iov0_len,
                               const void *iov1, size_t iov1_len,
                               const void *iov2, size_t iov2_len) {
  struct iovec iov[3] = {{(void *)iov0, iov0_len},
                         {(void *)iov1, iov1_len},
                         {(void *)iov2, iov2_len}};
  return pal_socket_writev_n(fd, iov, 3);
}

/* ---- TCP_CORK / TCP_NOPUSH for batch-write efficiency ---- */

int pal_socket_set_cork(socket_t fd, bool enabled) {
  if (fd < 0) { errno = EBADF; return -1; }

#if defined(__linux__)
  int val = enabled ? 1 : 0;
  return setsockopt(fd, IPPROTO_TCP, TCP_CORK, &val, sizeof(val));
#elif defined(TCP_NOPUSH)
  /* FreeBSD / PS4 / PS5 / macOS */
  int val = enabled ? 1 : 0;
  return setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, &val, sizeof(val));
#else
  (void)enabled;
  return 0; /* unsupported — no-op */
#endif
}

/* ---- SO_SNDBUF tuning for bulk transfers ---- */

int pal_socket_set_sndbuf(socket_t fd, int bytes) {
  if (fd < 0) { errno = EBADF; return -1; }
  return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
}
