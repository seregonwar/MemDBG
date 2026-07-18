/*
 * memDBG - Portable I/O wait primitive (epoll/kqueue/select abstraction).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/pal/pal_wait.h"

#include <errno.h>
#include <sys/select.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/epoll.h>
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif
#elif defined(__FreeBSD__) || defined(__APPLE__)
#include <sys/event.h>
#endif

int wait_for_client(socket_t fd, int timeout_ms) {
#if defined(__linux__)
  /* Use epoll for near-zero-latency polling. */
  int epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) goto fallback_select;

  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLRDHUP;
  ev.data.fd = fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
    close(epfd);
    goto fallback_select;
  }

  struct epoll_event events[1];
  int rc = epoll_wait(epfd, events, 1, timeout_ms);
  close(epfd);

  if (rc > 0) {
    if (events[0].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) return -1;
    return (events[0].events & EPOLLIN) ? 1 : 0;
  }
  return rc; /* 0 = timeout, <0 = error */

#elif defined(__FreeBSD__) || defined(__APPLE__)
  /* Use kqueue for precise polling. */
  int kq = kqueue();
  if (kq < 0) goto fallback_select;

  struct kevent ev;
  EV_SET(&ev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

  struct timespec ts;
  struct timespec *tsp = NULL;
  if (timeout_ms >= 0) {
    ts.tv_sec  = timeout_ms / 1000;
    ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
    tsp = &ts;
  }

  int rc = kevent(kq, &ev, 1, &ev, 1, tsp);
  close(kq);

  if (rc > 0) {
    if (ev.flags & (EV_ERROR | EV_EOF)) return -1;
    return (ev.filter == EVFILT_READ) ? 1 : 0;
  }
  return rc; /* 0 = timeout, <0 = error */
#elif defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__) || \
      defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
  /* The console kqueue implementations are not equivalent to desktop
   * FreeBSD for this short-lived usage.  Creating and closing a kqueue on
   * every accept poll can eventually stop delivering listener events.
   * select() is reliable here and the daemon only watches one descriptor. */
  goto fallback_select;
#endif

fallback_select:
  {
    /* Guard against fd out of range for select().
     * macOS/FreeBSD assert at runtime if fd >= FD_SETSIZE. */
    if (fd < 0 || (unsigned int)fd >= FD_SETSIZE) return -1;

    fd_set rfds;
    struct timeval tv;
    struct timeval *tvp = NULL;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    if (timeout_ms >= 0) {
      tv.tv_sec  = timeout_ms / 1000;
      tv.tv_usec = (timeout_ms % 1000) * 1000;
      tvp = &tv;
    }
    /* Let the caller retry EINTR with freshly initialized fd_set/timeval;
     * select is allowed to mutate both arguments on interruption. */
    int fsrc = select(fd + 1, &rfds, NULL, NULL, tvp);
    if (fsrc <= 0) return fsrc;
    return FD_ISSET(fd, &rfds) ? 1 : 0;
  }
}
