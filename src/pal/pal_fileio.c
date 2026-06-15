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

#include "memdbg/pal/pal_fileio.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/sendfile.h>
#elif defined(__FreeBSD__)
#include <sys/uio.h>
#endif

int pal_file_open(const char *path, int flags, mode_t mode) {
  if (path == NULL || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }
  return open(path, flags, mode);
}

int pal_file_close(int fd) {
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

int pal_file_stat(const char *path, struct stat *st) {
  if (path == NULL || st == NULL) {
    errno = EINVAL;
    return -1;
  }
  return stat(path, st);
}

int pal_file_fstat(int fd, struct stat *st) {
  if (fd < 0 || st == NULL) {
    errno = EINVAL;
    return -1;
  }
  return fstat(fd, st);
}

ssize_t pal_file_read(int fd, void *buffer, size_t count) {
  if (fd < 0 || buffer == NULL) {
    errno = EINVAL;
    return -1;
  }
  ssize_t n;
  do {
    n = read(fd, buffer, count);
  } while (n < 0 && errno == EINTR);
  return n;
}

ssize_t pal_file_write(int fd, const void *buffer, size_t count) {
  if (fd < 0 || buffer == NULL) {
    errno = EINVAL;
    return -1;
  }
  ssize_t n;
  do {
    n = write(fd, buffer, count);
  } while (n < 0 && errno == EINTR);
  return n;
}

ssize_t pal_file_write_all(int fd, const void *buffer, size_t count) {
  const unsigned char *cursor = (const unsigned char *)buffer;
  size_t total = 0U;

  if (fd < 0 || (buffer == NULL && count != 0U)) {
    errno = EINVAL;
    return -1;
  }

  while (total < count) {
    ssize_t n = pal_file_write(fd, cursor + total, count - total);
    if (n < 0) {
      return -1;
    }
    if (n == 0) {
      errno = EIO;
      return -1;
    }
    total += (size_t)n;
  }

  return (ssize_t)total;
}

ssize_t pal_file_pread_all(int fd, void *buffer, size_t count, off_t offset) {
  unsigned char *cursor = (unsigned char *)buffer;
  size_t total = 0U;

  if (fd < 0 || (buffer == NULL && count != 0U) || offset < 0) {
    errno = EINVAL;
    return -1;
  }

  while (total < count) {
    ssize_t n;
    do {
      n = pread(fd, cursor + total, count - total, offset + (off_t)total);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
      return -1;
    }
    if (n == 0) {
      errno = EIO;
      return -1;
    }
    total += (size_t)n;
  }

  return (ssize_t)total;
}

ssize_t pal_file_pwrite_all(int fd, const void *buffer, size_t count,
                            off_t offset) {
  const unsigned char *cursor = (const unsigned char *)buffer;
  size_t total = 0U;

  if (fd < 0 || (buffer == NULL && count != 0U) || offset < 0) {
    errno = EINVAL;
    return -1;
  }

  while (total < count) {
    ssize_t n;
    do {
      n = pwrite(fd, cursor + total, count - total, offset + (off_t)total);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
      return -1;
    }
    if (n == 0) {
      errno = EIO;
      return -1;
    }
    total += (size_t)n;
  }

  return (ssize_t)total;
}

static ssize_t pal_sendfile_buffered(int sock_fd, int file_fd, off_t *offset,
                                     size_t count) {
  unsigned char *buffer = (unsigned char *)malloc(MEMDBG_IO_BUFFER_SIZE);
  size_t total = 0U;

  if (buffer == NULL) {
    errno = ENOMEM;
    return -1;
  }

  while (total < count) {
    size_t chunk = count - total;
    if (chunk > MEMDBG_IO_BUFFER_SIZE) {
      chunk = MEMDBG_IO_BUFFER_SIZE;
    }

    ssize_t nr = pread(file_fd, buffer, chunk, *offset);
    if (nr < 0) {
      if (errno == EINTR) {
        continue;
      }
      free(buffer);
      return -1;
    }
    if (nr == 0) {
      break;
    }

    size_t written = 0U;
    while (written < (size_t)nr) {
#ifdef MSG_NOSIGNAL
      ssize_t nw = send(sock_fd, buffer + written, (size_t)nr - written,
                        MSG_NOSIGNAL);
#else
      ssize_t nw = send(sock_fd, buffer + written, (size_t)nr - written, 0);
#endif
      if (nw < 0) {
        if (errno == EINTR) {
          continue;
        }
        free(buffer);
        return -1;
      }
      if (nw == 0) {
        errno = EPIPE;
        free(buffer);
        return -1;
      }
      written += (size_t)nw;
    }

    *offset += nr;
    total += (size_t)nr;
  }

  free(buffer);
  return (ssize_t)total;
}

ssize_t pal_sendfile(int sock_fd, int file_fd, off_t *offset, size_t count) {
  if (sock_fd < 0 || file_fd < 0 || offset == NULL || *offset < 0) {
    errno = EINVAL;
    return -1;
  }
  if (count == 0U) {
    return 0;
  }

#if defined(__linux__)
  {
    off_t local_off = *offset;
    ssize_t n;
    do {
      n = sendfile(sock_fd, file_fd, &local_off, count);
    } while (n < 0 && errno == EINTR);
    if (n >= 0) {
      *offset = local_off;
      return n;
    }
    if (errno != EINVAL && errno != ENOSYS) {
      return -1;
    }
  }
#elif defined(__FreeBSD__)
  {
    off_t sent = 0;
    int rc;
    do {
      rc = sendfile(file_fd, sock_fd, *offset, count, NULL, &sent, 0);
    } while (rc < 0 && errno == EINTR);
    if (rc == 0 || (rc < 0 && errno == EAGAIN && sent > 0)) {
      *offset += sent;
      return (ssize_t)sent;
    }
    if (sent > 0) {
      *offset += sent;
      return (ssize_t)sent;
    }
    if (errno != EINVAL && errno != ENOSYS) {
      return -1;
    }
  }
#endif

  return pal_sendfile_buffered(sock_fd, file_fd, offset, count);
}

int pal_mkdir_p(const char *path, mode_t mode) {
  char tmp[512];
  size_t len;

  if (path == NULL || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  len = strlen(path);
  if (len >= sizeof(tmp)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  memcpy(tmp, path, len + 1U);
  while (len > 1U && tmp[len - 1U] == '/') {
    tmp[--len] = '\0';
  }

  for (char *p = tmp + 1; *p != '\0'; ++p) {
    if (*p != '/') {
      continue;
    }
    *p = '\0';
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
      *p = '/';
      return -1;
    }
    *p = '/';
  }

  if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}
