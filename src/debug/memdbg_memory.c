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

#include "memdbg/debug/memdbg_memory.h"

#include "memdbg/pal/pal_fileio.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(__FreeBSD__)
#include <sys/ptrace.h>
#include <sys/types.h>
#endif

#if defined(__linux__)
static memdbg_status_t linux_mem_path(int pid, char *out, size_t out_size) {
  if (pid <= 0 || out == NULL || out_size == 0U) {
    return MEMDBG_ERR_PARAM;
  }
  int n = snprintf(out, out_size, "/proc/%d/mem", pid);
  if (n < 0 || (size_t)n >= out_size) {
    return MEMDBG_ERR_OVERFLOW;
  }
  return MEMDBG_OK;
}
#endif

memdbg_status_t memdbg_memory_read(int pid, uint64_t address, void *buffer,
                                   size_t length, size_t *read_out) {
  if (pid <= 0 || (buffer == NULL && length != 0U)) {
    return MEMDBG_ERR_PARAM;
  }
  if (read_out != NULL) {
    *read_out = 0U;
  }
  if (length == 0U) {
    return MEMDBG_OK;
  }

#if defined(__linux__)
  char path[64];
  memdbg_status_t st = linux_mem_path(pid, path, sizeof(path));
  if (st != MEMDBG_OK) {
    return st;
  }
  int fd = pal_file_open(path, O_RDONLY, 0);
  if (fd < 0) {
    return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  }
  ssize_t n = pal_file_pread_all(fd, buffer, length, (off_t)address);
  int saved = errno;
  (void)pal_file_close(fd);
  if (n < 0) {
    errno = saved;
    return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  }
  if (read_out != NULL) {
    *read_out = (size_t)n;
  }
  return MEMDBG_OK;

#elif defined(__FreeBSD__)
  struct ptrace_io_desc io;
  memset(&io, 0, sizeof(io));
  io.piod_op = PIOD_READ_D;
  io.piod_offs = (void *)(uintptr_t)address;
  io.piod_addr = buffer;
  io.piod_len = length;
  if (ptrace(PT_IO, pid, (caddr_t)&io, 0) != 0) {
    return errno == EACCES || errno == EPERM ? MEMDBG_ERR_PERMISSION
                                             : MEMDBG_ERR_IO;
  }
  if (read_out != NULL) {
    *read_out = length - io.piod_len;
  }
  return MEMDBG_OK;
#else
  (void)address;
  (void)buffer;
  (void)length;
  return MEMDBG_ERR_UNSUPPORTED;
#endif
}

memdbg_status_t memdbg_memory_write(int pid, uint64_t address,
                                    const void *buffer, size_t length,
                                    size_t *written_out) {
  if (pid <= 0 || (buffer == NULL && length != 0U)) {
    return MEMDBG_ERR_PARAM;
  }
  if (written_out != NULL) {
    *written_out = 0U;
  }
  if (length == 0U) {
    return MEMDBG_OK;
  }

#if defined(__linux__)
  char path[64];
  memdbg_status_t st = linux_mem_path(pid, path, sizeof(path));
  if (st != MEMDBG_OK) {
    return st;
  }
  int fd = pal_file_open(path, O_RDWR, 0);
  if (fd < 0) {
    return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  }
  ssize_t n = pal_file_pwrite_all(fd, buffer, length, (off_t)address);
  int saved = errno;
  (void)pal_file_close(fd);
  if (n < 0) {
    errno = saved;
    return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  }
  if (written_out != NULL) {
    *written_out = (size_t)n;
  }
  return MEMDBG_OK;

#elif defined(__FreeBSD__)
  struct ptrace_io_desc io;
  memset(&io, 0, sizeof(io));
  io.piod_op = PIOD_WRITE_D;
  io.piod_offs = (void *)(uintptr_t)address;
  io.piod_addr = (void *)(uintptr_t)buffer;
  io.piod_len = length;
  if (ptrace(PT_IO, pid, (caddr_t)&io, 0) != 0) {
    return errno == EACCES || errno == EPERM ? MEMDBG_ERR_PERMISSION
                                             : MEMDBG_ERR_IO;
  }
  if (written_out != NULL) {
    *written_out = length - io.piod_len;
  }
  return MEMDBG_OK;
#else
  (void)address;
  (void)buffer;
  (void)length;
  return MEMDBG_ERR_UNSUPPORTED;
#endif
}
