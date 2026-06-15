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

#ifndef MEMDBG_PAL_FILEIO_H
#define MEMDBG_PAL_FILEIO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEMDBG_FILE_PERM 0666
#define MEMDBG_DIR_PERM 0777
#define MEMDBG_IO_BUFFER_SIZE (64U * 1024U)

int pal_file_open(const char *path, int flags, mode_t mode);
int pal_file_close(int fd);
int pal_file_stat(const char *path, struct stat *st);
int pal_file_fstat(int fd, struct stat *st);
ssize_t pal_file_read(int fd, void *buffer, size_t count);
ssize_t pal_file_write(int fd, const void *buffer, size_t count);
ssize_t pal_file_write_all(int fd, const void *buffer, size_t count);
ssize_t pal_file_pread_all(int fd, void *buffer, size_t count, off_t offset);
ssize_t pal_file_pwrite_all(int fd, const void *buffer, size_t count,
                            off_t offset);
ssize_t pal_sendfile(int sock_fd, int file_fd, off_t *offset, size_t count);
int pal_mkdir_p(const char *path, mode_t mode);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_PAL_FILEIO_H */
