/*
 * memDBG - PAL: Cross-platform memory access dispatcher.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Platform dispatch:
 *   __ORBIS__        -> PS4  (pal_memory_console.c)
 *   __PROSPERO__     -> PS5  (pal_memory_console.c)
 *   __linux__        -> Host (pal_memory_linux.c)
 *   __FreeBSD__      -> Host (this file, ptrace PT_IO)
 *   __APPLE__        -> Host (this file, stub for now)
 *   default          -> MEMDBG_ERR_UNSUPPORTED (this file)
 *
 * Linux and console backends were split out in July 2026 to keep each
 * platform implementation self-contained and testable independently.
 */

#include "pal_memory_internal.h"

/* ========================================================================
 *  Linux  —  /proc/pid/mem  (pal_memory_linux.c)
 * ======================================================================== */
#if defined(__linux__)
/* Implementations live in pal_memory_linux.c for clarity. */

/* ========================================================================
 *  FreeBSD  —  ptrace(PT_IO)
 * ======================================================================== */
#elif defined(__FreeBSD__) && !defined(MEMDBG_PAL_CONSOLE)

memdbg_status_t pal_memory_read(int pid, uint64_t address, void *buffer,
                                size_t length, size_t *read_out) {
  if (read_out != NULL) *read_out = 0U;
  struct ptrace_io_desc io;
  memset(&io, 0, sizeof(io));
  io.piod_op   = PIOD_READ_D;
  io.piod_offs = (void *)(uintptr_t)address;
  io.piod_addr = buffer;
  io.piod_len  = length;
  if (ptrace(PT_IO, pid, (caddr_t)&io, 0) != 0)
    return errno == EACCES || errno == EPERM ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  if (read_out != NULL) *read_out = length - io.piod_len;
  return MEMDBG_OK;
}

memdbg_status_t pal_memory_write(int pid, uint64_t address,
                                 const void *buffer, size_t length,
                                 size_t *written_out) {
  if (written_out != NULL) *written_out = 0U;
  struct ptrace_io_desc io;
  memset(&io, 0, sizeof(io));
  io.piod_op   = PIOD_WRITE_D;
  io.piod_offs = (void *)(uintptr_t)address;
  io.piod_addr = (void *)(uintptr_t)buffer;
  io.piod_len  = length;
  if (ptrace(PT_IO, pid, (caddr_t)&io, 0) != 0)
    return errno == EACCES || errno == EPERM ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  if (written_out != NULL) *written_out = length - io.piod_len;
  return MEMDBG_OK;
}

memdbg_status_t pal_memory_protect(int pid, uint64_t address, size_t length,
                                   uint32_t protection,
                                   uint32_t *old_protection) {
  (void)pid; (void)address; (void)length; (void)protection;
  if (old_protection != NULL) *old_protection = 0U;
  return MEMDBG_ERR_UNSUPPORTED;
}

memdbg_status_t pal_memory_alloc(int pid, uint64_t hint, size_t length,
                                 uint32_t protection, uint32_t flags,
                                 uint64_t *address_out) {
  (void)pid; (void)hint; (void)length; (void)protection; (void)flags;
  if (address_out != NULL) *address_out = 0U;
  return MEMDBG_ERR_UNSUPPORTED;
}

memdbg_status_t pal_memory_free(int pid, uint64_t address, size_t length) {
  (void)pid; (void)address; (void)length;
  return MEMDBG_ERR_UNSUPPORTED;
}

/* FreeBSD batch falls back to individual ptrace calls. */
struct pal_memory_batch { int pid; };

pal_memory_batch_t *pal_memory_batch_begin(int pid) {
  pal_memory_batch_t *b = (pal_memory_batch_t *)malloc(sizeof(*b));
  if (b == NULL) return NULL;
  b->pid = pid;
  return b;
}

size_t pal_memory_batch_item(pal_memory_batch_t *batch, uint64_t address,
                             void *buffer, size_t length) {
  size_t read_out = 0U;
  if (pal_memory_read(batch->pid, address, buffer, length, &read_out) != MEMDBG_OK)
    return 0U;
  return read_out;
}

void pal_memory_batch_end(pal_memory_batch_t *batch) { free(batch); }

/* Batch write: falls back to individual ptrace calls. */
struct pal_memory_batch_write { int pid; };

pal_memory_batch_write_t *pal_memory_batch_write_begin(int pid) {
  pal_memory_batch_write_t *b = (pal_memory_batch_write_t *)malloc(sizeof(*b));
  if (b == NULL) return NULL;
  b->pid = pid;
  return b;
}

size_t pal_memory_batch_write_item(pal_memory_batch_write_t *batch,
                                   uint64_t address, const void *buffer,
                                   size_t length) {
  size_t written = 0U;
  if (pal_memory_write(batch->pid, address, buffer, length, &written) != MEMDBG_OK)
    return 0U;
  return written;
}

void pal_memory_batch_write_end(pal_memory_batch_write_t *batch) { free(batch); }

void pal_memory_fd_cache_flush(int pid) { (void)pid; }

/* ========================================================================
 *  PS4 / PS5  —  mdbg_copyout / mdbg_copyin (pal_memory_console.c)
 * ======================================================================== */
#elif defined(MEMDBG_PAL_CONSOLE)
/* Implementations live in pal_memory_console.c for clarity. */

/* ========================================================================
 *  macOS / other  —  stub for now (mach_vm would go here)
 * ======================================================================== */
#else

void pal_memory_fd_cache_flush(int pid) { (void)pid; }

memdbg_status_t pal_memory_read(int pid, uint64_t address, void *buffer,
                                size_t length, size_t *read_out) {
  (void)pid; (void)address; (void)buffer; (void)length;
  if (read_out != NULL) *read_out = 0U;
  return MEMDBG_ERR_UNSUPPORTED;
}

memdbg_status_t pal_memory_write(int pid, uint64_t address,
                                 const void *buffer, size_t length,
                                 size_t *written_out) {
  (void)pid; (void)address; (void)buffer; (void)length;
  if (written_out != NULL) *written_out = 0U;
  return MEMDBG_ERR_UNSUPPORTED;
}

memdbg_status_t pal_memory_protect(int pid, uint64_t address, size_t length,
                                   uint32_t protection,
                                   uint32_t *old_protection) {
  (void)pid; (void)address; (void)length; (void)protection;
  if (old_protection != NULL) *old_protection = 0U;
  return MEMDBG_ERR_UNSUPPORTED;
}

memdbg_status_t pal_memory_alloc(int pid, uint64_t hint, size_t length,
                                 uint32_t protection, uint32_t flags,
                                 uint64_t *address_out) {
  (void)pid; (void)hint; (void)length; (void)protection; (void)flags;
  if (address_out != NULL) *address_out = 0U;
  return MEMDBG_ERR_UNSUPPORTED;
}

memdbg_status_t pal_memory_free(int pid, uint64_t address, size_t length) {
  (void)pid; (void)address; (void)length;
  return MEMDBG_ERR_UNSUPPORTED;
}

struct pal_memory_batch { int unused; };
pal_memory_batch_t *pal_memory_batch_begin(int pid) { (void)pid; return NULL; }
size_t pal_memory_batch_item(pal_memory_batch_t *b, uint64_t a, void *buf, size_t len) {
  (void)b; (void)a; (void)buf; (void)len; return 0U; }
void pal_memory_batch_end(pal_memory_batch_t *b) { free(b); }

struct pal_memory_batch_write { int unused; };
pal_memory_batch_write_t *pal_memory_batch_write_begin(int pid) { (void)pid; return NULL; }
size_t pal_memory_batch_write_item(pal_memory_batch_write_t *b, uint64_t a, const void *buf, size_t len) {
  (void)b; (void)a; (void)buf; (void)len; return 0U; }
void pal_memory_batch_write_end(pal_memory_batch_write_t *b) { free(b); }

#endif
