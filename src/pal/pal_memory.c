/*
 * memDBG - PAL: Cross-platform memory access implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Platform dispatch:
 *   __ORBIS__        → PS4  (sceDbgMemoryRead/Write)
 *   __PROSPERO__     → PS5  (sceDbgMemoryRead/Write, Prospero equivalents)
 *   __linux__        → Host (/proc/pid/mem)
 *   __FreeBSD__      → Host (ptrace PT_IO)
 *   __APPLE__        → Host (mach_vm, via task_for_pid + vm_read/write — stub for now)
 *   default          → MEMDBG_ERR_UNSUPPORTED
 */

#include "memdbg/pal/pal_memory.h"
#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/pal/pal_fileio.h"
#include "memdbg/pal/pal_process.h"
#include "memdbg/pal/pal_kernel_fast.h"
#include "memdbg/scanner/pt_walker.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(PLATFORM_PS4) || defined(PS4) || defined(__ORBIS__)
#define MEMDBG_PAL_PS4 1
#endif

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#define MEMDBG_PAL_PS5 1
#endif

#if defined(MEMDBG_PAL_PS4) || defined(MEMDBG_PAL_PS5)
#define MEMDBG_PAL_CONSOLE 1
#endif

#if defined(MEMDBG_PAL_PS4)
#include <ps4/mdbg.h>
#elif defined(MEMDBG_PAL_PS5)
#include <ps5/kernel.h>
#include <ps5/mdbg.h>
#include <sys/mman.h>
#endif

#if defined(__FreeBSD__) && !defined(MEMDBG_PAL_CONSOLE)
#include <sys/ptrace.h>
#include <sys/types.h>
#endif

/* ========================================================================
 *  Linux  —  /proc/pid/mem  (with per-PID fd cache)
 * ======================================================================== */
#if defined(__linux__)

#include <pthread.h>
#include <time.h>

/* ---- Per-PID fd cache ----
 *
 * Opening /proc/pid/mem is relatively expensive (~20 µs).  During a
 * scan the scanner makes hundreds of short reads across many maps;
 * caching the fd per PID reduces this to 1 open/close per PID.
 *
 * The cache holds up to 4 fds, uses LRU eviction, and is thread-safe
 * via a pthread mutex.  Entries expire after 30 s of inactivity so
 * stale fds don't accumulate after a scan finishes. */

#define MEMDBG_FD_CACHE_MAX 4
#define MEMDBG_FD_CACHE_TTL 30

typedef struct {
  int      pid;
  int      fd;
  time_t   last_used;
  bool     valid;
} fd_cache_entry_t;

static fd_cache_entry_t g_fd_cache[MEMDBG_FD_CACHE_MAX];
static pthread_mutex_t  g_fd_cache_mtx = PTHREAD_MUTEX_INITIALIZER;
static bool             g_fd_cache_init = false;

static void fd_cache_ensure_init(void) {
  if (g_fd_cache_init) return;
  memset(g_fd_cache, 0, sizeof(g_fd_cache));
  g_fd_cache_init = true;
}

/* Look up or create a cached fd for `pid`.  Returns -1 on error. */
static int fd_cache_get(int pid) {
  time_t now = time(NULL);
  int slot = -1, empty_slot = -1;
  time_t oldest = now;

  fd_cache_ensure_init();
  pthread_mutex_lock(&g_fd_cache_mtx);

  for (int i = 0; i < MEMDBG_FD_CACHE_MAX; ++i) {
    if (!g_fd_cache[i].valid) {
      if (empty_slot < 0) empty_slot = i;
      continue;
    }
    /* Expire stale entries. */
    if (now - g_fd_cache[i].last_used > MEMDBG_FD_CACHE_TTL) {
      (void)pal_file_close(g_fd_cache[i].fd);
      g_fd_cache[i].valid = false;
      if (empty_slot < 0) empty_slot = i;
      continue;
    }
    /* Hit. */
    if (g_fd_cache[i].pid == pid) {
      g_fd_cache[i].last_used = now;
      int fd = g_fd_cache[i].fd;
      pthread_mutex_unlock(&g_fd_cache_mtx);
      return fd;
    }
    /* Track LRU candidate. */
    if (g_fd_cache[i].last_used < oldest) {
      oldest = g_fd_cache[i].last_used;
      slot = i;
    }
  }

  /* Evict if needed, prefer an empty slot. */
  if (empty_slot >= 0) slot = empty_slot;
  else if (slot < 0)   slot = 0;

  if (g_fd_cache[slot].valid)
    (void)pal_file_close(g_fd_cache[slot].fd);

  /* Open new fd. */
  char path[64];
  if (snprintf(path, sizeof(path), "/proc/%d/mem", pid) < 0) {
    pthread_mutex_unlock(&g_fd_cache_mtx);
    return -1;
  }
  int fd = pal_file_open(path, O_RDONLY, 0);
  if (fd < 0) {
    g_fd_cache[slot].valid = false;
    pthread_mutex_unlock(&g_fd_cache_mtx);
    return -1;
  }

  g_fd_cache[slot].pid       = pid;
  g_fd_cache[slot].fd        = fd;
  g_fd_cache[slot].last_used = now;
  g_fd_cache[slot].valid     = true;

  pthread_mutex_unlock(&g_fd_cache_mtx);
  return fd;
}

/* Flush cached fds for `pid`, or all if pid <= 0. */
void pal_memory_fd_cache_flush(int pid) {
  pthread_mutex_lock(&g_fd_cache_mtx);
  for (int i = 0; i < MEMDBG_FD_CACHE_MAX; ++i) {
    if (!g_fd_cache[i].valid) continue;
    if (pid <= 0 || g_fd_cache[i].pid == pid) {
      (void)pal_file_close(g_fd_cache[i].fd);
      g_fd_cache[i].valid = false;
    }
  }
  pthread_mutex_unlock(&g_fd_cache_mtx);
}

static memdbg_status_t linux_mem_path(int pid, char *out, size_t out_size) {
  if (pid <= 0 || out == NULL || out_size == 0U)
    return MEMDBG_ERR_PARAM;
  int n = snprintf(out, out_size, "/proc/%d/mem", pid);
  if (n < 0 || (size_t)n >= out_size)
    return MEMDBG_ERR_OVERFLOW;
  return MEMDBG_OK;
}

memdbg_status_t pal_memory_read(int pid, uint64_t address, void *buffer,
                                size_t length, size_t *read_out) {
  if (read_out != NULL) *read_out = 0U;

  int fd = fd_cache_get(pid);
  if (fd < 0)
    return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  ssize_t n = pal_file_pread_all(fd, buffer, length, (off_t)address);
  if (n < 0) {
    int saved = errno;
    /* Invalidate cache entry on persistent error. */
    if (saved != EINTR && saved != EAGAIN)
      pal_memory_fd_cache_flush(pid);
    errno = saved;
    return saved == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  }
  if (read_out != NULL) *read_out = (size_t)n;
  return MEMDBG_OK;
}

memdbg_status_t pal_memory_write(int pid, uint64_t address,
                                 const void *buffer, size_t length,
                                 size_t *written_out) {
  (void)pid; /* write uses its own O_RDWR fd — not cached for now */
  if (written_out != NULL) *written_out = 0U;
  char path[64];
  int n = snprintf(path, sizeof(path), "/proc/%d/mem", pid);
  if (n < 0 || (size_t)n >= sizeof(path)) return MEMDBG_ERR_OVERFLOW;
  int fd = pal_file_open(path, O_RDWR, 0);
  if (fd < 0)
    return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  ssize_t nw = pal_file_pwrite_all(fd, buffer, length, (off_t)address);
  int saved = errno;
  (void)pal_file_close(fd);
  if (nw < 0) { errno = saved; return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO; }
  if (written_out != NULL) *written_out = (size_t)nw;
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

/* Batch uses the fd cache for /proc/pid/mem — avoids opening duplicate
   fds when a scan already cached the fd for this PID. */
struct pal_memory_batch { int fd; int pid; bool cached_fd; };

pal_memory_batch_t *pal_memory_batch_begin(int pid) {
  int fd = fd_cache_get(pid);
  if (fd < 0) return NULL;
  pal_memory_batch_t *b = (pal_memory_batch_t *)malloc(sizeof(*b));
  if (b == NULL) return NULL;
  b->fd        = fd;
  b->pid       = pid;
  b->cached_fd = true;  /* do not close — fd_cache owns the fd */
  return b;
}

size_t pal_memory_batch_item(pal_memory_batch_t *batch, uint64_t address,
                             void *buffer, size_t length) {
  if (batch == NULL || batch->fd < 0 || buffer == NULL || length == 0U) return 0U;
  ssize_t n = pal_file_pread_all(batch->fd, buffer, length, (off_t)address);
  return n > 0 ? (size_t)n : 0U;
}

void pal_memory_batch_end(pal_memory_batch_t *batch) {
  if (batch == NULL) return;
  if (!batch->cached_fd)
    (void)pal_file_close(batch->fd);
  free(batch);
}

/* Batch write: single fd opened O_RDWR, reused for all items. */
struct pal_memory_batch_write { int fd; int pid; };

pal_memory_batch_write_t *pal_memory_batch_write_begin(int pid) {
  char path[64];
  if (linux_mem_path(pid, path, sizeof(path)) != MEMDBG_OK) return NULL;
  int fd = pal_file_open(path, O_RDWR, 0);
  if (fd < 0) return NULL;
  pal_memory_batch_write_t *b = (pal_memory_batch_write_t *)malloc(sizeof(*b));
  if (b == NULL) { pal_file_close(fd); return NULL; }
  b->fd  = fd;
  b->pid = pid;
  return b;
}

size_t pal_memory_batch_write_item(pal_memory_batch_write_t *batch,
                                   uint64_t address, const void *buffer,
                                   size_t length) {
  if (batch == NULL || batch->fd < 0 || buffer == NULL || length == 0U) return 0U;
  ssize_t n = pal_file_pwrite_all(batch->fd, buffer, length, (off_t)address);
  return n > 0 ? (size_t)n : 0U;
}

void pal_memory_batch_write_end(pal_memory_batch_write_t *batch) {
  if (batch == NULL) return;
  (void)pal_file_close(batch->fd);
  free(batch);
}

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
 *  PS4 / PS5  —  mdbg_copyout / mdbg_copyin
 * ======================================================================== */
#elif defined(MEMDBG_PAL_CONSOLE)

#include <pthread.h>

/* Sony's mdbg process-rw syscall shares kernel-side state and is not
 * re-entrant across payload threads.  Parallel protocol connections remain
 * useful, but calls into this one primitive must enter one at a time. */
static pthread_mutex_t g_mdbg_mutex = PTHREAD_MUTEX_INITIALIZER;

static int console_mdbg_copyout(pid_t pid, intptr_t address, void *buffer,
                                size_t length) {
  (void)pthread_mutex_lock(&g_mdbg_mutex);
  errno = 0;
  const int rc = mdbg_copyout(pid, address, buffer, length);
  const int saved_errno = errno;
  (void)pthread_mutex_unlock(&g_mdbg_mutex);
  errno = saved_errno;
  return rc;
}

static int console_mdbg_copyin_raw(pid_t pid, const void *buffer,
                                   intptr_t address, size_t length) {
  (void)pthread_mutex_lock(&g_mdbg_mutex);
  errno = 0;
  const int rc = mdbg_copyin(pid, buffer, address, length);
  const int saved_errno = errno;
  (void)pthread_mutex_unlock(&g_mdbg_mutex);
  errno = saved_errno;
  return rc;
}

static memdbg_status_t mdbg_errno_status(void) {
  switch (errno) {
  case EACCES:
  case EPERM:
    return MEMDBG_ERR_PERMISSION;
  case ESRCH:
  case ENOENT:
    return MEMDBG_ERR_NOT_FOUND;
  case EINVAL:
    return MEMDBG_ERR_PARAM;
  default:
    return MEMDBG_ERR_IO;
  }
}

#if defined(MEMDBG_PAL_PS5)
static int console_get_vmem_protection(pid_t pid, intptr_t address,
                                       size_t length) {
  if (memdbg_kernel_external_begin() != 0) {
    errno = EBUSY;
    return -1;
  }
  int result = kernel_get_vmem_protection(pid, address, length);
  int saved_errno = errno;
  memdbg_kernel_external_end();
  errno = saved_errno;
  return result;
}

static int console_set_vmem_protection(pid_t pid, intptr_t address,
                                       size_t length, int protection) {
  if (memdbg_kernel_external_begin() != 0) {
    errno = EBUSY;
    return -1;
  }
  int result = kernel_set_vmem_protection(pid, address, length, protection);
  int saved_errno = errno;
  memdbg_kernel_external_end();
  errno = saved_errno;
  return result;
}

static int console_mdbg_copyin_ps5_regions(pid_t pid, intptr_t address,
                                           const void *buffer, size_t length) {
  pal_map_list_t maps;
  uint64_t cursor = (uint64_t)(uintptr_t)address;
  uint64_t end;
  size_t buffer_offset = 0U;
  int failure_errno = 0;

  if (length > UINT64_MAX - cursor) {
    errno = EOVERFLOW;
    return -1;
  }
  end = cursor + length;
  if (pal_process_maps((int)pid, &maps) != MEMDBG_OK) {
    if (errno == 0) errno = EIO;
    return -1;
  }

  while (cursor < end) {
    const pal_map_entry_t *map = NULL;
    for (size_t i = 0U; i < maps.count; ++i) {
      if (maps.entries[i].start <= cursor && cursor < maps.entries[i].end) {
        map = &maps.entries[i];
        break;
      }
    }
    if (map == NULL) {
      failure_errno = EFAULT;
      break;
    }

    const uint64_t segment_end = map->end < end ? map->end : end;
    const size_t segment_length = (size_t)(segment_end - cursor);
    const int original_prot = console_get_vmem_protection(
        pid, (intptr_t)cursor, segment_length);
    if (original_prot < 0) {
      failure_errno = errno != 0 ? errno : EIO;
      break;
    }

    bool changed_protection = (original_prot & PROT_WRITE) == 0;
    if (changed_protection &&
        console_set_vmem_protection(pid, (intptr_t)cursor, segment_length,
                                    original_prot | PROT_READ | PROT_WRITE) != 0) {
      failure_errno = errno != 0 ? errno : EACCES;
      break;
    }

    errno = 0;
    const int copy_rc = console_mdbg_copyin_raw(
        pid, (const uint8_t *)buffer + buffer_offset, (intptr_t)cursor,
        segment_length);
    const int copy_errno = errno;

    int dmap_ok = 0;
    if (copy_rc != 0 && ptw_is_available()) {
      dmap_ok = (ptw_write((uint32_t)pid, cursor, segment_length,
                           (const uint8_t *)buffer + buffer_offset) == 0);
    }

    if (changed_protection) {
      errno = 0;
      if (console_set_vmem_protection(pid, (intptr_t)cursor, segment_length,
                                      original_prot) != 0) {
        failure_errno = errno != 0 ? errno : EIO;
        break;
      }
    }
    if (copy_rc != 0 && !dmap_ok) {
      failure_errno = copy_errno != 0 ? copy_errno : EIO;
      break;
    }

    buffer_offset += segment_length;
    cursor = segment_end;
  }

  pal_process_maps_free(&maps);
  if (failure_errno != 0) {
    errno = failure_errno;
    return -1;
  }
  return 0;
}
#endif

#if defined(MEMDBG_PAL_PS5)
static int s_fw_needs_dmap = -1;

static int console_fw_needs_dmap(void) {
  if (s_fw_needs_dmap < 0)
    s_fw_needs_dmap = ((kernel_get_fw_version() & 0xffff0000u) >= 0x08400000u) ? 1 : 0;
  return s_fw_needs_dmap;
}
#endif

static int console_mdbg_copyin(pid_t pid, intptr_t address, const void *buffer,
                               size_t length) {
  errno = 0;
  if (console_mdbg_copyin_raw(pid, buffer, address, length) == 0) {
    return 0;
  }

  const int first_errno = errno;

#if defined(MEMDBG_PAL_PS5)
  if (first_errno == EACCES || first_errno == EPERM) {
    if (length != 0U && ptw_is_available() &&
        ptw_write((uint32_t)pid, (uint64_t)address, (uint64_t)length, buffer) == 0)
      return 0;

    if (length != 0U) {
      if (console_mdbg_copyin_ps5_regions(pid, address, buffer, length) == 0)
        return 0;
    }
    return -1;
  }
#endif

  errno = first_errno;
  return -1;
}

memdbg_status_t pal_memory_read(int pid, uint64_t address, void *buffer,
                                size_t length, size_t *read_out) {
  if (read_out != NULL) *read_out = 0U;
  if (pid <= 0 || (buffer == NULL && length != 0U)) return MEMDBG_ERR_PARAM;
  if (pid <= 1) return MEMDBG_ERR_PERMISSION;
  if (length == 0U) return MEMDBG_OK;

#if defined(MEMDBG_PAL_PS5)
  if (ptw_aux_contains((uint32_t)pid, address, (uint64_t)length) &&
      ptw_read((uint32_t)pid, address, (uint64_t)length, buffer) == 0) {
    if (read_out != NULL) *read_out = length;
    return MEMDBG_OK;
  }
#endif

  errno = 0;
  if (console_mdbg_copyout((pid_t)pid, (intptr_t)address, buffer, length) != 0) {
    const int first_errno = errno;
#if defined(MEMDBG_PAL_PS5)
    /* DMAP is a fallback for a blocked mdbg primitive, not for an invalid or
     * partially unmapped user range. Walking an EFAULT range can touch an
     * absent page-table level and terminate the connection handler. */
    if ((first_errno == EACCES || first_errno == EPERM) &&
        ptw_is_available() &&
        ptw_read((uint32_t)pid, address, (uint64_t)length, buffer) == 0) {
      if (read_out != NULL) *read_out = length;
      return MEMDBG_OK;
    }
#endif
    errno = first_errno;
    return mdbg_errno_status();
  }

  if (read_out != NULL) *read_out = length;
  return MEMDBG_OK;
}

memdbg_status_t pal_memory_write(int pid, uint64_t address,
                                 const void *buffer, size_t length,
                                 size_t *written_out) {
  if (written_out != NULL) *written_out = 0U;
  if (pid <= 0 || (buffer == NULL && length != 0U)) return MEMDBG_ERR_PARAM;
  if (pid <= 1) return MEMDBG_ERR_PERMISSION;
  if (length == 0U) return MEMDBG_OK;

#if defined(MEMDBG_PAL_PS5)
  if (console_fw_needs_dmap() && ptw_is_available()) {
    if (ptw_write((uint32_t)pid, address, (uint64_t)length, buffer) == 0) {
      if (written_out != NULL) *written_out = length;
      return MEMDBG_OK;
    }
  }
#endif

  errno = 0;
  if (console_mdbg_copyin((pid_t)pid, (intptr_t)address, buffer, length) != 0)
    return mdbg_errno_status();

  if (written_out != NULL) *written_out = length;
  return MEMDBG_OK;
}

#if defined(MEMDBG_PAL_PS5)
static int memdbg_prot_to_native(uint32_t protection) {
  int native = 0;
  if ((protection & MEMDBG_MAP_PROT_READ) != 0U) native |= PROT_READ;
  if ((protection & MEMDBG_MAP_PROT_WRITE) != 0U) native |= PROT_WRITE;
  if ((protection & MEMDBG_MAP_PROT_EXEC) != 0U) native |= PROT_EXEC;
  return native;
}

static uint32_t native_prot_to_memdbg(int protection) {
  uint32_t out = 0U;
  if ((protection & PROT_READ) != 0) out |= MEMDBG_MAP_PROT_READ;
  if ((protection & PROT_WRITE) != 0) out |= MEMDBG_MAP_PROT_WRITE;
  if ((protection & PROT_EXEC) != 0) out |= MEMDBG_MAP_PROT_EXEC;
  return out;
}
#endif

memdbg_status_t pal_memory_protect(int pid, uint64_t address, size_t length,
                                   uint32_t protection,
                                   uint32_t *old_protection) {
  if (old_protection != NULL) *old_protection = 0U;
  if (pid <= 1 || address == 0U || length == 0U)
    return MEMDBG_ERR_PARAM;

#if defined(MEMDBG_PAL_PS5)
  if (memdbg_kernel_external_begin() != 0) return MEMDBG_ERR_STATE;
  int old_native = kernel_get_vmem_protection((pid_t)pid, (intptr_t)address,
                                              length);
  if (old_native < 0) {
    memdbg_kernel_external_end();
    return mdbg_errno_status();
  }
  if (old_protection != NULL)
    *old_protection = native_prot_to_memdbg(old_native);

  int new_native = memdbg_prot_to_native(protection);
  if (kernel_mprotect((pid_t)pid, (intptr_t)address, length, new_native) != 0 &&
      kernel_set_vmem_protection((pid_t)pid, (intptr_t)address, length,
                                 new_native) != 0) {
    memdbg_kernel_external_end();
    return mdbg_errno_status();
  }
  memdbg_kernel_external_end();
  return MEMDBG_OK;
#else
  (void)protection;
  return MEMDBG_ERR_UNSUPPORTED;
#endif
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

struct pal_memory_batch { int pid; };
pal_memory_batch_t *pal_memory_batch_begin(int pid) {
  if (pid <= 1) return NULL;
  pal_memory_batch_t *b = (pal_memory_batch_t *)malloc(sizeof(*b));
  if (b == NULL) return NULL;
  b->pid = pid;
  return b;
}

size_t pal_memory_batch_item(pal_memory_batch_t *b, uint64_t a, void *buf, size_t len) {
  if (b == NULL || buf == NULL || len == 0U) return 0U;
  if (b->pid <= 1) return 0U;
#if defined(MEMDBG_PAL_PS5)
  if (ptw_aux_contains((uint32_t)b->pid, a, (uint64_t)len) &&
      ptw_read((uint32_t)b->pid, a, (uint64_t)len, buf) == 0)
    return len;
#endif
  errno = 0;
  if (console_mdbg_copyout((pid_t)b->pid, (intptr_t)a, buf, len) != 0) {
#if defined(MEMDBG_PAL_PS5)
    if (ptw_is_available() &&
        ptw_read((uint32_t)b->pid, a, (uint64_t)len, buf) == 0)
      return len;
#endif
    return 0U;
  }
  return len;
}

void pal_memory_batch_end(pal_memory_batch_t *b) { free(b); }

struct pal_memory_batch_write { int pid; };
pal_memory_batch_write_t *pal_memory_batch_write_begin(int pid) {
  if (pid <= 1) return NULL;
  pal_memory_batch_write_t *b =
      (pal_memory_batch_write_t *)malloc(sizeof(*b));
  if (b == NULL) return NULL;
  b->pid = pid;
  return b;
}

size_t pal_memory_batch_write_item(pal_memory_batch_write_t *b, uint64_t a, const void *buf, size_t len) {
  if (b == NULL || buf == NULL || len == 0U) return 0U;
  if (b->pid <= 1) return 0U;
#if defined(MEMDBG_PAL_PS5)
  if (console_fw_needs_dmap() && ptw_is_available()) {
    if (ptw_write((uint32_t)b->pid, a, (uint64_t)len, buf) == 0)
      return len;
  }
#endif
  return console_mdbg_copyin((pid_t)b->pid, (intptr_t)a, buf, len) == 0 ? len : 0U;
}

void pal_memory_batch_write_end(pal_memory_batch_write_t *b) { free(b); }

void pal_memory_fd_cache_flush(int pid) { (void)pid; }

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
