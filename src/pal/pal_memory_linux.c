/*
 * memDBG - PAL: Linux /proc/pid/mem memory access backend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Compiled on all platforms (Makefile globs src/ * .c) but the outer
 * #if defined(__linux__) guard makes this file a no-op on non-Linux.
 */

#include "pal_memory_internal.h"

#if defined(__linux__)

#include <pthread.h>
#include <time.h>

/* ---- Per-PID fd cache ----
 *
 * Opening /proc/pid/mem is relatively expensive (~20 us).  During a
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
static pthread_once_t   g_fd_cache_once = PTHREAD_ONCE_INIT;

static void fd_cache_init_once(void) {
  memset(g_fd_cache, 0, sizeof(g_fd_cache));
}

/* Look up or create a cached fd for `pid`.  Returns -1 on error. */
static int fd_cache_get(int pid) {
  time_t now = time(NULL);
  int slot = -1, empty_slot = -1;
  time_t oldest = now;

  pthread_once(&g_fd_cache_once, fd_cache_init_once);
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

  /* First attempt: cached fd. */
  int fd = fd_cache_get(pid);
  if (fd < 0)
    return errno == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
  ssize_t n = pal_file_pread_all(fd, buffer, length, (off_t)address);
  if (n >= 0) {
    if (read_out != NULL) *read_out = (size_t)n;
    return MEMDBG_OK;
  }

  int saved = errno;

  /* If the cached fd was closed by a concurrent flush (TOCTOU race),
   * invalidate the stale cache entry, open a fresh fd outside the
   * cache, and retry exactly once.  All other errors are terminal. */
  if (saved == EBADF) {
    pal_memory_fd_cache_flush(pid);
    char path[64];
    if (snprintf(path, sizeof(path), "/proc/%d/mem", pid) >= 0) {
      fd = pal_file_open(path, O_RDONLY, 0);
      if (fd >= 0) {
        n = pal_file_pread_all(fd, buffer, length, (off_t)address);
        if (n >= 0) {
          (void)pal_file_close(fd);
          if (read_out != NULL) *read_out = (size_t)n;
          return MEMDBG_OK;
        }
        saved = errno;
        (void)pal_file_close(fd);
      }
    }
  } else if (saved != EINTR && saved != EAGAIN) {
    /* Non-retryable error (e.g. EACCES, EIO): invalidate cache entry so
     * the next call reopens /proc/pid/mem rather than reusing the stale
     * fd.  EINTR / EAGAIN are transient and the cached fd remains valid. */
    pal_memory_fd_cache_flush(pid);
  }

  errno = saved;
  return saved == EACCES ? MEMDBG_ERR_PERMISSION : MEMDBG_ERR_IO;
}

memdbg_status_t pal_memory_write(int pid, uint64_t address,
                                 const void *buffer, size_t length,
                                 size_t *written_out) {
  (void)pid; /* write uses its own O_RDWR fd - not cached for now */
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

/* Batch uses the fd cache for /proc/pid/mem - avoids opening duplicate
   fds when a scan already cached the fd for this PID. */
struct pal_memory_batch { int fd; int pid; bool cached_fd; };

pal_memory_batch_t *pal_memory_batch_begin(int pid) {
  int fd = fd_cache_get(pid);
  if (fd < 0) return NULL;
  pal_memory_batch_t *b = (pal_memory_batch_t *)malloc(sizeof(*b));
  if (b == NULL) return NULL;
  b->fd        = fd;
  b->pid       = pid;
  b->cached_fd = true;  /* do not close - fd_cache owns the fd */
  return b;
}

size_t pal_memory_batch_item(pal_memory_batch_t *batch, uint64_t address,
                             void *buffer, size_t length) {
  if (batch == NULL || batch->fd < 0 || buffer == NULL || length == 0U) return 0U;
  ssize_t n = pal_file_pread_all(batch->fd, buffer, length, (off_t)address);
  if (n > 0) return (size_t)n;

  /* If the cached fd was closed by a concurrent flush (TOCTOU race),
   * fall back to a direct open + pread for this item. */
  if (n < 0 && errno == EBADF && batch->cached_fd && batch->pid > 0) {
    char path[64];
    if (snprintf(path, sizeof(path), "/proc/%d/mem", batch->pid) >= 0) {
      int fd = pal_file_open(path, O_RDONLY, 0);
      if (fd >= 0) {
        ssize_t m = pal_file_pread_all(fd, buffer, length, (off_t)address);
        (void)pal_file_close(fd);
        if (m > 0) return (size_t)m;
      }
    }
  }
  return 0U;
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

#endif /* __linux__ */
