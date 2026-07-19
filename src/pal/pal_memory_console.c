/*
 * memDBG - PAL: PS4/PS5 console memory access backend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Uses Sony's mdbg_copyout / mdbg_copyin syscalls with PS5-specific
 * fallbacks: PTWALK (direct-memory-access page-table walk) and DMAP
 * (FW >= 8.40).  The td_proc-switch helper enables cross-process
 * mmap/munmap/mprotect via __crt_syscall.
 *
 * Guarded by MEMDBG_PAL_CONSOLE; compiles to an empty TU on host.
 */

#include "pal_memory_internal.h"

#if defined(MEMDBG_PAL_CONSOLE)

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
      /* PTWALK writes physical memory directly, bypassing the CPU cache.
       * Follow up with a VA-path write via the safe mdbg_copyin to force
       * instruction-cache coherency on x86-64 (AMD Zen 2).  If the caller
       * used PROCESS_PROTECT first, mdbg_copyin will succeed and properly
       * flush the icache.  If it returns EACCES (hypervisor W^X), the
       * ptw_write already succeeded - this is best-effort. */
      (void)console_mdbg_copyin_raw((pid_t)pid, buffer,
                                    (intptr_t)address, length);
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

/* ---- PS5 td_proc-switch helper (shared by alloc / free) ---- */

#if defined(MEMDBG_PAL_PS5)

typedef struct {
  intptr_t my_td;
  intptr_t saved_proc;
} td_proc_ctx_t;

/* Switch the current kernel thread's proc pointer to the target process.
 * On return the caller is inside the kernel-external lock and can safely
 * issue __crt_syscall(mmap/munmap/...).  Call td_proc_switch_restore()
 * afterwards to revert and unlock.
 *
 * td_proc is at offset 0x8 inside struct thread (right after td_lock)
 * on every supported FreeBSD kernel version.  The p_threads offset varies
 * (0x10 on FreeBSD 12, 0x60 on FreeBSD 9-11); we probe both. */
static memdbg_status_t td_proc_switch_to_target(int pid, td_proc_ctx_t *ctx) {
  memset(ctx, 0, sizeof(*ctx));

  if (memdbg_kernel_external_begin() != 0) return MEMDBG_ERR_STATE;

  intptr_t target_proc = kernel_get_proc((pid_t)pid);
  intptr_t my_proc     = kernel_get_proc(getpid());
  if (target_proc == 0 || my_proc == 0) {
    memdbg_kernel_external_end();
    return target_proc == 0 ? MEMDBG_ERR_NOT_FOUND : MEMDBG_ERR_STATE;
  }

  /* Find one of our own threads by walking p_threads. */
  static const int k_thr_off_candidates[] = {0x10, 0x60};
  intptr_t my_td = 0;
  for (size_t ci = 0U;
       ci < sizeof(k_thr_off_candidates) / sizeof(k_thr_off_candidates[0]); ++ci) {
    intptr_t candidate = (intptr_t)kernel_getlong(my_proc + k_thr_off_candidates[ci]);
    /* td_proc is at thread+0x8 - validate the candidate points back
     * to our own proc. */
    if (candidate != 0 &&
        (intptr_t)kernel_getlong(candidate + 0x8) == my_proc) {
      my_td = candidate;
      break;
    }
  }
  if (my_td == 0) {
    memdbg_kernel_external_end();
    return MEMDBG_ERR_STATE;
  }

  ctx->my_td      = my_td;
  ctx->saved_proc = (intptr_t)kernel_getlong(my_td + 0x8);
  (void)kernel_setlong(my_td + 0x8, (uint64_t)target_proc);
  return MEMDBG_OK;
}

static void td_proc_switch_restore(const td_proc_ctx_t *ctx) {
  (void)kernel_setlong(ctx->my_td + 0x8, (uint64_t)ctx->saved_proc);
  memdbg_kernel_external_end();
}

#endif /* MEMDBG_PAL_PS5 */

memdbg_status_t pal_memory_alloc(int pid, uint64_t hint, size_t length,
                                 uint32_t protection, uint32_t flags,
                                 uint64_t *address_out) {
#if defined(MEMDBG_PAL_PS5)
  if (address_out != NULL) *address_out = 0U;
  if (pid <= 1 || length == 0U) return MEMDBG_ERR_PARAM;
  (void)flags;

  td_proc_ctx_t ctx;
  memdbg_status_t st = td_proc_switch_to_target(pid, &ctx);
  if (st != MEMDBG_OK) return st;

  int native_prot = (int)(protection & 0x7U);
  int mmap_flags  = 0x1002;  /* MAP_ANON | MAP_PRIVATE */
  void *result = (void *)__crt_syscall(477, hint, (long)length,
                                       (long)native_prot, (long)mmap_flags,
                                       (long)-1, (long)0);

  td_proc_switch_restore(&ctx);

  if (result == (void *)-1) return MEMDBG_ERR_IO;
  if (address_out != NULL) *address_out = (uint64_t)(uintptr_t)result;
  return MEMDBG_OK;
#else
  (void)pid; (void)hint; (void)length; (void)protection; (void)flags;
  if (address_out != NULL) *address_out = 0U;
  return MEMDBG_ERR_UNSUPPORTED;
#endif
}

memdbg_status_t pal_memory_free(int pid, uint64_t address, size_t length) {
#if defined(MEMDBG_PAL_PS5)
  if (pid <= 1 || address == 0U || length == 0U) return MEMDBG_ERR_PARAM;

  td_proc_ctx_t ctx;
  memdbg_status_t st = td_proc_switch_to_target(pid, &ctx);
  if (st != MEMDBG_OK) return st;

  long rc = __crt_syscall(73, (long)address, (long)length);

  td_proc_switch_restore(&ctx);
  return rc == 0 ? MEMDBG_OK : MEMDBG_ERR_IO;
#else
  (void)pid; (void)address; (void)length;
  return MEMDBG_ERR_UNSUPPORTED;
#endif
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
    if (ptw_write((uint32_t)b->pid, a, (uint64_t)len, buf) == 0) {
      /* Best-effort cache coherency via safe mdbg_copyin (see
       * pal_memory_write for rationale). */
      (void)console_mdbg_copyin_raw((pid_t)b->pid, buf, (intptr_t)a, len);
      return len;
    }
  }
#endif
  return console_mdbg_copyin((pid_t)b->pid, (intptr_t)a, buf, len) == 0 ? len : 0U;
}

void pal_memory_batch_write_end(pal_memory_batch_write_t *b) { free(b); }

void pal_memory_fd_cache_flush(int pid) { (void)pid; }

#endif /* MEMDBG_PAL_CONSOLE */
