/*
 * memDBG - Fast PS5 kernel read/write primitive and process cache.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "memdbg/pal/pal_kernel_fast.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)

#include <ps5/kernel.h>
#include <ps5/payload.h>

extern long __crt_syscall(long sysno, ...);

#define MEMDBG_FAST_PROC_CACHE 16

typedef struct memdbg_fast_proc_entry {
  pid_t pid;
  intptr_t address;
} memdbg_fast_proc_entry_t;

static pthread_once_t g_fast_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_fast_mutex;
static pthread_mutex_t g_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static memdbg_fast_proc_entry_t g_proc_cache[MEMDBG_FAST_PROC_CACHE];
static unsigned int g_proc_cache_next;
static int g_rwpipe[2] = {-1, -1};
static int g_rwpair[2] = {-1, -1};
static uint64_t g_kpipe_address;
static int g_fast_available;

static void fast_init(void) {
  pthread_mutexattr_t attr;
  payload_args_t *args = payload_get_args();
  (void)pthread_mutexattr_init(&attr);
  (void)pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  (void)pthread_mutex_init(&g_fast_mutex, &attr);
  (void)pthread_mutexattr_destroy(&attr);
  if (args == NULL || args->rwpipe == NULL || args->rwpair == NULL ||
      args->kpipe_addr == 0)
    return;
  g_rwpipe[0] = args->rwpipe[0];
  g_rwpipe[1] = args->rwpipe[1];
  g_rwpair[0] = args->rwpair[0];
  g_rwpair[1] = args->rwpair[1];
  g_kpipe_address = (uint64_t)args->kpipe_addr;
  g_fast_available = g_rwpipe[0] >= 0 && g_rwpipe[1] >= 0 &&
                     g_rwpair[0] >= 0 && g_rwpair[1] >= 0;
}

int memdbg_kernel_fast_available(void) {
  (void)pthread_once(&g_fast_once, fast_init);
  return g_fast_available;
}

int memdbg_kernel_external_begin(void) {
  (void)pthread_once(&g_fast_once, fast_init);
  return pthread_mutex_lock(&g_fast_mutex);
}

void memdbg_kernel_external_end(void) {
  (void)pthread_mutex_unlock(&g_fast_mutex);
}

static int setup_pipe(uint64_t address, int writing) {
  uint64_t setup[7];
  memset(setup, 0, sizeof(setup));
  setup[0] = writing ? 0U : 0x4000000040000000ULL;
  setup[1] = 0x4000000000000000ULL;
  setup[4] = g_kpipe_address;
  if (__crt_syscall(0x69, g_rwpair[0], 0x29, 0x2e, &setup[4], 0x14) != 0)
    return -1;
  if (__crt_syscall(0x69, g_rwpair[1], 0x29, 0x2e, &setup[0], 0x14) != 0)
    return -1;

  memset(setup, 0, sizeof(setup));
  setup[0] = address;
  setup[4] = g_kpipe_address + 0x10U;
  if (__crt_syscall(0x69, g_rwpair[0], 0x29, 0x2e, &setup[4], 0x14) != 0)
    return -1;
  return __crt_syscall(0x69, g_rwpair[1], 0x29, 0x2e,
                       &setup[0], 0x14) == 0 ? 0 : -1;
}

int32_t memdbg_kernel_copyin_fast(const void *source, intptr_t destination,
                                  size_t length) {
  if (source == NULL || destination == 0 || length == 0U) {
    errno = EINVAL;
    return -1;
  }
  if (!memdbg_kernel_fast_available()) {
    errno = ENOTSUP;
    return -1;
  }
  if (memdbg_kernel_external_begin() != 0) return -1;
  int rc = setup_pipe((uint64_t)destination, 1);
  if (rc == 0) {
    long n = __crt_syscall(4, g_rwpipe[1], source, length);
    rc = n == (long)length ? 0 : -1;
  }
  memdbg_kernel_external_end();
  return rc;
}

int32_t memdbg_kernel_copyout_fast(intptr_t source, void *destination,
                                   size_t length) {
  if (source == 0 || destination == NULL || length == 0U) {
    errno = EINVAL;
    return -1;
  }
  if (!memdbg_kernel_fast_available()) {
    errno = ENOTSUP;
    return -1;
  }
  if (memdbg_kernel_external_begin() != 0) return -1;
  int rc = setup_pipe((uint64_t)source, 0);
  if (rc == 0) {
    long n = __crt_syscall(3, g_rwpipe[0], destination, length);
    rc = n == (long)length ? 0 : -1;
  }
  memdbg_kernel_external_end();
  return rc;
}

static intptr_t walk_allproc(pid_t pid) {
  intptr_t current = 0;
  if (memdbg_kernel_copyout_fast(KERNEL_ADDRESS_ALLPROC, &current,
                                 sizeof(current)) != 0)
    return 0;
  while (current != 0) {
    pid_t candidate = 0;
    intptr_t next = 0;
    if (memdbg_kernel_copyout_fast(
            current + KERNEL_OFFSET_PROC_P_PID, &candidate,
            sizeof(candidate)) != 0)
      return 0;
    if (candidate == pid) return current;
    if (memdbg_kernel_copyout_fast(current, &next, sizeof(next)) != 0)
      return 0;
    current = next;
  }
  return 0;
}

intptr_t memdbg_kernel_get_proc_fast(pid_t pid) {
  if (pid <= 0) return 0;
  intptr_t cached = 0;
  (void)pthread_mutex_lock(&g_cache_mutex);
  for (unsigned int i = 0; i < MEMDBG_FAST_PROC_CACHE; ++i) {
    if (g_proc_cache[i].pid == pid && g_proc_cache[i].address != 0) {
      cached = g_proc_cache[i].address;
      break;
    }
  }
  (void)pthread_mutex_unlock(&g_cache_mutex);
  if (cached != 0) {
    pid_t verify = 0;
    if (memdbg_kernel_copyout_fast(
            cached + KERNEL_OFFSET_PROC_P_PID, &verify,
            sizeof(verify)) == 0 && verify == pid)
      return cached;
    memdbg_kernel_proc_cache_invalidate(pid);
  }

  intptr_t address = walk_allproc(pid);
  if (address != 0) {
    (void)pthread_mutex_lock(&g_cache_mutex);
    unsigned int slot = g_proc_cache_next++ % MEMDBG_FAST_PROC_CACHE;
    g_proc_cache[slot].pid = pid;
    g_proc_cache[slot].address = address;
    (void)pthread_mutex_unlock(&g_cache_mutex);
  }
  return address;
}

void memdbg_kernel_proc_cache_flush(void) {
  (void)pthread_mutex_lock(&g_cache_mutex);
  memset(g_proc_cache, 0, sizeof(g_proc_cache));
  g_proc_cache_next = 0U;
  (void)pthread_mutex_unlock(&g_cache_mutex);
}

void memdbg_kernel_proc_cache_invalidate(pid_t pid) {
  (void)pthread_mutex_lock(&g_cache_mutex);
  for (unsigned int i = 0; i < MEMDBG_FAST_PROC_CACHE; ++i) {
    if (g_proc_cache[i].pid == pid) {
      g_proc_cache[i].pid = 0;
      g_proc_cache[i].address = 0;
    }
  }
  (void)pthread_mutex_unlock(&g_cache_mutex);
}

#else

int memdbg_kernel_fast_available(void) { return 0; }
int32_t memdbg_kernel_copyin_fast(const void *s, intptr_t d, size_t n) {
  (void)s; (void)d; (void)n; errno = ENOTSUP; return -1;
}
int32_t memdbg_kernel_copyout_fast(intptr_t s, void *d, size_t n) {
  (void)s; (void)d; (void)n; errno = ENOTSUP; return -1;
}
intptr_t memdbg_kernel_get_proc_fast(pid_t pid) { (void)pid; return 0; }
void memdbg_kernel_proc_cache_flush(void) {}
void memdbg_kernel_proc_cache_invalidate(pid_t pid) { (void)pid; }
int memdbg_kernel_external_begin(void) { return 0; }
void memdbg_kernel_external_end(void) {}

#endif
