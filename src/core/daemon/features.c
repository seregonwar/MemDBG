/*
 * memDBG - Extended daemon features: klog, auth, arena, bulk-write-advanced, ELF enhancements.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/core/memdbg_protocol.h"
#include "memdbg/core/region_match.h"
#include "memdbg/pal/pal_network.h"
#include "memdbg/pal/pal_memory.h"
#include "memdbg/pal/pal_notification.h"
#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/debug/memdbg_process.h"
#include "memdbg/privilege/privilege.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/mman.h>

// External declarations for feature helpers

extern int memdbg_privilege_jailbreak_self(void);
extern int memdbg_elf_load_enhanced(int pid, const uint8_t *elf, uint64_t elf_size,
                                    const char *region, uint32_t match_flags,
                                    uint64_t *entry, uint64_t *base);

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#include <ps5/kernel.h>
#endif

// Auth ceremony

static int g_auth_privileged = 0;

int memdbg_auth_handle(int fd, const memdbg_auth_key_request_t *req) {
  if (!req || req->magic != MEMDBG_AUTH_KEY_MAGIC) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000002u}, 4);
    return 1;
  }

  // Elevate payload privileges for debug operations
  int rc = memdbg_privilege_jailbreak_self();
  if (rc != 0) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000002u}, 4);
    return 1;
  }

  g_auth_privileged = 1;
  pal_socket_write_all(fd, &(uint32_t){0}, 4);
  return 0;
}

int memdbg_is_privileged(void) { return g_auth_privileged; }

// Arena memory sub-allocator

#define ARENA_ALIGN      0x4000ULL
#define ARENA_CHUNK      (16ULL * 1024 * 1024)
#define ARENA_MAX_PIDS   4

struct arena_seg { uint64_t base, size, used; struct arena_seg *next; };
struct arena_blk { uint64_t addr, size;       struct arena_blk *next; };

struct arena_pool {
  int               active;
  uint32_t          pid;
  struct arena_seg *segs;
  struct arena_blk *freelist;
};

static struct arena_pool g_arenas[ARENA_MAX_PIDS];
static int g_arena_on = 1;

static uint64_t arena_align(uint64_t n) {
  return (n + (ARENA_ALIGN - 1)) & ~(ARENA_ALIGN - 1);
}

static struct arena_pool *arena_for(uint32_t pid, int create) {
  int slot = -1;
  for (int i = 0; i < ARENA_MAX_PIDS; i++) {
    if (g_arenas[i].active && g_arenas[i].pid == pid) return &g_arenas[i];
    if (!g_arenas[i].active && slot < 0) slot = i;
  }
  if (!create || slot < 0) return NULL;

  // Reuse slot
  struct arena_pool *ap = &g_arenas[slot];
  for (struct arena_seg *s = ap->segs; s; ) {
    struct arena_seg *n = s->next; free(s); s = n;
  }
  for (struct arena_blk *b = ap->freelist; b; ) {
    struct arena_blk *n = b->next; free(b); b = n;
  }
  memset(ap, 0, sizeof(*ap));
  ap->active = 1;
  ap->pid    = pid;
  return ap;
}

static int arena_try_alloc(struct arena_pool *ap, uint64_t length, uint64_t *out) {
  uint64_t size = arena_align(length ? length : ARENA_ALIGN);

  // Check freelist first
  struct arena_blk **pp = &ap->freelist;
  for (struct arena_blk *b = ap->freelist; b; pp = &b->next, b = b->next) {
    if (b->size >= size) {
      if (b->size >= size + ARENA_ALIGN) {
        *out = b->addr; b->addr += size; b->size -= size;
      } else {
        *out = b->addr; *pp = b->next; free(b);
      }
      return 0;
    }
  }

  /* Check existing segments for room */
  for (struct arena_seg *s = ap->segs; s; s = s->next)
    if (s->size - s->used >= size) { *out = s->base + s->used; s->used += size; return 0; }

  // Allocate new segment
  uint64_t seg_size = (size > ARENA_CHUNK) ? size : ARENA_CHUNK;
  uint64_t base = 0;
  {
    int r = pal_memory_alloc((int)ap->pid, 0x4000, seg_size, 7, 0, &base);
    if (r != 0) return -1;
  }

  struct arena_seg *s = (struct arena_seg *)malloc(sizeof(*s));
  if (!s) { *out = base; return 0; }
  s->base = base; s->size = seg_size; s->used = size; s->next = ap->segs; ap->segs = s;
  *out = base;
  return 0;
}

static int arena_try_free(struct arena_pool *ap, uint64_t addr, uint64_t length) {
  int owned = 0;
  for (struct arena_seg *s = ap->segs; s; s = s->next)
    if (addr >= s->base && addr < s->base + s->size) { owned = 1; break; }
  if (!owned) return -1;

  uint64_t size = arena_align(length ? length : ARENA_ALIGN);
  struct arena_blk *b = (struct arena_blk *)malloc(sizeof(*b));
  if (b) { b->addr = addr; b->size = size; b->next = ap->freelist; ap->freelist = b; }
  return 0;
}

int memdbg_arena_config_handle(int fd, const memdbg_arena_config_request_t *req) {
  g_arena_on = req->enabled ? 1 : 0;
  pal_socket_write_all(fd, &(uint32_t){0}, 4);
  return 0;
}

int memdbg_arena_alloc_hinted(uint32_t pid, uint64_t *addr, uint64_t length, uint64_t hint) {
  int rc;
  if (g_arena_on && hint == 0x4000) {
    struct arena_pool *ap = arena_for(pid, 1);
    if (ap && arena_try_alloc(ap, length, addr) == 0) { rc = 0; goto done; }
  }
  rc = pal_memory_alloc((int)pid, hint, length, 7, 0, addr);
done:
  if (rc == 0) memdbg_process_maps_cache_flush((int)pid);
  return rc;
}

int memdbg_arena_free_hinted(uint32_t pid, uint64_t addr, uint64_t length) {
  int rc;
  if (g_arena_on) {
    struct arena_pool *ap = arena_for(pid, 0);
    if (ap && arena_try_free(ap, addr, length) == 0) { rc = 0; goto done; }
  }
  rc = pal_memory_free((int)pid, addr, length);
done:
  if (rc == 0) memdbg_process_maps_cache_flush((int)pid);
  return rc;
}

// Bulk write advanced

int memdbg_batch_write_adv_handle(int fd, const memdbg_batch_write_adv_request_t *req,
                                  const uint8_t *body, uint32_t body_len) {
  if (!req || req->count == 0 || req->count > MEMDBG_BATCH_WRITE_ADV_MAX_ENTRIES) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000002u}, 4);
    return 1;
  }

  int want_status = (req->flags & 1u) != 0;
  if (body_len < sizeof(*req)) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000002u}, 4);
    return 1;
  }

  pal_socket_write_all(fd, &(uint32_t){0}, 4);  // ack

  const uint8_t *cursor = body + sizeof(*req);
  const uint8_t *end    = body + body_len;
  uint8_t *status_array = want_status ? (uint8_t *)malloc(req->count) : NULL;

  for (uint32_t i = 0; i < req->count; i++) {
    if ((size_t)(end - cursor) < 12) break;

    uint64_t addr;
    uint32_t len;
    memcpy(&addr, cursor, 8);
    memcpy(&len,  cursor + 8, 4);
    cursor += 12;

    if (len > MEMDBG_BATCH_WRITE_ADV_MAX_ENTRY || (size_t)(end - cursor) < len)
      break;

    size_t written = 0;
    memdbg_memory_write(req->pid, addr, cursor, len, &written);

    if (status_array)
      status_array[i] = (written == len) ? 0 : 1;

    cursor += len;
  }

  if (status_array) {
    pal_socket_write_all(fd, status_array, req->count);
    free(status_array);
  }

  pal_socket_write_all(fd, &(uint32_t){0}, 4);  // CMD_SUCCESS
  return 0;
}

// Enhanced ELF loader with JIT shared memory

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#include <ps5/kernel.h>

static long remote_syscall(int pid, long no, long a, long b, long c,
                           long d, long e, long f) {
  (void)pid; (void)no; (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
  volatile long ret;
  __asm__ volatile(
    "mov %[no], %%rax\n"
    "mov %[a], %%rdi\n"
    "mov %[b], %%rsi\n"
    "mov %[c], %%rdx\n"
    "mov %[d], %%r10\n"
    "mov %[e], %%r8\n"
    "mov %[f], %%r9\n"
    "syscall\n"
    "mov %%rax, %[ret]\n"
    : [ret] "=r" (ret)
    : [no] "r" (no), [a] "r" (a), [b] "r" (b), [c] "r" (c),
      [d] "r" (d), [e] "r" (e), [f] "r" (f)
    : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "rcx", "r11", "memory"
  );
  return ret;
}

static int jit_shm_create(int pid, uint64_t size, int prot) {
  return (int)remote_syscall(pid, 0x215, (long)0, (long)size, (long)prot, 0, 0, 0);
}

static int jit_shm_alias(int pid, int shm_fd, int prot) {
  return (int)remote_syscall(pid, 0x216, (long)shm_fd, (long)prot, 0, 0, 0, 0);
}

int memdbg_elf_load_enhanced(int pid, const uint8_t *elf, uint64_t elf_size,
                             const char *target_region, uint32_t match_flags,
                             uint64_t *entry_out, uint64_t *base_out) {
  if (!elf || elf_size < 52 || elf[0] != 0x7F || elf[1] != 'E' ||
      elf[2] != 'L' || elf[3] != 'F') return -1;

  uint64_t e_entry = *(const uint64_t *)(elf + 0x18);
  uint64_t e_phoff = *(const uint64_t *)(elf + 0x20);
  uint64_t e_shoff = *(const uint64_t *)(elf + 0x28);
  uint16_t e_type  = *(const uint16_t *)(elf + 0x10);
  uint16_t e_phnum = *(const uint16_t *)(elf + 0x38);
  uint16_t e_shnum = *(const uint16_t *)(elf + 0x3C);

  if (e_phoff > elf_size || e_shoff > elf_size) return -1;

  const uint8_t *phdr_base = elf + e_phoff;
  const uint8_t *shdr_base = elf + e_shoff;

  // Compute address range
  uint64_t min_addr = ~0ULL, max_addr = 0;
  if (e_phnum) {
    for (uint16_t i = 0; i < e_phnum; i++) {
      const uint8_t *ph = phdr_base + (uint64_t)i * 56;
      uint32_t p_type  = *(const uint32_t *)(ph + 0);
      if (p_type != 1) continue;
      uint64_t p_memsz = *(const uint64_t *)(ph + 40);
      if (p_memsz == 0) continue;
      uint64_t p_vaddr = *(const uint64_t *)(ph + 16);
      if (p_vaddr < min_addr) min_addr = p_vaddr;
      uint64_t seg_end = p_vaddr + p_memsz;
      if (seg_end > max_addr) max_addr = seg_end;
    }
  }

  // Round to pages
  const uint64_t page_mask = 0x3FFFULL;
  uint64_t min_aligned = min_addr & ~page_mask;
  uint64_t total_size = ((max_addr + page_mask) & ~page_mask) - min_aligned;

  uint64_t base;
  int      use_existing_region = (target_region && target_region[0] != '\0');

  if (use_existing_region) {
    // Find the named VM region in the target process
    memdbg_map_list_t map_list;
    if (memdbg_process_maps(pid, &map_list) != 0)
      return -1;

    uint64_t region_base = 0, region_end = 0;
    for (size_t i = 0; i < map_list.count; i++) {
      if (region_name_matches(map_list.entries[i].name, target_region, match_flags)) {
        region_base = map_list.entries[i].start;
        region_end  = map_list.entries[i].end;
        break;
      }
    }
    memdbg_process_maps_free(&map_list);

    if (region_base == 0 || region_end <= region_base)
      return -1;

    uint64_t available = region_end - region_base;
    if (total_size > available)
      return -1;

    base = region_base + min_aligned;
  } else {
    // Allocate new memory in target
    int mmap_flags = (e_type == 2) ? 0x1012 : 0x1002;
    uint64_t base_request = (e_type == 2) ? min_aligned : 0;
    void *base_p = (void *)(uintptr_t)base_request;
    int rc = pal_memory_alloc(pid, base_request, total_size, 0,
                              (uint32_t)mmap_flags, (uint64_t *)&base_p);
    if (rc != 0) return -1;
    base = (uint64_t)(uintptr_t)base_p;
  }

  // Load segments
  if (e_phnum) {
    for (uint16_t i = 0; i < e_phnum; i++) {
      const uint8_t *ph = phdr_base + (uint64_t)i * 56;
      uint32_t p_type = *(const uint32_t *)(ph + 0);
      if (p_type != 1) continue;
      uint64_t p_memsz  = *(const uint64_t *)(ph + 40);
      if (p_memsz == 0) continue;
      uint32_t p_flags  = *(const uint32_t *)(ph + 4);
      uint64_t p_offset = *(const uint64_t *)(ph + 8);
      uint64_t p_vaddr  = *(const uint64_t *)(ph + 16);

      int seg_prot = ((p_flags & 1) ? 4 : 0) |
                     ((p_flags & 2) ? 2 : 0) |
                     ((p_flags & 4) ? 1 : 0);
      uint64_t aligned_sz = (p_memsz + page_mask) & ~page_mask;
      uint64_t tgt_addr   = base + p_vaddr;

      if ((p_flags & 1) && !use_existing_region) {
        // Executable (new allocation): use JIT shared memory
        int shm_fd = jit_shm_create(pid, aligned_sz, ((p_flags >> 2) & 1) | 6);
        if (shm_fd < 0) continue;

        void *exe_p = (void *)(uintptr_t)tgt_addr;
        pal_memory_alloc(pid, tgt_addr, aligned_sz, (uint32_t)seg_prot,
                         0x11, (uint64_t *)&exe_p);
        if ((uint64_t)(uintptr_t)exe_p != tgt_addr) return -1;

        int alias_fd = jit_shm_alias(pid, shm_fd, 3);
        if (alias_fd < 0) return -1;

        void *rw_p = NULL;
        pal_memory_alloc(pid, 0, aligned_sz, 3, 1,
                         (uint64_t *)(uintptr_t)&rw_p);

        size_t wb = 0;
        memdbg_memory_write(pid, (uint64_t)(uintptr_t)rw_p,
                            elf + p_offset, p_memsz, &wb);

        pal_memory_free(pid, (uint64_t)(uintptr_t)rw_p, aligned_sz);
      } else {
        // Non-executable or existing region: direct write
        uint32_t old_prot = 0;
        if (use_existing_region && (p_flags & 1))
          pal_memory_protect(pid, tgt_addr, aligned_sz, 7, &old_prot);

        size_t wb = 0;
        memdbg_memory_write(pid, tgt_addr, elf + p_offset, p_memsz, &wb);

        if (use_existing_region && (p_flags & 1) && wb != p_memsz) {
          pal_memory_protect(pid, tgt_addr, aligned_sz, old_prot, NULL);
          return -1;
        }
        if (use_existing_region && (p_flags & 1))
          pal_memory_protect(pid, tgt_addr, aligned_sz, old_prot, NULL);
      }
    }
  }

  // Apply RELA relocations
  if (e_shnum) {
    for (uint16_t i = 0; i < e_shnum; i++) {
      const uint8_t *sh = shdr_base + (uint64_t)i * 64;
      uint32_t sh_type = *(const uint32_t *)(sh + 4);
      if (sh_type != 4) continue;
      uint64_t sh_size   = *(const uint64_t *)(sh + 0x20);
      if (sh_size < 24) continue;
      uint64_t sh_offset = *(const uint64_t *)(sh + 0x18);
      const uint8_t *rela_base = elf + sh_offset;
      uint64_t n_rela = sh_size / 24;

      for (uint64_t j = 0; j < n_rela; j++) {
        const uint8_t *r = rela_base + j * 24;
        uint32_t r_type = *(const uint32_t *)(r + 8);
        if (r_type != 8) continue; // R_X86_64_RELATIVE
        uint64_t r_offset = *(const uint64_t *)(r + 0);
        uint64_t r_addend = *(const uint64_t *)(r + 16);
        uint64_t target   = base + r_offset;
        uint64_t value    = base + r_addend;
        size_t wb = 0;
        memdbg_memory_write(pid, target, &value, 8, &wb);
      }
    }
  }

  // Fix segment protections after loading
  if (e_phnum) {
    for (uint16_t i = 0; i < e_phnum; i++) {
      const uint8_t *ph = phdr_base + (uint64_t)i * 56;
      uint32_t p_type = *(const uint32_t *)(ph + 0);
      if (p_type != 1) continue;
      uint64_t p_memsz = *(const uint64_t *)(ph + 40);
      if (p_memsz == 0) continue;
      uint32_t p_flags  = *(const uint32_t *)(ph + 4);
      uint64_t p_vaddr  = *(const uint64_t *)(ph + 16);
      uint64_t aligned_sz = (p_memsz + page_mask) & ~page_mask;
      uint64_t tgt_addr   = base + p_vaddr;
      int seg_prot = ((p_flags & 1) ? 4 : 0) |
                     ((p_flags & 2) ? 2 : 0) |
                     ((p_flags & 4) ? 1 : 0);
      pal_memory_protect(pid, tgt_addr, aligned_sz, (uint32_t)seg_prot, NULL);
    }
  }

  if (entry_out) *entry_out = base + e_entry;
  if (base_out)  *base_out  = base;
  memdbg_process_maps_cache_flush(pid);
  return 0;
}

#else /* !PS5 */

int memdbg_elf_load_enhanced(int pid, const uint8_t *elf, uint64_t elf_size,
                             const char *target_region, uint32_t match_flags,
                             uint64_t *entry_out, uint64_t *base_out) {
  (void)pid; (void)elf; (void)elf_size; (void)target_region; (void)match_flags;
  if (entry_out) *entry_out = 0;
  if (base_out)  *base_out  = 0;
  return -1;
}

#endif

// Klog streaming server

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
static int g_klog_listen_fd = -1;

static void *klog_server_thread(void *arg) {
  (void)arg;

  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0) return NULL;

  int one = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_port        = htons(0xA00C);
  sa.sin_addr.s_addr = INADDR_ANY;

  if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    close(srv);
    return NULL;
  }
  if (listen(srv, 5) < 0) {
    close(srv);
    return NULL;
  }

  g_klog_listen_fd = srv;

  char rbuf[4096];
  for (;;) {
    int conn = accept(srv, NULL, NULL);
    if (conn < 0) break;

    int klog_fd = open("/dev/klog", O_RDONLY);
    if (klog_fd < 0) {
      write(conn, "Cannot open /dev/klog\n", 22);
      close(conn);
      continue;
    }

    write(conn, "Klog streaming started\n", 23);

    for (;;) {
      struct timespec ts = {0, 100000000L};
      nanosleep(&ts, NULL);

      int err_val = 0;
      socklen_t err_len = sizeof(err_val);
      if (getsockopt(conn, SOL_SOCKET, SO_ERROR, &err_val, &err_len) < 0 ||
          err_val != 0)
        break;

      ssize_t n = read(klog_fd, rbuf, sizeof(rbuf) - 1);
      if (n > 0) {
        rbuf[n] = 0;
        if (write(conn, rbuf, (size_t)(n + 1)) != n + 1)
          break;
      }
    }

    close(klog_fd);
    close(conn);
  }

  close(srv);
  g_klog_listen_fd = -1;
  return NULL;
}

int memdbg_klog_start(pthread_t *out_tid) {
  if (g_klog_listen_fd >= 0) return 0; // already running

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  int rc = pthread_create(out_tid, &attr, klog_server_thread, NULL);
  pthread_attr_destroy(&attr);
  return rc;
}

void memdbg_klog_stop(void) {
  if (g_klog_listen_fd >= 0) {
    shutdown(g_klog_listen_fd, SHUT_RDWR);
    close(g_klog_listen_fd);
    g_klog_listen_fd = -1;
  }
}

#else

int memdbg_klog_start(pthread_t *out_tid) {
  (void)out_tid;
  return -1;
}
void memdbg_klog_stop(void) {}

#endif

// Broadcast beacon

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)

static int g_beacon_fd = -1;

static void *beacon_thread(void *arg) {
  (void)arg;

  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) return NULL;

  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_port        = htons(0x3F2);
  sa.sin_addr.s_addr = INADDR_ANY;

  if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    close(s);
    return NULL;
  }

  g_beacon_fd = s;

  for (;;) {
    uint32_t magic = 0;
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);

    ssize_t n = recvfrom(s, &magic, sizeof(magic), 0,
                         (struct sockaddr *)&peer, &peer_len);
    if (n < 0) break;

    if (magic == 0xFFFFAAAAu) {
      sendto(s, &magic, sizeof(magic), 0,
             (const struct sockaddr *)&peer, peer_len);
    }
  }

  close(s);
  g_beacon_fd = -1;
  return NULL;
}

int memdbg_beacon_start(pthread_t *out_tid) {
  if (g_beacon_fd >= 0) return 0;

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  int rc = pthread_create(out_tid, &attr, beacon_thread, NULL);
  pthread_attr_destroy(&attr);
  return rc;
}

void memdbg_beacon_stop(void) {
  if (g_beacon_fd >= 0) {
    shutdown(g_beacon_fd, SHUT_RDWR);
    close(g_beacon_fd);
    g_beacon_fd = -1;
  }
}

#else

int memdbg_beacon_start(pthread_t *out_tid) {
  (void)out_tid;
  return -1;
}
void memdbg_beacon_stop(void) {}

#endif

// Hijack mode: inject payload without blocking the caller

struct hijack_ctx {
  int            pid;
  uint8_t       *elf_data;
  uint64_t       elf_size;
  uint32_t       flags;
  uint32_t       match_flags;
  char           target_region[44];
  volatile int   done;
  int            result;
  uint64_t       entry;
  uint64_t       base;
};

static void *hijack_thread(void *arg) {
  struct hijack_ctx *ctx = (struct hijack_ctx *)arg;

  const char *region = ctx->target_region[0] ? ctx->target_region : NULL;
  ctx->result = memdbg_elf_load_enhanced(
      ctx->pid, ctx->elf_data, ctx->elf_size, region, ctx->match_flags,
      &ctx->entry, &ctx->base);

  ctx->done = 1;
  free(ctx->elf_data);
  free(ctx);
  return NULL;
}

int memdbg_hijack_handle(int fd, const memdbg_process_hijack_request_t *req,
                         const uint8_t *body, uint32_t body_len) {
  if (!req || req->payload_size == 0 || req->payload_size > (64ULL << 20)) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000002u}, 4);
    return 1;
  }

  if (body_len < sizeof(*req) + req->payload_size) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000002u}, 4);
    return 1;
  }

  if (req->pid <= 1) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000002u}, 4);
    return 1;
  }

  // Copy ELF data so the caller can be released immediately
  const uint8_t *elf_src = body + sizeof(*req);
  uint8_t *elf_copy = (uint8_t *)malloc((size_t)req->payload_size);
  if (!elf_copy) {
    pal_socket_write_all(fd, &(uint32_t){0xF0000003u}, 4);
    return 1;
  }
  memcpy(elf_copy, elf_src, (size_t)req->payload_size);

  struct hijack_ctx *ctx = (struct hijack_ctx *)calloc(1, sizeof(*ctx));
  if (!ctx) {
    free(elf_copy);
    pal_socket_write_all(fd, &(uint32_t){0xF0000003u}, 4);
    return 1;
  }

  ctx->pid         = req->pid;
  ctx->elf_data    = elf_copy;
  ctx->elf_size    = req->payload_size;
  ctx->flags       = req->flags;
  ctx->match_flags = req->match_flags;
  memcpy(ctx->target_region, req->target_region, sizeof(ctx->target_region));
  ctx->target_region[sizeof(ctx->target_region) - 1] = '\0';
  ctx->done      = 0;
  ctx->result    = -1;

  pthread_t tid;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  int rc = pthread_create(&tid, &attr, hijack_thread, ctx);
  pthread_attr_destroy(&attr);

  if (rc != 0) {
    free(elf_copy);
    free(ctx);
    pal_socket_write_all(fd, &(uint32_t){0xF0000003u}, 4);
    return 1;
  }

  // Reply immediately — injection proceeds in background
  memdbg_process_hijack_response_t resp;
  resp.accepted = 1;
  resp.reserved = 0;
  pal_socket_write_all(fd, &resp, sizeof(resp));
  return 0;
}
