/*
 * memDBG - Page-table walker implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Direct page-table introspection for DMAP discovery, PT enumeration,
 * augmented VM maps, and direct physical memory access.
 *
 * This module relies on kernel_copyout/kernel_copyin for kernel
 * memory access and kernel_get_proc for the process structure.
 */

#include "memdbg/scanner/pt_walker.h"
#include "memdbg/pal/pal_kernel_fast.h"
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>

/* Forward declarations for PS5 kernel copy wrappers. */
#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
static int kread(intptr_t kaddr, void *dst, size_t n);
static int kwrite(const void *src, intptr_t kaddr, size_t n);
#endif
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

// Platform abstraction: kernel memory access

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#include <ps5/kernel.h>
#include <pthread.h>
#define PTW_HAS_DMAP 1
#endif

#if !defined(PTW_HAS_DMAP)
#define PTW_HAS_DMAP 0
#endif

#if PTW_HAS_DMAP

// Constants

#define PTW_PHYS_MASK     0x000FFFFFFFFFF000ULL
#define PTW_PHYS_BOUND    0x1000000000ULL
#define PTW_CANON_KERNEL  0x1FFFFULL

#define PTW_PTE_PRESENT   0x1ULL
#define PTW_PTE_RW        0x2ULL
#define PTW_PTE_PS        0x80ULL
#define PTW_PTE_NX        0x8000000000000000ULL
#define PTW_PTE_PCD       0x10ULL

#define PTW_USER_PML4_LIMIT  256
#define PTW_MAX_ENTRIES      16384

#define PTW_PROC_VMSPACE_OFF 0x200ULL
#define PTW_PMAP_OFF_KNOWN   0x300ULL
#define PTW_VMSPACE_SCAN_END 0x400ULL

// Static cache

static volatile uint64_t g_ptw_known_value = 0x5E7C0DE5E7C0DE71ULL;

static _Atomic int      g_ptw_state     = 0;
static _Atomic uint64_t g_ptw_dmap      = 0;
static _Atomic uint64_t g_ptw_pmap_off  = 0;
static pthread_mutex_t g_ptw_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

// Per-PID vmspace+cr3 cache (avoids 2 kernel reads per ptw_read/write/probe call)
#define PTW_VMCACHE_N 4
static struct { int32_t pid; uint64_t kproc; uint64_t vmspace; uint64_t pml4; uint64_t cr3; } g_vmcache[PTW_VMCACHE_N];
static int g_vmcache_next = 0;

static int ptw_resolve_pid(uint32_t pid, uint64_t *out_cr3) {
  (void)pthread_mutex_lock(&g_ptw_cache_mutex);
  for (int i = 0; i < PTW_VMCACHE_N; i++) {
    if (g_vmcache[i].pid == (int32_t)pid && g_vmcache[i].cr3 != 0) {
      *out_cr3 = g_vmcache[i].cr3;
      (void)pthread_mutex_unlock(&g_ptw_cache_mutex);
      return 0;
    }
  }

  intptr_t kproc = memdbg_kernel_fast_available()
                       ? memdbg_kernel_get_proc_fast((pid_t)pid)
                       : (intptr_t)kernel_get_proc((pid_t)pid);
  if (!kproc) goto fail;

  uint64_t vmspace = 0;    if (kread(kproc + (intptr_t)PTW_PROC_VMSPACE_OFF, &vmspace, 8) != 0 || !vmspace)
    goto fail;

  uint64_t pair[2];
  if (kread((intptr_t)(vmspace + g_ptw_pmap_off), pair, sizeof(pair)) != 0)
    goto fail;

  uint64_t cr3 = pair[1];
  if (cr3 == 0 || (cr3 & 0xFFF) || cr3 >= PTW_PHYS_BOUND) goto fail;
  if (pair[0] - cr3 != g_ptw_dmap) goto fail;

  int s = g_vmcache_next;
  g_vmcache[s].pid     = (int32_t)pid;
  g_vmcache[s].kproc   = (uint64_t)kproc;
  g_vmcache[s].vmspace = vmspace;
  g_vmcache[s].pml4    = pair[0];
  g_vmcache[s].cr3     = cr3;
  g_vmcache_next = (g_vmcache_next + 1) % PTW_VMCACHE_N;
  *out_cr3 = cr3;
  (void)pthread_mutex_unlock(&g_ptw_cache_mutex);
  return 0;
fail:
  (void)pthread_mutex_unlock(&g_ptw_cache_mutex);
  return 1;
}

// Minimal kernel copy wrappers

static inline int kread(intptr_t kaddr, void *dst, size_t n) {
  if (memdbg_kernel_fast_available())
    return memdbg_kernel_copyout_fast(kaddr, dst, n) == 0 ? 0 : -1;
  if (kernel_copyout(kaddr, dst, n) != 0) return -1;
  return 0;
}

static inline int kwrite(const void *src, intptr_t kaddr, size_t n) {
  if (memdbg_kernel_fast_available())
    return memdbg_kernel_copyin_fast(src, kaddr, n) == 0 ? 0 : -1;
  if (kernel_copyin(src, kaddr, n) != 0) return -1;
  return 0;
}

// Virtual to physical using known DMAP

static uint64_t ptw_va_to_phys(uint64_t dmap, uint64_t cr3, uint64_t va) {
  uint64_t table = cr3 & PTW_PHYS_MASK;
  for (int level = 0; level < 4; level++) {
    if (table >= PTW_PHYS_BOUND) return 0;
    int      shift = 39 - level * 9;
    uint64_t idx   = (va >> shift) & 0x1FF;
    uint64_t e     = 0;
    if (kread((intptr_t)(dmap + table + idx * 8), &e, 8) != 0) return 0;
    if (!(e & PTW_PTE_PRESENT)) return 0;
    if (level == 3)
      return (e & PTW_PHYS_MASK) | (va & 0xFFF);
    if ((level == 1 || level == 2) && (e & PTW_PTE_PS)) {
      uint64_t pgmask = (level == 1) ? ((1ULL << 30) - 1) : ((1ULL << 21) - 1);
      return ((e & PTW_PHYS_MASK) & ~pgmask) | (va & pgmask);
    }
    table = e & PTW_PHYS_MASK;
  }
  return 0;
}

// Walk one leaf level for a VA

static int ptw_walk_leaf_inner(uint64_t dmap, uint64_t cr3, uint64_t va,
                               uint64_t *out_e, int *out_level) {
  uint64_t table = cr3 & PTW_PHYS_MASK;
  for (int level = 0; level < 4; level++) {
    if (table >= PTW_PHYS_BOUND) { if(out_e) *out_e = 0; if(out_level) *out_level = level; return 1; }
    int      shift = 39 - level * 9;
    uint64_t idx   = (va >> shift) & 0x1FF;
    uint64_t e     = 0;
    if (kread((intptr_t)(dmap + table + idx * 8), &e, 8) != 0)
      { if(out_e) *out_e = 0; if(out_level) *out_level = level; return 1; }
    if (!(e & PTW_PTE_PRESENT)) { if(out_e) *out_e = e; if(out_level) *out_level = level; return 1; }
    if (level == 3) { if(out_e) *out_e = e; if(out_level) *out_level = 3; return 0; }
    if ((level == 1 || level == 2) && (e & PTW_PTE_PS))
      { if(out_e) *out_e = e; if(out_level) *out_level = level; return 0; }
    table = e & PTW_PHYS_MASK;
  }
  if(out_e) *out_e = 0; if(out_level) *out_level = -1;
  return 1;
}

// DMAP discovery

static uint64_t ptw_try_offset(uint64_t vmspace, uint64_t off,
                               uint64_t verify_va, uint64_t verify_val) {
  uint64_t pair[2];
  if (kread((intptr_t)(vmspace + off), pair, sizeof(pair)) != 0) return 0;

  uint64_t pml4_va = pair[0];
  uint64_t cr3     = pair[1];

  if ((pml4_va >> 47) != PTW_CANON_KERNEL) return 0;
  if (pml4_va & 0xFFF)                     return 0;
  if (cr3 == 0 || (cr3 & 0xFFF))           return 0;
  if (cr3 >= PTW_PHYS_BOUND)               return 0;

  uint64_t dmap = pml4_va - cr3;
  if (dmap & 0xFFFFFFFFULL)                return 0;
  if ((dmap >> 47) != PTW_CANON_KERNEL)    return 0;

  uint64_t phys = ptw_va_to_phys(dmap, cr3, verify_va);
  if (phys == 0) return 0;

  uint64_t probe = 0;
  if (kread((intptr_t)(dmap + phys), &probe, 8) != 0) return 0;
  if (probe != verify_val) return 0;

  return dmap;
}

int ptw_discover(uint64_t *dmap_base_out, uint64_t *pmap_offset_out) {
  (void)pthread_mutex_lock(&g_ptw_cache_mutex);
  if (g_ptw_state != 0) {
    if (dmap_base_out) *dmap_base_out = g_ptw_dmap;
    if (pmap_offset_out) *pmap_offset_out = g_ptw_pmap_off;
    int rc = (g_ptw_state == 1) ? 0 : -1;
    (void)pthread_mutex_unlock(&g_ptw_cache_mutex);
    return rc;
  }

  int result = -1;
  pid_t self = getpid();
  intptr_t kproc = memdbg_kernel_fast_available()
                       ? memdbg_kernel_get_proc_fast(self)
                       : (intptr_t)kernel_get_proc(self);
  if (kproc) {
    uint64_t vmspace = 0;
    if (kread(kproc + (intptr_t)PTW_PROC_VMSPACE_OFF, &vmspace, 8) == 0 && vmspace) {
      uint64_t verify_va  = (uint64_t)(uintptr_t)&g_ptw_known_value;
      uint64_t verify_val = g_ptw_known_value;

      uint64_t found_off = PTW_PMAP_OFF_KNOWN;
      uint64_t dmap = ptw_try_offset(vmspace, found_off, verify_va, verify_val);
      if (!dmap) {
        for (uint64_t off = 0x100; off + 16 <= PTW_VMSPACE_SCAN_END; off += 8) {
          if (off == PTW_PMAP_OFF_KNOWN) continue;
          dmap = ptw_try_offset(vmspace, off, verify_va, verify_val);
          if (dmap) { found_off = off; break; }
        }
      }
      if (dmap) {
        g_ptw_dmap     = dmap;
        g_ptw_pmap_off = found_off;
        result = 1;
      }
    }
  }

  g_ptw_state = result;
  if (dmap_base_out) *dmap_base_out = g_ptw_dmap;
  if (pmap_offset_out) *pmap_offset_out = g_ptw_pmap_off;
  (void)pthread_mutex_unlock(&g_ptw_cache_mutex);
  return (result == 1) ? 0 : -1;
}

int ptw_is_available(void) {
  if (g_ptw_state == 0) {
    uint64_t d, o;
    ptw_discover(&d, &o);
  }
  return (g_ptw_state == 1);
}

uint64_t ptw_dmap_base(void) { return g_ptw_dmap; }

// Physical address resolution

int ptw_probe(uint32_t pid, uint64_t va,
              uint64_t *phys_out, int *level_out,
              uint64_t *pagesize_out, uint64_t *pte_out) {
  if ((int32_t)pid <= 0) return 1;
  if (!ptw_is_available()) return 1;

  uint64_t cr3;
  if (ptw_resolve_pid(pid, &cr3) != 0) return 1;

  uint64_t e  = 0;
  int      lv = -1;
  if (ptw_walk_leaf_inner(g_ptw_dmap, cr3, va, &e, &lv) != 0) return 1;
  if (!(e & PTW_PTE_PRESENT)) return 1;

  uint64_t pgsz = (lv == 3) ? 0x1000ULL
                : (lv == 2) ? 0x200000ULL
                : (lv == 1) ? 0x40000000ULL : 0;
  if (!pgsz) return 1;

  uint64_t mask = pgsz - 1;
  if (phys_out)     *phys_out     = ((e & PTW_PHYS_MASK) & ~mask) + (va & mask);
  if (level_out)    *level_out    = lv;
  if (pagesize_out) *pagesize_out = pgsz;
  if (pte_out)      *pte_out      = e;
  return 0;
}

int ptw_span_resolve(uint32_t pid, uint64_t span_2m, int *is_huge,
                     uint64_t *phys_base, uint64_t *leaf_pt_kaddr,
                     uint64_t *pte_out) {
  if ((int32_t)pid <= 0) return 1;
  if (!ptw_is_available()) return 1;

  uint64_t cr3;
  if (ptw_resolve_pid(pid, &cr3) != 0) return 1;

  uint64_t table = cr3 & PTW_PHYS_MASK;
  for (int level = 0; level < 3; level++) {
    if (table >= PTW_PHYS_BOUND) return 1;
    int      shift = 39 - level * 9;
    uint64_t idx   = (span_2m >> shift) & 0x1FF;
    uint64_t e     = 0;
    if (kread((intptr_t)(g_ptw_dmap + table + idx * 8), &e, 8) != 0)
      return 1;
    if (!(e & PTW_PTE_PRESENT)) return 1;
    if ((level == 1 || level == 2) && (e & PTW_PTE_PS)) {
      uint64_t pgsz = (level == 1) ? (1ULL << 30) : (1ULL << 21);
      uint64_t base = (e & PTW_PHYS_MASK) & ~(pgsz - 1);
      if (is_huge)        *is_huge        = 1;
      if (phys_base)      *phys_base      = base + (span_2m & (pgsz - 1));
      if (pte_out)        *pte_out        = e;
      if (leaf_pt_kaddr)  *leaf_pt_kaddr  = 0;
      return 0;
    }
    table = e & PTW_PHYS_MASK;
  }
  if (table >= PTW_PHYS_BOUND) return 1;
  if (is_huge)        *is_huge        = 0;
  if (leaf_pt_kaddr)  *leaf_pt_kaddr  = g_ptw_dmap + table;
  if (phys_base)      *phys_base      = 0;
  if (pte_out)        *pte_out        = 0;
  return 0;
}

int ptw_leaf_addr(uint32_t pid, uint64_t va,
                  uint64_t *pte_kaddr_out, uint64_t *pte_val_out,
                  int *level_out) {
  if ((int32_t)pid <= 0) return 1;
  if (!ptw_is_available()) return 1;

  uint64_t cr3;
  if (ptw_resolve_pid(pid, &cr3) != 0) return 1;

  uint64_t table = cr3 & PTW_PHYS_MASK;
  for (int level = 0; level < 4; level++) {
    if (table >= PTW_PHYS_BOUND) return 1;
    int      shift     = 39 - level * 9;
    uint64_t idx       = (va >> shift) & 0x1FF;
    uint64_t ent_kaddr = g_ptw_dmap + table + idx * 8;
    uint64_t e = 0;
    if (kread((intptr_t)ent_kaddr, &e, 8) != 0) return 1;

    if (level == 3) {
      if (pte_kaddr_out) *pte_kaddr_out = ent_kaddr;
      if (pte_val_out)   *pte_val_out   = e;
      if (level_out)     *level_out     = 3;
      return 0;
    }
    if (!(e & PTW_PTE_PRESENT)) return 2;
    if ((level == 1 || level == 2) && (e & PTW_PTE_PS)) return 3;
    table = e & PTW_PHYS_MASK;
  }
  return 1;
}

// Direct DMAP read/write

int ptw_read(uint32_t pid, uint64_t va, uint64_t len, void *dst) {
  if ((int32_t)pid <= 0 || !dst || len == 0) return 1;
  if (!ptw_is_available()) return 1;

  uint64_t cr3;
  if (ptw_resolve_pid(pid, &cr3) != 0) return 1;

  uint8_t *out  = (uint8_t *)dst;
  uint64_t done = 0;
  uint64_t batch_phys = 0, batch_len = 0, batch_va_end = 0;

  while (done < len) {
    uint64_t cur_va = va + done;
    uint64_t e  = 0;
    int      lv = -1;
    if (ptw_walk_leaf_inner(g_ptw_dmap, cr3, cur_va, &e, &lv) != 0) return 1;

    uint64_t pgsz;
    if      (lv == 3) pgsz = 0x1000ULL;
    else if (lv == 2) pgsz = 0x200000ULL;
    else if (lv == 1) pgsz = 0x40000000ULL;
    else return 1;

    uint64_t page_mask   = pgsz - 1;
    uint64_t off_in_page = cur_va & page_mask;
    uint64_t phys        = ((e & PTW_PHYS_MASK) & ~page_mask) + off_in_page;

    uint64_t n = len - done;
    uint64_t avail = pgsz - off_in_page;
    if (n > avail) n = avail;

    if (phys >= PTW_PHYS_BOUND || phys + n > PTW_PHYS_BOUND) return 1;

    if (batch_len > 0 && phys == batch_phys + batch_len &&
        cur_va == batch_va_end) {
      batch_len += n;
      batch_va_end = cur_va + n;
    } else {
      if (batch_len > 0) {
        if (kread((intptr_t)(g_ptw_dmap + batch_phys), out + done - batch_len, batch_len) != 0)
          return 1;
      }
      batch_phys   = phys;
      batch_len    = n;
      batch_va_end = cur_va + n;
    }
    done += n;
  }
  if (batch_len > 0) {
    if (kread((intptr_t)(g_ptw_dmap + batch_phys), out + done - batch_len, batch_len) != 0)
      return 1;
  }
  return 0;
}

int ptw_write(uint32_t pid, uint64_t va, uint64_t len, const void *src) {
  if ((int32_t)pid <= 0 || !src || len == 0) return 1;
  if (!ptw_is_available()) return 1;

  uint64_t cr3;
  if (ptw_resolve_pid(pid, &cr3) != 0) return 1;

  const uint8_t *in = (const uint8_t *)src;
  uint64_t done = 0, batch_phys = 0, batch_len = 0, batch_va_end = 0;
  while (done < len) {
    uint64_t cur_va = va + done;
    uint64_t e  = 0;
    int      lv = -1;
    if (ptw_walk_leaf_inner(g_ptw_dmap, cr3, cur_va, &e, &lv) != 0) return 1;

    uint64_t pgsz;
    if      (lv == 3) pgsz = 0x1000ULL;
    else if (lv == 2) pgsz = 0x200000ULL;
    else if (lv == 1) pgsz = 0x40000000ULL;
    else return 1;

    uint64_t page_mask   = pgsz - 1;
    uint64_t off_in_page = cur_va & page_mask;
    uint64_t phys        = ((e & PTW_PHYS_MASK) & ~page_mask) + off_in_page;

    uint64_t n = len - done;
    uint64_t avail = pgsz - off_in_page;
    if (n > avail) n = avail;

    if (phys >= PTW_PHYS_BOUND || phys + n > PTW_PHYS_BOUND) return 1;

    if (batch_len > 0 && phys == batch_phys + batch_len &&
        cur_va == batch_va_end) {
      batch_len += n;
      batch_va_end = cur_va + n;
    } else {
      if (batch_len > 0) {
        if (kwrite(in + done - batch_len, (intptr_t)(g_ptw_dmap + batch_phys), batch_len) != 0)
          return 1;
      }
      batch_phys   = phys;
      batch_len    = n;
      batch_va_end = cur_va + n;
    }
    done += n;
  }
  if (batch_len > 0) {
    if (kwrite(in + done - batch_len, (intptr_t)(g_ptw_dmap + batch_phys), batch_len) != 0)
      return 1;
  }
  return 0;
}

// PT protection conversion

static uint16_t ptw_prot_from_pte(uint64_t pte) {
  uint16_t prot = 1U;
  if (pte & PTW_PTE_RW)    prot |= 2U;
  if (!(pte & PTW_PTE_NX)) prot |= 4U;
  return prot;
}

// Coalesced entry builder for PT enumeration

struct ptw_coal {
  memdbg_map_entry_t *ents;
  int      n;
  int      have;
  uint64_t cur_start;
  uint64_t cur_end;
  uint16_t cur_prot;
};

static void ptw_coal_flush(struct ptw_coal *c) {
  if (!c->have || c->n >= PTW_MAX_ENTRIES) return;
  memdbg_map_entry_t *o = &c->ents[c->n];
  memset(o, 0, sizeof(*o));
  o->start      = c->cur_start;
  o->end        = c->cur_end;
  o->protection = c->cur_prot;
  memcpy(o->name, "(ptaux)", 7);
  c->n++;
}

static void ptw_coal_emit(struct ptw_coal *c,
                          uint64_t start, uint64_t end, uint64_t pte) {
  uint16_t prot = ptw_prot_from_pte(pte);
  if (c->have && start == c->cur_end && prot == c->cur_prot) {
    c->cur_end = end;
    return;
  }
  ptw_coal_flush(c);
  c->have      = 1;
  c->cur_start = start;
  c->cur_end   = end;
  c->cur_prot  = prot;
}

// Full PT enumeration

static int ptw_enumerate(uint64_t cr3,
                         memdbg_map_entry_t **out, int *out_count) {
  uint64_t *pml4 = (uint64_t *)malloc(4096);
  uint64_t *pdpt = (uint64_t *)malloc(4096);
  uint64_t *pd   = (uint64_t *)malloc(4096);
  uint64_t *pt   = (uint64_t *)malloc(4096);
  struct ptw_coal c;
  memset(&c, 0, sizeof(c));
  c.ents = (memdbg_map_entry_t *)malloc(
      (size_t)PTW_MAX_ENTRIES * sizeof(memdbg_map_entry_t));

  if (!pml4 || !pdpt || !pd || !pt || !c.ents) {
    free(pml4); free(pdpt); free(pd); free(pt); free(c.ents);
    return 1;
  }

  uint64_t pml4_phys = cr3 & PTW_PHYS_MASK;
  if (pml4_phys >= PTW_PHYS_BOUND ||
      kread((intptr_t)(g_ptw_dmap + pml4_phys), pml4, 4096) != 0) {
    free(pml4); free(pdpt); free(pd); free(pt); free(c.ents);
    return 1;
  }

  for (int i = 0; i < PTW_USER_PML4_LIMIT && c.n < PTW_MAX_ENTRIES; i++) {
    uint64_t e4 = pml4[i];
    if (!(e4 & PTW_PTE_PRESENT)) continue;
    uint64_t p3 = e4 & PTW_PHYS_MASK;
    if (p3 >= PTW_PHYS_BOUND) continue;
    if (kread((intptr_t)(g_ptw_dmap + p3), pdpt, 4096) != 0) continue;

    for (int j = 0; j < 512 && c.n < PTW_MAX_ENTRIES; j++) {
      uint64_t e3  = pdpt[j];
      if (!(e3 & PTW_PTE_PRESENT)) continue;
      uint64_t va3 = ((uint64_t)i << 39) | ((uint64_t)j << 30);
      if (e3 & PTW_PTE_PS) {
        ptw_coal_emit(&c, va3, va3 + (1ULL << 30), e3);
        continue;
      }
      uint64_t p2 = e3 & PTW_PHYS_MASK;
      if (p2 >= PTW_PHYS_BOUND) continue;
      if (kread((intptr_t)(g_ptw_dmap + p2), pd, 4096) != 0) continue;

      for (int k = 0; k < 512 && c.n < PTW_MAX_ENTRIES; k++) {
        uint64_t e2  = pd[k];
        if (!(e2 & PTW_PTE_PRESENT)) continue;
        uint64_t va2 = va3 | ((uint64_t)k << 21);
        if (e2 & PTW_PTE_PS) {
          ptw_coal_emit(&c, va2, va2 + (1ULL << 21), e2);
          continue;
        }
        uint64_t p1 = e2 & PTW_PHYS_MASK;
        if (p1 >= PTW_PHYS_BOUND) continue;
        if (kread((intptr_t)(g_ptw_dmap + p1), pt, 4096) != 0) continue;

        for (int m = 0; m < 512 && c.n < PTW_MAX_ENTRIES; m++) {
          uint64_t e1  = pt[m];
          if (!(e1 & PTW_PTE_PRESENT)) continue;
          uint64_t va1 = va2 | ((uint64_t)m << 12);
          ptw_coal_emit(&c, va1, va1 + 0x1000, e1);
        }
      }
    }
  }
  ptw_coal_flush(&c);

  free(pml4); free(pdpt); free(pd); free(pt);

  if (c.n == 0) { free(c.ents); return 1; }
  *out       = c.ents;
  *out_count = c.n;
  return 0;
}

// Merge vm_map and PT entries

static int ptw_merge(memdbg_map_entry_t *v, int v_count,
                     memdbg_map_entry_t *e, int e_count,
                     memdbg_map_entry_t **out_buf, int *out_count) {
  int max_out = v_count + e_count;
  if (max_out <= 0) return 1;

  memdbg_map_entry_t *o = (memdbg_map_entry_t *)
      malloc((size_t)max_out * sizeof(memdbg_map_entry_t));
  if (!o) return 1;

  int iv = 0, ie = 0, io = 0;
  while (iv < v_count && ie < e_count) {
    if (v[iv].start == e[ie].start) {
      o[io++] = v[iv++];
      ie++;
    } else if (v[iv].start < e[ie].start) {
      o[io++] = v[iv++];
    } else {
      o[io++] = e[ie++];
    }
  }
  while (iv < v_count) o[io++] = v[iv++];
  while (ie < e_count) o[io++] = e[ie++];

  *out_buf   = o;
  *out_count = io;
  return 0;
}

// Aux cache

#define AUX_CACHE_MAX 4096
#define AUX_CACHE_SLOTS 4
struct aux_cache_slot {
  struct { uint64_t start, end; } ranges[AUX_CACHE_MAX];
  int count;
  uint32_t pid;
};
static struct aux_cache_slot g_aux_cache[AUX_CACHE_SLOTS];
static unsigned int g_aux_cache_next;

static void aux_cache_rebuild(uint32_t pid, memdbg_map_entry_t *m, int n) {
  (void)pthread_mutex_lock(&g_ptw_cache_mutex);
  unsigned int slot = AUX_CACHE_SLOTS;
  for (unsigned int i = 0; i < AUX_CACHE_SLOTS; ++i) {
    if (g_aux_cache[i].pid == pid) { slot = i; break; }
    if (slot == AUX_CACHE_SLOTS && g_aux_cache[i].pid == 0U) slot = i;
  }
  if (slot == AUX_CACHE_SLOTS)
    slot = g_aux_cache_next++ % AUX_CACHE_SLOTS;
  struct aux_cache_slot *cache = &g_aux_cache[slot];
  int k = 0;
  for (int i = 0; i < n && k < AUX_CACHE_MAX; i++) {
    const char *nm = m[i].name;
    if (nm[0]=='(' && nm[1]=='p' && nm[2]=='t' && nm[3]=='a' &&
        nm[4]=='u' && nm[5]=='x' && nm[6]==')' && m[i].end > m[i].start) {
      cache->ranges[k].start = m[i].start;
      cache->ranges[k].end   = m[i].end;
      k++;
    }
  }
  cache->count = k;
  cache->pid = pid;
  (void)pthread_mutex_unlock(&g_ptw_cache_mutex);
}

int ptw_aux_contains(uint32_t pid, uint64_t addr, uint64_t len) {
  if (len == 0) return 0;
  uint64_t end = addr + len;
  if (end < addr) return 0;
  int found = 0;
  (void)pthread_mutex_lock(&g_ptw_cache_mutex);
  for (unsigned int slot = 0; slot < AUX_CACHE_SLOTS && !found; ++slot) {
    if (g_aux_cache[slot].pid != pid) continue;
    for (int i = 0; i < g_aux_cache[slot].count; ++i) {
      if (addr >= g_aux_cache[slot].ranges[i].start &&
          end <= g_aux_cache[slot].ranges[i].end) {
        found = 1;
        break;
      }
    }
  }
  (void)pthread_mutex_unlock(&g_ptw_cache_mutex);
  return found;
}

// Public augment

int ptw_augment_maps(uint32_t pid,
                     memdbg_map_entry_t *vmaps, int vmap_count,
                     memdbg_map_entry_t **out_maps, int *out_count) {
  if (out_maps)   *out_maps   = NULL;
  if (out_count)  *out_count  = 0;
  if ((int32_t)pid <= 0 || !vmaps || vmap_count <= 0) return 1;

  if (!ptw_is_available()) return 1;

  uint64_t cr3;
  if (ptw_resolve_pid(pid, &cr3) != 0) return 1;

  memdbg_map_entry_t *e = NULL;
  int e_count = 0;
  if (ptw_enumerate(cr3, &e, &e_count) != 0 || e_count == 0) {
    if (e) free(e);
    return 1;
  }

  int rc = ptw_merge(vmaps, vmap_count, e, e_count, out_maps, out_count);
  if (rc == 0 && out_maps && *out_maps && out_count)
    aux_cache_rebuild(pid, *out_maps, *out_count);
  free(e);
  return rc;
}

void ptw_flush(void) {
  (void)pthread_mutex_lock(&g_ptw_cache_mutex);
  g_ptw_state    = 0;
  g_ptw_dmap     = 0;
  g_ptw_pmap_off = 0;
  memset(g_vmcache, 0, sizeof(g_vmcache));
  memset(g_aux_cache, 0, sizeof(g_aux_cache));
  g_vmcache_next = 0;
  g_aux_cache_next = 0U;
  (void)pthread_mutex_unlock(&g_ptw_cache_mutex);
}

#else /* !PTW_HAS_DMAP */

// Stubs for non-PS5 platforms

int ptw_discover(uint64_t *dmap, uint64_t *p_off) {
  (void)dmap; (void)p_off; return -1;
}
int ptw_is_available(void) { return 0; }
uint64_t ptw_dmap_base(void) { return 0; }
int ptw_probe(uint32_t pid, uint64_t va, uint64_t *ph, int *lv, uint64_t *ps, uint64_t *pte) {
  (void)pid; (void)va; (void)ph; (void)lv; (void)ps; (void)pte; return -1;
}
int ptw_span_resolve(uint32_t pid, uint64_t s, int *h, uint64_t *ph, uint64_t *lk, uint64_t *pte) {
  (void)pid; (void)s; (void)h; (void)ph; (void)lk; (void)pte; return -1;
}
int ptw_leaf_addr(uint32_t pid, uint64_t va, uint64_t *ka, uint64_t *val, int *lv) {
  (void)pid; (void)va; (void)ka; (void)val; (void)lv; return -1;
}
int ptw_read(uint32_t pid, uint64_t va, uint64_t len, void *dst) {
  (void)pid; (void)va; (void)len; (void)dst; return -1;
}
int ptw_write(uint32_t pid, uint64_t va, uint64_t len, const void *src) {
  (void)pid; (void)va; (void)len; (void)src; return -1;
}
int ptw_augment_maps(uint32_t pid, memdbg_map_entry_t *v, int vc,
                     memdbg_map_entry_t **out, int *oc) {
  (void)pid; (void)v; (void)vc; if(out)*out=NULL; if(oc)*oc=0; return 1;
}
int ptw_aux_contains(uint32_t pid, uint64_t a, uint64_t l) {
  (void)pid; (void)a; (void)l; return 0;
}
void ptw_flush(void) {}

#endif /* PTW_HAS_DMAP */
