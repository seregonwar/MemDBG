/*
 * memDBG - Page alias engine implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Maps foreign physical pages into the payload's virtual address space by
 * overwriting leaf PTEs. After a successful map, the caller can directly
 * dereference the returned pointer to read target memory — much faster than
 * the mdbg_copyout syscall for large scans.
 */

#include "page_alias.h"
#include "pt_walker.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)
#include <ps5/kernel.h>
#define ALIAS_HAS_DMAP 1
#endif

#if !defined(ALIAS_HAS_DMAP)
#define ALIAS_HAS_DMAP 0
#endif

#if ALIAS_HAS_DMAP

// Constants

#define AL_SPAN_SIZE      0x200000ULL
#define AL_PT_ENTRIES     512U
#define AL_PAGE_SIZE      0x1000ULL
#define AL_MAX_PAGES      511U
#define AL_ARENA_DEFAULT  (64ULL << 20)
#define AL_DMAP_BOUND     0x1000000000ULL
#define AL_PTE_PRESENT    0x1ULL
#define AL_PTE_PCD        0x10ULL
#define AL_PHYS_MASK      0x000FFFFFFFFFF000ULL
#define AL_PTE_PROT       0x7ULL

#define AL_MAX_SPANS      128U
#define AL_VERIFY_INTERVAL 16U          /* verify every N remaps */
#define AL_VERIFY_MAX      32U
#define AL_TOUCH_SLOT     511U

struct page_alias_ctx {
  uint32_t pid;
  uint32_t self_pid;
  uint64_t map_counter;
  uint64_t dmap;

  uint64_t arena_bytes;
  uint64_t arena_raw;
  uint64_t arena_size;
  uint64_t arena_end;
  uint64_t cursor;
  uint64_t used_pt_bases[AL_MAX_SPANS];
  uint64_t used_count;

  int      has_mapping;
  uint64_t map_pt_kaddr;   /* kernel address of leaf PT page */
  uint64_t map_pages;      /* number of PTEs written */

  int      sc_valid;
  uint64_t sc_span_2m;
  int      sc_huge;
  uint64_t sc_phys_base;
  uint64_t sc_pte;
  uint64_t span_pt[AL_PT_ENTRIES];
};

// Kernel access wrappers

static inline int kread(intptr_t kaddr, void *dst, size_t n) {
  return kernel_copyout_fast(kaddr, dst, n);
}

static inline int kwrite(const void *src, intptr_t kaddr, size_t n) {
  return kernel_copyin_fast(src, kaddr, n);
}

static long raw_syscall(long no, long a, long b, long c, long d, long e, long f) {
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

static long raw_mmap(uint64_t size) {
  return raw_syscall(477, 0L, (long)size, 3L, 0x1002L, -1L, 0L);
}

static int raw_munmap(uint64_t addr, uint64_t size) {
  return (int)raw_syscall(73, (long)addr, (long)size, 0L, 0L, 0L, 0L);
}

// Arena management

static int al_arena_alloc(page_alias_ctx_t *c) {
  uint64_t mapsz = c->arena_bytes + AL_SPAN_SIZE;
  long raw = raw_mmap(mapsz);
  if (raw == -1 || raw == 0) return -1;
  uint64_t base = ((uint64_t)raw + (AL_SPAN_SIZE - 1)) & ~(AL_SPAN_SIZE - 1);
  c->arena_raw   = (uint64_t)raw;
  c->arena_size  = mapsz;
  c->arena_end   = base + c->arena_bytes;
  c->cursor      = base;
  c->used_count  = 0;
  return 0;
}

static int al_next_span(page_alias_ctx_t *c, uint64_t *span_out) {
  if (c->cursor == 0 || c->cursor + AL_SPAN_SIZE > c->arena_end) {
    if (c->arena_raw) {
      if (c->has_mapping) page_alias_release(c);
      int can_unmap = (c->used_count <= AL_MAX_SPANS);
      if (can_unmap) {
        for (uint64_t i = 0; can_unmap && i < c->used_count; i++) {
          uint64_t pt[AL_PT_ENTRIES];
          if (kread((intptr_t)c->used_pt_bases[i], pt, sizeof(pt)) != 0)
            { can_unmap = 0; break; }
          for (unsigned k = 0; k < AL_VERIFY_MAX; k++)
            if (pt[k] & AL_PTE_PRESENT) { can_unmap = 0; break; }
        }
      }
      if (can_unmap)
        raw_munmap(c->arena_raw, c->arena_size);
      c->arena_raw = 0; c->arena_size = 0; c->arena_end = 0;
      c->cursor = 0; c->used_count = 0;
    }
    if (al_arena_alloc(c) != 0) return -1;
  }
  *span_out = c->cursor;
  c->cursor += AL_SPAN_SIZE;
  return 0;
}

// Public API

page_alias_ctx_t *page_alias_begin(uint32_t pid, uint64_t arena_cap) {
  uint64_t dmap = ptw_dmap_base();
  if (dmap == 0) return NULL;

  page_alias_ctx_t *c = (page_alias_ctx_t *)malloc(sizeof(*c));
  if (!c) return NULL;
  memset(c, 0, sizeof(*c));
  c->pid         = pid;
  c->self_pid    = (uint32_t)getpid();
  c->dmap        = dmap;
  c->arena_bytes = arena_cap ? arena_cap : AL_ARENA_DEFAULT;
  if (al_arena_alloc(c) != 0) { free(c); return NULL; }
  return c;
}

void page_alias_rebind(page_alias_ctx_t *c, uint32_t pid) {
  if (!c) return;
  if (c->has_mapping) page_alias_release(c);
  c->pid      = pid;
  c->sc_valid = 0;
}

void page_alias_release(page_alias_ctx_t *c) {
  if (!c || !c->has_mapping) return;
  uint64_t zeros[AL_MAX_PAGES];
  memset(zeros, 0, c->map_pages * 8);
  kwrite(zeros, (intptr_t)c->map_pt_kaddr, c->map_pages * 8);
  c->has_mapping  = 0;
  c->map_pages    = 0;
  c->map_pt_kaddr = 0;
}

const void *page_alias_map(page_alias_ctx_t *c,
                           uint64_t target_va, uint64_t length,
                           uint64_t *mapped_len_out) {
  if (!c || length == 0) return NULL;
  if (c->has_mapping) page_alias_release(c);

  uint64_t tgt_page = target_va & ~(AL_PAGE_SIZE - 1);
  uint64_t offset   = target_va &  (AL_PAGE_SIZE - 1);
  uint64_t npages   = (offset + length + (AL_PAGE_SIZE - 1)) >> 12;
  if (npages == 0 || npages > AL_MAX_PAGES) return NULL;

  uint64_t span;
  if (al_next_span(c, &span) != 0) return NULL;

  /* Touch the guard page to force PT allocation */
  *(volatile uint8_t *)(uintptr_t)(span + (uint64_t)AL_TOUCH_SLOT * AL_PAGE_SIZE) = 0;

  uint64_t pt_kaddr = 0, pt_val = 0;
  int      pt_lv = -1;
  if (ptw_leaf_addr(c->self_pid, span, &pt_kaddr, &pt_val, &pt_lv) != 0)
    return NULL;
  if (pt_lv != 3) return NULL;
  if (pt_kaddr < c->dmap || pt_kaddr >= c->dmap + AL_DMAP_BOUND)
    return NULL;

  uint64_t pt[AL_PT_ENTRIES];
  if (kread((intptr_t)pt_kaddr, pt, sizeof(pt)) != 0) return NULL;

  uint64_t verify_vas[AL_VERIFY_MAX], verify_tgts[AL_VERIFY_MAX];
  unsigned n_verify = 0;

  for (uint64_t k = 0; k < npages; k++) {
    uint64_t tpage  = tgt_page + k * AL_PAGE_SIZE;
    uint64_t span2m = tpage & ~(AL_SPAN_SIZE - 1);
    uint64_t tphys;
    int      newly_resolved = 0;

    // Span-resolution cache: resolve 2MB span once
    if (!c->sc_valid || c->sc_span_2m != span2m) {
      int    huge = 0;
      uint64_t pbase = 0, leaf_kaddr = 0, pte = 0;
      if (ptw_span_resolve(c->pid, span2m, &huge, &pbase, &leaf_kaddr, &pte) != 0)
        return NULL;

      if (huge) {
        if (pte & AL_PTE_PCD) return NULL;
        c->sc_huge      = 1;
        c->sc_phys_base = pbase;
        c->sc_pte       = pte;
      } else {
        if (kread((intptr_t)leaf_kaddr, c->span_pt, sizeof(c->span_pt)) != 0)
          return NULL;
        c->sc_huge = 0;
      }
      c->sc_span_2m = span2m;
      c->sc_valid   = 1;
      newly_resolved = 1;
    }

    if (c->sc_huge) {
      tphys = c->sc_phys_base + (tpage - span2m);
    } else {
      uint64_t e = c->span_pt[(tpage >> 12) & 0x1FF];
      if (!(e & AL_PTE_PRESENT)) return NULL;
      if (e & AL_PTE_PCD)        return NULL;
      tphys = e & AL_PHYS_MASK;
    }

    if (pt[k] & AL_PTE_PRESENT) return NULL;

    pt[k] = (tphys & AL_PHYS_MASK) | AL_PTE_PROT;

    // Select verification pages: first, last, and each newly resolved span
    if ((newly_resolved || k == 0 || k == npages - 1) && n_verify < AL_VERIFY_MAX) {
      verify_vas[n_verify]   = span + k * AL_PAGE_SIZE;
      verify_tgts[n_verify]  = tpage;
      n_verify++;
    }
  }

  if ((pt_kaddr & 0xFFFULL) != 0 || npages > AL_MAX_PAGES) return NULL;

  if (kwrite(pt, (intptr_t)pt_kaddr, npages * 8) != 0) {
    uint64_t zeros[AL_MAX_PAGES];
    memset(zeros, 0, npages * 8);
    kwrite(zeros, (intptr_t)pt_kaddr, npages * 8);
    return NULL;
  }

  c->has_mapping   = 1;
  c->map_pt_kaddr  = pt_kaddr;
  c->map_pages     = npages;

  if (c->used_count < AL_MAX_SPANS)
    c->used_pt_bases[c->used_count] = pt_kaddr;
  c->used_count++;

  // Periodic verification: compare alias content against real read
  int do_verify = ((c->map_counter % AL_VERIFY_INTERVAL) == 0);
  c->map_counter++;
  if (do_verify) {
    for (unsigned s = 0; s < n_verify; s++) {
      uint8_t alias_buf[64], real_buf[64];
      memcpy(alias_buf, (const void *)(uintptr_t)verify_vas[s], sizeof(alias_buf));
      memset(real_buf, 0, sizeof(real_buf));
      {
        size_t rsz = 0;
        {
          extern memdbg_status_t pal_memory_read(int, uint64_t, void*, size_t, size_t*);
          (void)pal_memory_read((int)c->pid, verify_tgts[s], real_buf, sizeof(real_buf), &rsz);
        }
      }
      if (memcmp(alias_buf, real_buf, sizeof(alias_buf)) != 0) {
        page_alias_release(c);
        return NULL;
      }
    }
  }

  if (mapped_len_out) *mapped_len_out = length;
  return (const void *)(uintptr_t)(span + offset);
}

void page_alias_end(page_alias_ctx_t *c) {
  if (!c) return;
  page_alias_release(c);
  if (c->arena_raw) {
    int can_unmap = (c->used_count <= AL_MAX_SPANS);
    if (can_unmap) {
      for (uint64_t i = 0; can_unmap && i < c->used_count; i++) {
        uint64_t pt[AL_PT_ENTRIES];
        if (kread((intptr_t)c->used_pt_bases[i], pt, sizeof(pt)) != 0)
          { can_unmap = 0; break; }
        for (unsigned k = 0; k < AL_VERIFY_MAX; k++)
          if (pt[k] & AL_PTE_PRESENT) { can_unmap = 0; break; }
      }
    }
    if (can_unmap)
      raw_munmap(c->arena_raw, c->arena_size);
  }
  free(c);
}

#else /* !ALIAS_HAS_DMAP */

// Stubs

page_alias_ctx_t *page_alias_begin(uint32_t pid, uint64_t cap) {
  (void)pid; (void)cap; return NULL;
}
void page_alias_rebind(page_alias_ctx_t *c, uint32_t pid) {
  (void)c; (void)pid;
}
const void *page_alias_map(page_alias_ctx_t *c, uint64_t va, uint64_t len, uint64_t *mlen) {
  (void)c; (void)va; (void)len; if(mlen) *mlen = 0; return NULL;
}
void page_alias_release(page_alias_ctx_t *c) { (void)c; }
void page_alias_end(page_alias_ctx_t *c) { (void)c; }

#endif /* ALIAS_HAS_DMAP */
