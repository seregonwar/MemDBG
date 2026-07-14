/*
 * MemDBG - SPRX injector implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Loads a shared-library ELF (SPRX) into a target process and calls its
 * entry-point function via the debugger (ptrace-based remote call).
 *
 * Used by:
 *   - daemon auto-injection  (sprx_inject_auto)
 *   - frontend via protocol  (MEMDBG_CMD_SPRX_INJECT)
 */

#include "sprx_injector.h"

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_log.h"
#include "memdbg/debug/memdbg_debugger.h"
#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/debug/memdbg_process.h"
#include "memdbg/pal/pal_time.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Forward: ELF loader from features.c */
extern int memdbg_elf_load_enhanced(int pid, const uint8_t *elf,
                                    uint64_t elf_size, const char *region,
                                    uint32_t match_flags, uint64_t *entry,
                                    uint64_t *base);

#if defined(PLATFORM_PS5) || defined(PS5) || defined(__PROSPERO__)

extern int64_t dbg_remote_mmap(int pid, uint64_t addr, uint64_t len,
                                int prot, int flags);
extern int64_t dbg_remote_munmap(int pid, uint64_t addr, uint64_t len);

/* ── PID lookup ──────────────────────────────────────────────────────── */

int sprx_find_pid_by_name(const char *partial_name) {
  if (partial_name == NULL || partial_name[0] == '\0')
    return 0;

  memdbg_process_list_t list;
  memset(&list, 0, sizeof(list));
  if (memdbg_process_list(&list) != MEMDBG_OK)
    return -1;

  int found = 0;
  size_t plen = strlen(partial_name);
  for (uint32_t i = 0; i < list.count && found == 0; ++i) {
    const char *pname = list.entries[i].name;
    const char *pos = pname;
    while (*pos) {
      size_t k;
      for (k = 0; k < plen; ++k) {
        unsigned char ca = (unsigned char)pos[k];
        unsigned char cb = (unsigned char)partial_name[k];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
        if (ca != cb || pos[k] == '\0')
          break;
      }
      if (k == plen) {
        found = list.entries[i].pid;
        break;
      }
      ++pos;
    }
  }

  memdbg_process_list_free(&list);
  return found;
}

/* ── Remote function call (shared primitive) ─────────────────────────── */

int sprx_remote_call(int pid, uint64_t addr, int argc, const uint64_t *argv) {
  bool need_detach = false;
  memdbg_status_t st;
  int32_t lwp;
  size_t written;

  st = memdbg_debugger_conditional_attach(pid, &need_detach);
  if (st != MEMDBG_OK) return -1;

  st = memdbg_debugger_stop();
  if (st != MEMDBG_OK) {
    if (need_detach) (void)memdbg_debugger_detach();
    return -1;
  }

  /* Find a thread */
  int32_t lwps[1] = {0};
  char names_buf[1][24];
  uint32_t states[1];
  uint32_t count = 1U;
  memdbg_debugger_get_threads(lwps, names_buf, states, &count, 1U);
  if (count == 0U) {
    if (need_detach) (void)memdbg_debugger_detach();
    return -1;
  }
  lwp = lwps[0];

  /* Save registers */
  memdbg_debug_regs_t orig_regs;
  memset(&orig_regs, 0, sizeof(orig_regs));
  st = memdbg_debugger_get_regs(lwp, &orig_regs);
  if (st != MEMDBG_OK) {
    if (need_detach) (void)memdbg_debugger_detach();
    return -1;
  }

  /* Allocate a stub page for the INT3 return trampoline via remote mmap */
  int64_t mmap_res = dbg_remote_mmap(pid, 0, 4096,
                                      PROT_READ | PROT_EXEC,
                                      0x1002);  /* MAP_ANONYMOUS|MAP_PRIVATE */
  if (mmap_res < 0) {
    if (need_detach) (void)memdbg_debugger_detach();
    return -1;
  }
  uint64_t stub_addr = (uint64_t)mmap_res;

  /* Place INT3 at stub_addr */
  {
    uint8_t cc = 0xCCU;
    st = memdbg_memory_write(pid, stub_addr, &cc, 1U, &written);
    if (st != MEMDBG_OK || written != 1U) {
      (void)dbg_remote_munmap(pid, stub_addr, 4096);
      if (need_detach) (void)memdbg_debugger_detach();
      return -1;
    }
  }

  /* Set up call registers */
  memdbg_debug_regs_t call_regs = orig_regs;
  call_regs.r_rsp = (int64_t)(((uint64_t)orig_regs.r_rsp & ~0xFULL) - 8U);
  call_regs.r_rip = (int64_t)addr;

  if (argv && argc > 0) {
    int64_t *regs[6] = {
      &call_regs.r_rdi, &call_regs.r_rsi, &call_regs.r_rdx,
      &call_regs.r_rcx, &call_regs.r_r8,  &call_regs.r_r9
    };
    int n = (argc > 6) ? 6 : argc;
    for (int i = 0; i < n; ++i)
      *regs[i] = (int64_t)argv[i];
  }

  /* Write return address (stub_addr) on the stack */
  {
    uint64_t ra = stub_addr;
    st = memdbg_memory_write(pid, (uint64_t)call_regs.r_rsp, &ra, 8U, &written);
  }
  if (st != MEMDBG_OK || written != 8U) {
    (void)dbg_remote_munmap(pid, stub_addr, 4096);
    (void)memdbg_debugger_set_regs(lwp, &orig_regs);
    if (need_detach) (void)memdbg_debugger_detach();
    return -1;
  }

  st = memdbg_debugger_set_regs(lwp, &call_regs);
  if (st != MEMDBG_OK) {
    (void)dbg_remote_munmap(pid, stub_addr, 4096);
    if (need_detach) (void)memdbg_debugger_detach();
    return -1;
  }

  st = memdbg_debugger_continue();
  if (st != MEMDBG_OK) {
    (void)dbg_remote_munmap(pid, stub_addr, 4096);
    (void)memdbg_debugger_set_regs(lwp, &orig_regs);
    if (need_detach) (void)memdbg_debugger_detach();
    return -1;
  }

  /* Wait for INT3 or timeout (5 seconds) */
  {
    const uint32_t max_wait_ms = 5000U;
    uint32_t waited_ms = 0U;
    while (!memdbg_debugger_is_stopped() && waited_ms < max_wait_ms) {
      (void)memdbg_debugger_poll_events();
      memdbg_sleep_ms(10U);
      waited_ms += 10U;
    }
    if (!memdbg_debugger_is_stopped()) {
      (void)memdbg_debugger_stop();
      (void)memdbg_debugger_set_regs(lwp, &orig_regs);
      (void)dbg_remote_munmap(pid, stub_addr, 4096);
      if (need_detach) (void)memdbg_debugger_detach();
      return -1;
    }
  }

  /* Get return value (rax) */
  memdbg_debug_regs_t ret_regs;
  memset(&ret_regs, 0, sizeof(ret_regs));
  st = memdbg_debugger_get_regs(lwp, &ret_regs);
  int64_t rax = (st == MEMDBG_OK) ? ret_regs.r_rax : -1LL;

  /* Restore original state */
  (void)memdbg_debugger_set_regs(lwp, &orig_regs);
  (void)dbg_remote_munmap(pid, stub_addr, 4096);

  if (need_detach)
    (void)memdbg_debugger_detach();

  return (rax == 0) ? 0 : -1;
}

/* ── SPRX injection ──────────────────────────────────────────────────── */

int sprx_inject_file_ex(const char *path, int target_pid,
                         uint64_t *entry_out, uint64_t *base_out) {
  if (entry_out) *entry_out = 0U;
  if (base_out)  *base_out  = 0U;
  if (path == NULL || target_pid <= 1)
    return -1;

  /* 1. Read SPRX from file */
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    memdbg_log_write(MEMDBG_LOG_ERROR, "sprx_inject: cannot open %s", path);
    return -1;
  }

  struct stat st;
  if (fstat(fd, &st) < 0 || st.st_size <= 0 || st.st_size > (64 << 20)) {
    close(fd);
    memdbg_log_write(MEMDBG_LOG_ERROR, "sprx_inject: bad file size for %s", path);
    return -1;
  }

  uint8_t *elf = (uint8_t *)malloc((size_t)st.st_size);
  if (elf == NULL) {
    close(fd);
    return -1;
  }

  ssize_t nr = read(fd, elf, (size_t)st.st_size);
  close(fd);

  if (nr != st.st_size) {
    free(elf);
    memdbg_log_write(MEMDBG_LOG_ERROR, "sprx_inject: short read on %s", path);
    return -1;
  }

  /* 2. Attach debugger before ELF load (needed for remote mmap) */
  bool need_detach = false;
  memdbg_status_t attach_st =
    memdbg_debugger_conditional_attach(target_pid, &need_detach);
  if (attach_st != MEMDBG_OK) {
    free(elf);
    memdbg_log_write(MEMDBG_LOG_ERROR,
                     "sprx_inject: cannot attach debugger to pid %d", target_pid);
    return -1;
  }

  /* 3. Stop target for remote operations */
  memdbg_debugger_stop();

  /* 4. Load ELF into target process */
  uint64_t entry = 0U, base = 0U;
  int rc = memdbg_elf_load_enhanced(target_pid, elf, (uint64_t)st.st_size,
                                    NULL, 0U, &entry, &base);
  free(elf);

  if (rc != 0) {
    memdbg_log_write(MEMDBG_LOG_ERROR,
                     "sprx_inject: ELF load failed for pid %d", target_pid);
    if (need_detach) memdbg_debugger_detach();
    return -2;
  }

  if (entry_out) *entry_out = entry;
  if (base_out)  *base_out  = base;

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "sprx_inject: loaded %s -> pid %d, base=0x%llx, entry=0x%llx",
                   path, target_pid,
                   (unsigned long long)base, (unsigned long long)entry);

  /* 5. Continue target first (sprx_remote_call manages its own stop/continue) */
  memdbg_debugger_continue();

  /* 6. Call entry point in target context */
  if (entry != 0U) {
    rc = sprx_remote_call(target_pid, entry, 0, NULL);
    if (rc != 0) {
      memdbg_log_write(MEMDBG_LOG_WARN,
                       "sprx_inject: init call returned %d (pid %d)", rc,
                       target_pid);
      if (need_detach) memdbg_debugger_detach();
      return -3;
    }
    memdbg_log_write(MEMDBG_LOG_INFO,
                     "sprx_inject: init call succeeded (pid %d)", target_pid);
  }

  if (need_detach)
    memdbg_debugger_detach();

  return 0;
}

int sprx_inject_file(const char *path, int target_pid) {
  return sprx_inject_file_ex(path, target_pid, NULL, NULL);
}

/* ── Auto-injection ──────────────────────────────────────────────────── */

int sprx_inject_auto(void) {
  int pid = sprx_find_pid_by_name("SceShellUI");
  if (pid <= 1) {
    memdbg_log_write(MEMDBG_LOG_WARN,
                     "sprx_inject: SceShellUI not found, skipping auto-inject");
    return -4;
  }

  memdbg_log_write(MEMDBG_LOG_INFO,
                   "sprx_inject: found SceShellUI at pid %d", pid);

  return sprx_inject_file("/user/data/memdbg/memdbg_shellui.sprx", pid);
}

#else /* !PS5 — host stubs */

int sprx_find_pid_by_name(const char *partial_name) {
  (void)partial_name;
  return 0;
}
int sprx_inject_file_ex(const char *path, int target_pid,
                         uint64_t *entry_out, uint64_t *base_out) {
  (void)path; (void)target_pid;
  if (entry_out) *entry_out = 0U;
  if (base_out)  *base_out  = 0U;
  return 0;
}
int sprx_inject_file(const char *path, int target_pid) {
  (void)path; (void)target_pid;
  return 0;
}
int sprx_remote_call(int pid, uint64_t addr, int argc, const uint64_t *argv) {
  (void)pid; (void)addr; (void)argc; (void)argv;
  return 0;
}
int sprx_inject_auto(void) { return 0; }

#endif /* PLATFORM_PS5 */
