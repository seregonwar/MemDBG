/*
 * memDBG - Debugger breakpoint and watchpoint management.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "internal.h"
#include "memdbg/pal/debug.h"
#include "memdbg/pal/pal_memory.h"
#include <errno.h>
#include <string.h>
#include <sys/wait.h>

int find_breakpoint_slot(uint64_t address) {
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_BREAKPOINTS; ++i) {
    if (g_dbg.breakpoints[i].active &&
        g_dbg.breakpoints[i].address == address) {
      return (int)i;
    }
  }
  return -1;
}

int alloc_breakpoint_slot(void) {
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_BREAKPOINTS; ++i) {
    if (!g_dbg.breakpoints[i].active) return (int)i;
  }
  return -1;
}

int find_watchpoint_slot(uint64_t address) {
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_WATCHPOINTS; ++i) {
    if (g_dbg.watchpoints[i].installed &&
        g_dbg.watchpoints[i].address == address) {
      return (int)i;
    }
  }
  return -1;
}

int alloc_hw_slot(void) {
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_WATCHPOINTS; ++i) {
    if (!g_dbg.watchpoints[i].installed) return (int)i;
  }
  return -1;
}


memdbg_status_t install_sw_breakpoint(memdbg_breakpoint_t *bp) {
  if (bp->installed) return MEMDBG_OK;
  uint8_t byte = 0;
  memdbg_status_t st = debugger_memory_read(bp->address, &byte, 1);
  if (st != MEMDBG_OK) return st;
  bp->original_byte = byte;
  uint8_t int3 = INT3_OPCODE;
  st = debugger_memory_write(bp->address, &int3, 1);
  if (st != MEMDBG_OK) return st;
  bp->installed = true;
  return MEMDBG_OK;
}

memdbg_status_t uninstall_sw_breakpoint(memdbg_breakpoint_t *bp) {
  if (!bp->installed) return MEMDBG_OK;
  memdbg_status_t st = debugger_memory_write(bp->address, &bp->original_byte,
                                             1);
  if (st != MEMDBG_OK) return st;
  bp->installed = false;
  return MEMDBG_OK;
}

// Hardware breakpoint/watchpoint helpers

void build_dr7(uint32_t *dr7_out) {
  uint32_t dr7 = 0;
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_WATCHPOINTS; ++i) {
    const memdbg_watchpoint_t *wp = &g_dbg.watchpoints[i];
    if (!wp->installed) continue;
    uint32_t rw = 0;
    uint32_t len = 0;
    switch (wp->type) {
    case 0:
      rw = 0;
      break; /* exec */
    case 1:
      rw = 1;
      break; /* write */
    case 2:
      rw = 3;
      break; /* read */
    case 3:
      rw = 3;
      break; /* read-write */
    default:
      rw = 3;
      break;
    }
    switch (wp->length) {
    case 1:
      len = 0;
      break;
    case 2:
      len = 1;
      break;
    case 4:
      len = 3;
      break;
    case 8:
      len = 2;
      break;
    default:
      len = 3;
      break;
    }
    uint32_t shift = 16 + (i * 4);
    dr7 |= (rw << shift) | (len << (shift + 2));
    dr7 |= (1U << (i * 2));     /* local enable */
    dr7 |= (1U << (i * 2 + 1)); /* global enable */
  }
  *dr7_out = dr7;
}

memdbg_status_t apply_dbregs_to_all(void) {
  int32_t lwps[MEMDBG_DEBUGGER_MAX_THREADS];
  uint32_t count = 0;    memdbg_status_t st = get_threads_locked(lwps, NULL, NULL, &count,
                                          MEMDBG_DEBUGGER_MAX_THREADS);
  if (st != MEMDBG_OK) return st;
  for (uint32_t i = 0; i < count; ++i) {
    if (pal_debug_set_dbregs((int)g_dbg.pid, lwps[i], &g_dbg.dbregs) != 0) {
      return pal_status_from_errno();
    }
  }
  return MEMDBG_OK;
}

memdbg_status_t refresh_dbregs_from_thread(int32_t lwp) {
  if (pal_debug_get_dbregs((int)g_dbg.pid, lwp, &g_dbg.dbregs) != 0) {
    return pal_status_from_errno();
  }
  g_dbg.dbregs_valid = true;
  return MEMDBG_OK;
}

// Internal single-step over a software breakpoint

memdbg_status_t step_over_sw_breakpoint_locked(int32_t lwp) {
  memdbg_debug_regs_t regs;
  memset(&regs, 0, sizeof(regs));
  if (pal_debug_get_regs((int)g_dbg.pid, lwp, &regs) != 0) {
    return pal_status_from_errno();
  }

  uint64_t bp_addr = (uint64_t)(regs.r_rip - 1);
  int slot = find_breakpoint_slot(bp_addr);
  if (slot < 0 || g_dbg.breakpoints[slot].kind != MEMDBG_BP_SOFTWARE) {
    /* No software breakpoint under RIP; just single-step. */
    if (pal_debug_single_step((int)g_dbg.pid, lwp) != 0) {
      return pal_status_from_errno();
    }
    return MEMDBG_OK;
  }

  memdbg_breakpoint_t *bp = &g_dbg.breakpoints[slot];
  memdbg_status_t st = uninstall_sw_breakpoint(bp);
  if (st != MEMDBG_OK) return st;

  regs.r_rip -= 1;
  if (pal_debug_set_regs((int)g_dbg.pid, lwp, &regs) != 0) {
    (void)install_sw_breakpoint(bp);
    return pal_status_from_errno();
  }

  if (pal_debug_single_step((int)g_dbg.pid, lwp) != 0) {
    (void)install_sw_breakpoint(bp);
    return pal_status_from_errno();
  }

  /* Wait for the single-step SIGTRAP. */
  for (int i = 0; i < 500; ++i) {
    int status = 0;
    int r = pal_debug_wait((int)g_dbg.pid, &status, true);
    if (r == 1 && WIFSTOPPED(status)) break;
    debugger_sleep_ms(10);
  }

  st = install_sw_breakpoint(bp);
  return st;
}

// Internal hardware debug-register synchronisation

memdbg_status_t sync_hardware_dbregs_locked(void) {
  if (!g_dbg.dbregs_valid) {
    int32_t lwps[1];
    uint32_t count = 0;
    if (get_threads_locked(lwps, NULL, NULL, &count, 1) != MEMDBG_OK ||
        count == 0) {
      return MEMDBG_ERR_IO;
    }
    if (refresh_dbregs_from_thread(lwps[0]) != MEMDBG_OK) {
      return pal_status_from_errno();
    }
  }

  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_WATCHPOINTS; ++i) {
    const memdbg_watchpoint_t *wp = &g_dbg.watchpoints[i];
    if (wp->installed) {
      g_dbg.dbregs.dr[i] = wp->address;
    } else {
      g_dbg.dbregs.dr[i] = 0;
    }
  }

  uint32_t dr7 = 0;
  build_dr7(&dr7);
  g_dbg.dbregs.dr[7] = (uint64_t)dr7;

  return apply_dbregs_to_all();
}


memdbg_status_t memdbg_debugger_set_breakpoint(uint64_t address,
                                               uint32_t kind) {
  return memdbg_debugger_set_breakpoint_cond(address, kind,
      MEMDBG_BP_COND_NONE, MEMDBG_BP_COND_EQ, 0ULL);
}

memdbg_status_t memdbg_debugger_set_breakpoint_cond(
    uint64_t address, uint32_t kind,
    uint32_t cond_reg, uint32_t cond_op, uint64_t cond_value) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  if (cond_reg > MEMDBG_BP_COND_RIP) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }
  if (cond_op > MEMDBG_BP_COND_GE) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }

  if (find_breakpoint_slot(address) >= 0) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }

  int slot = alloc_breakpoint_slot();
  if (slot < 0) {
    debugger_unlock();
    return MEMDBG_ERR_NOMEM;
  }

  memdbg_breakpoint_t *bp = &g_dbg.breakpoints[slot];
  memset(bp, 0, sizeof(*bp));
  bp->address = address;
  bp->kind = kind;
  bp->active = true;
  bp->cond_reg = cond_reg;
  bp->cond_op = cond_op;
  bp->cond_value = cond_value;

  memdbg_status_t st = MEMDBG_OK;
  if (kind == MEMDBG_BP_SOFTWARE) {
    st = install_sw_breakpoint(bp);
  } else if (kind == MEMDBG_BP_HARDWARE) {
    int hw = alloc_hw_slot();
    if (hw < 0) {
      st = MEMDBG_ERR_NOMEM;
    } else {
      memdbg_watchpoint_t fake;
      memset(&fake, 0, sizeof(fake));
      fake.address = address;
      fake.length = 1;
      fake.type = 0; /* exec */
      fake.slot = (uint32_t)hw;
      fake.installed = true;
      g_dbg.watchpoints[hw] = fake;
      st = sync_hardware_dbregs_locked();
      if (st != MEMDBG_OK) {
        memset(&g_dbg.watchpoints[hw], 0,
               sizeof(g_dbg.watchpoints[hw]));
      }
    }
  } else {
    st = MEMDBG_ERR_PARAM;
  }

  if (st != MEMDBG_OK) {
    memset(bp, 0, sizeof(*bp));
  }

  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_clear_breakpoint(uint64_t address) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  int slot = find_breakpoint_slot(address);
  if (slot < 0) {
    debugger_unlock();
    return MEMDBG_ERR_NOT_FOUND;
  }

  memdbg_breakpoint_t *bp = &g_dbg.breakpoints[slot];
  memdbg_status_t st = MEMDBG_OK;
  if (bp->kind == MEMDBG_BP_SOFTWARE) {
    st = uninstall_sw_breakpoint(bp);
  } else if (bp->kind == MEMDBG_BP_HARDWARE) {
    int hw = find_watchpoint_slot(address);
    if (hw >= 0) {
      memset(&g_dbg.watchpoints[hw], 0, sizeof(g_dbg.watchpoints[hw]));
      st = sync_hardware_dbregs_locked();
    }
  }

  memset(bp, 0, sizeof(*bp));
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_clear_all_breakpoints(uint32_t *cleared) {
  uint32_t c = 0;
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    if (cleared != NULL) *cleared = 0;
    return MEMDBG_ERR_STATE;
  }
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_BREAKPOINTS; ++i) {
    if (!g_dbg.breakpoints[i].active) continue;
    memdbg_breakpoint_t *bp = &g_dbg.breakpoints[i];
    if (bp->kind == MEMDBG_BP_SOFTWARE) {
      (void)uninstall_sw_breakpoint(bp);
    } else if (bp->kind == MEMDBG_BP_HARDWARE) {
      int hw = find_watchpoint_slot(bp->address);
      if (hw >= 0) {
        memset(&g_dbg.watchpoints[hw], 0, sizeof(g_dbg.watchpoints[hw]));
      }
    }
    memset(bp, 0, sizeof(*bp));
    ++c;
  }
  if (c > 0) (void)sync_hardware_dbregs_locked();
  if (cleared != NULL) *cleared = c;
  debugger_unlock();
  return MEMDBG_OK;
}

memdbg_status_t memdbg_debugger_breakpoints_snapshot(
    memdbg_breakpoint_t *out, uint32_t max, uint32_t *count) {
  if (count == NULL || (out == NULL && max > 0U)) {
    return MEMDBG_ERR_PARAM;
  }

  uint32_t n = max;
  if (n > MEMDBG_DEBUGGER_MAX_BREAKPOINTS) {
    n = MEMDBG_DEBUGGER_MAX_BREAKPOINTS;
  }

  debugger_lock();
  if (n > 0U) {
    memcpy(out, g_dbg.breakpoints, n * sizeof(out[0]));
  }
  debugger_unlock();

  *count = n;
  return MEMDBG_OK;
}

memdbg_status_t memdbg_debugger_set_watchpoint(uint64_t address,
                                               uint32_t length,
                                               uint32_t type) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  if (length != 1 && length != 2 && length != 4 && length != 8) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }
  if (type > 3) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }

  if (find_watchpoint_slot(address) >= 0) {
    debugger_unlock();
    return MEMDBG_ERR_PARAM;
  }

  int slot = alloc_hw_slot();
  if (slot < 0) {
    debugger_unlock();
    return MEMDBG_ERR_NOMEM;
  }

  memdbg_watchpoint_t *wp = &g_dbg.watchpoints[slot];
  memset(wp, 0, sizeof(*wp));
  wp->address = address;
  wp->length = length;
  wp->type = type;
  wp->slot = (uint32_t)slot;
  wp->installed = true;

  memdbg_status_t st = sync_hardware_dbregs_locked();
  if (st != MEMDBG_OK) {
    memset(wp, 0, sizeof(*wp));
  }

  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_clear_watchpoint(uint64_t address) {
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    return MEMDBG_ERR_STATE;
  }

  int slot = find_watchpoint_slot(address);
  if (slot < 0) {
    debugger_unlock();
    return MEMDBG_ERR_NOT_FOUND;
  }

  memset(&g_dbg.watchpoints[slot], 0, sizeof(g_dbg.watchpoints[slot]));
  memdbg_status_t st = sync_hardware_dbregs_locked();
  debugger_unlock();
  return st;
}

memdbg_status_t memdbg_debugger_clear_all_watchpoints(uint32_t *cleared) {
  uint32_t c = 0;
  debugger_lock();
  if (!g_dbg.attached) {
    debugger_unlock();
    if (cleared != NULL) *cleared = 0;
    return MEMDBG_ERR_STATE;
  }
  for (uint32_t i = 0; i < MEMDBG_DEBUGGER_MAX_WATCHPOINTS; ++i) {
    if (!g_dbg.watchpoints[i].installed) continue;
    memset(&g_dbg.watchpoints[i], 0, sizeof(g_dbg.watchpoints[i]));
    ++c;
  }
  if (c > 0) (void)sync_hardware_dbregs_locked();
  if (cleared != NULL) *cleared = c;
  debugger_unlock();
  return MEMDBG_OK;
}

memdbg_status_t memdbg_debugger_watchpoints_snapshot(
    memdbg_watchpoint_t *out, uint32_t max, uint32_t *count) {
  if (count == NULL || (out == NULL && max > 0U)) {
    return MEMDBG_ERR_PARAM;
  }

  uint32_t n = max;
  if (n > MEMDBG_DEBUGGER_MAX_WATCHPOINTS) {
    n = MEMDBG_DEBUGGER_MAX_WATCHPOINTS;
  }

  debugger_lock();
  if (n > 0U) {
    memcpy(out, g_dbg.watchpoints, n * sizeof(out[0]));
  }
  debugger_unlock();

  *count = n;
  return MEMDBG_OK;
}
