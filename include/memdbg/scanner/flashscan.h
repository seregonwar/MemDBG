/*
 * memDBG - FlashScan: server-resident scanning with snapshots.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_SCANNER_FLASHSCAN_H
#define MEMDBG_SCANNER_FLASHSCAN_H

#include "memdbg/core/memdbg_protocol.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FLASHSCAN_MAX_SESSIONS 12U

// Lifecycle
void flashscan_init(void);
void flashscan_cleanup_orphans(void);
void flashscan_free_slot(unsigned int slot);

// Handlers
int flashscan_handle_caps(int fd);
int flashscan_handle_config(int fd, const memdbg_quickscan_config_request_t *req,
                            const uint8_t *extra, uint32_t path_len);
int flashscan_handle_regions(int fd, const memdbg_quickscan_regions_request_t *req);
int flashscan_handle_start(int fd,
                           const memdbg_quickscan_start_request_t *req,
                           const uint8_t *compare_data, const uint8_t *mask,
                           unsigned int client_slot);
int flashscan_handle_count(int fd,
                           const memdbg_quickscan_count_request_t *req,
                           const uint8_t *compare_data, const uint8_t *mask,
                           unsigned int client_slot);
int flashscan_handle_fetch(int fd,
                           const memdbg_quickscan_fetch_request_t *req,
                           unsigned int client_slot);
int flashscan_handle_end(int fd, unsigned int client_slot);
int flashscan_handle_cancel(int fd, unsigned int client_slot);

static inline int snap_compare(const uint8_t *mem_p, const uint8_t *pattern,
                                const uint8_t *prev_p, const uint8_t *mask,
                                const uint8_t *between_hi,
                                uint32_t cmp_type, uint64_t vlen) {
  int matched;
  if (cmp_type == 0 && mask == NULL) {
    matched = (memcmp(mem_p, pattern, vlen) == 0);
  } else if (cmp_type == 4 && between_hi) {
    matched = (memcmp(mem_p, pattern, vlen) >= 0 &&
               memcmp(mem_p, between_hi, vlen) <= 0);
  } else if (cmp_type == 1) {
    matched = (memcmp(mem_p, pattern, vlen) > 0);
  } else if (cmp_type == 2) {
    matched = (memcmp(mem_p, pattern, vlen) < 0);
  } else if (cmp_type == 3 && prev_p) {
    matched = (memcmp(mem_p, prev_p, vlen) != 0);
  } else {
    int64_t dv = 0, pv = 0;
    if (vlen <= 8) {
      memcpy(&dv, mem_p, vlen);
      memcpy(&pv, pattern, vlen);
    }
    switch (cmp_type) {
    case 5: matched = (dv == pv); break;
    case 6: matched = (dv > pv); break;
    case 7: matched = (dv < pv); break;
    case 8: matched = (dv != pv); break;
    case 9: matched = (dv < pv || dv > pv); break;
    case 10: matched = (dv == pv); break;
    case 11: matched = (dv > pv); break;
    case 12: matched = (dv < pv); break;
    default: matched = (memcmp(mem_p, pattern, vlen) == 0); break;
    }
  }
  return matched;
}



#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SCANNER_FLASHSCAN_H */
