/*
 * memDBG - Shared benchmark utilities.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Common timing and data-generation helpers used by benchmarks.
 */

#ifndef MEMDBG_TESTS_BENCH_UTILS_H
#define MEMDBG_TESTS_BENCH_UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Monotonic nanosecond timer. */
static inline uint64_t bench_now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Fill buffer with deterministic pseudo-random pattern. */
static inline void bench_fill_pattern(uint8_t *buf, size_t len, uint64_t seed) {
  for (size_t i = 0; i < len; ++i)
    buf[i] = (uint8_t)((seed + i * 0x9E3779B9ULL) & 0xFFU);
}

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_TESTS_BENCH_UTILS_H */
