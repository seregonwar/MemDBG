/*
 * memDBG - SIMD-accelerated scan comparisons (implementation).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scan_simd.h"
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__SSE2__) || defined(__AVX2__) || defined(__AVX__)
#include <emmintrin.h>
#endif
#if defined(__AVX2__)
#include <immintrin.h>
#endif

int memdbg_simd_exact_available(uint32_t value_type, uint32_t value_length) {
  (void)value_type;
  (void)value_length;
#if defined(__SSE2__)
  return (value_length == 1U || value_length == 2U ||
          value_length == 4U || value_length == 8U);
#else
  return 0;
#endif
}

// Broadcast a value into a vector register

#if defined(__AVX2__)
static __m256i broadcast_value_avx2(const uint8_t *v, uint32_t len) {
  switch (len) {
  case 1U: return _mm256_set1_epi8((char)v[0]);
  case 2U: return _mm256_set1_epi16(*(const int16_t *)v);
  case 4U: return _mm256_set1_epi32(*(const int32_t *)v);
  case 8U: return _mm256_set1_epi64x(*(const int64_t *)v);
  default: return _mm256_setzero_si256();
  }
}
#endif

#if defined(__SSE2__)
static __m128i broadcast_value_sse2(const uint8_t *v, uint32_t len) {
  switch (len) {
  case 1U: return _mm_set1_epi8((char)v[0]);
  case 2U: return _mm_set1_epi16(*(const int16_t *)v);
  case 4U: return _mm_set1_epi32(*(const int32_t *)v);
  case 8U: return _mm_set1_epi64x(*(const int64_t *)v);
  default: return _mm_setzero_si128();
  }
}
#endif

size_t memdbg_simd_find_exact(uint32_t value_type,
                              const uint8_t *haystack, size_t haystack_len,
                              const uint8_t *needle, uint32_t value_length,
                              uint32_t *offsets, size_t max_offsets) {
  (void)value_type;
  if (haystack_len < value_length || max_offsets == 0U) return 0U;

  size_t count = 0U;

#if defined(__AVX2__) && defined(__SSE2__)
  if (value_length <= 8U) {
    const size_t vec32 = 32U;
    __m256i pat = broadcast_value_avx2(needle, value_length);
    size_t limit = haystack_len - (size_t)value_length + 1U;

    size_t i = 0U;
    for (; i + vec32 <= limit && count < max_offsets; i += value_length) {
      const uint8_t *ptr = haystack + i;
      if (value_length == 1U) {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)ptr);
        __m256i cmp   = _mm256_cmpeq_epi8(chunk, pat);
        uint32_t mask = _mm256_movemask_epi8(cmp);
        while (mask != 0U && count < max_offsets) {
          uint32_t bit = (uint32_t)__builtin_ctz(mask);
          size_t idx = i + bit;
          if (idx < limit) { offsets[count++] = (uint32_t)idx; }
          mask &= mask - 1U;
        }
      } else if (value_length == 2U) {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)ptr);
        __m256i cmp   = _mm256_cmpeq_epi16(chunk, pat);
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(cmp);
        while (mask != 0U && count < max_offsets) {
          uint32_t bit = (uint32_t)__builtin_ctz(mask);
          if ((bit & 1U) == 0U) {
            size_t idx = i + bit;
            if (idx < limit) offsets[count++] = (uint32_t)idx;
          }
          mask &= mask - 1U;
        }
      } else if (value_length == 4U) {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)ptr);
        __m256i cmp   = _mm256_cmpeq_epi32(chunk, pat);
        uint32_t mask = _mm256_movemask_epi8(cmp);
        while (mask != 0U && count < max_offsets) {
          uint32_t bit = (uint32_t)__builtin_ctz(mask);
          if ((bit & 3U) == 0U) {
            size_t idx = i + bit;
            if (idx < limit) offsets[count++] = (uint32_t)idx;
          }
          mask &= mask - 1U;
        }
      } else if (value_length == 8U) {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)ptr);
        __m256i cmp   = _mm256_cmpeq_epi64(chunk, pat);
        uint32_t mask = _mm256_movemask_epi8(cmp);
        while (mask != 0U && count < max_offsets) {
          uint32_t bit = (uint32_t)__builtin_ctz(mask);
          if ((bit & 7U) == 0U) {
            size_t idx = i + bit;
            if (idx < limit) offsets[count++] = (uint32_t)idx;
          }
          mask &= mask - 1U;
        }
      }
    }

    return count;
  }
#elif defined(__SSE2__)
  if (value_length <= 8U) {
    const size_t vec16 = 16U;
    __m128i pat = broadcast_value_sse2(needle, value_length);
    size_t limit = haystack_len - (size_t)value_length + 1U;

    size_t i = 0U;
    for (; i + vec16 <= limit && count < max_offsets; i += value_length) {
      const uint8_t *ptr = haystack + i;
      if (value_length == 1U) {
        __m128i chunk = _mm_loadu_si128((const __m128i *)ptr);
        __m128i cmp   = _mm_cmpeq_epi8(chunk, pat);
        uint32_t mask = (uint32_t)_mm_movemask_epi8(cmp);
        while (mask != 0U && count < max_offsets) {
          uint32_t bit = (uint32_t)__builtin_ctz(mask);
          size_t idx = i + bit;
          if (idx < limit) { offsets[count++] = (uint32_t)idx; }
          mask &= mask - 1U;
        }
      } else if (value_length == 2U) {
        __m128i chunk = _mm_loadu_si128((const __m128i *)ptr);
        __m128i cmp   = _mm_cmpeq_epi16(chunk, pat);
        uint32_t mask = (uint32_t)_mm_movemask_epi8(cmp);
        while (mask != 0U && count < max_offsets) {
          uint32_t bit = (uint32_t)__builtin_ctz(mask);
          if ((bit & 1U) == 0U) {
            size_t idx = i + bit;
            if (idx < limit) offsets[count++] = (uint32_t)idx;
          }
          mask &= mask - 1U;
        }
      } else if (value_length == 4U) {
        __m128i chunk = _mm_loadu_si128((const __m128i *)ptr);
        __m128i cmp   = _mm_cmpeq_epi32(chunk, pat);
        uint32_t mask = (uint32_t)_mm_movemask_epi8(cmp);
        while (mask != 0U && count < max_offsets) {
          uint32_t bit = (uint32_t)__builtin_ctz(mask);
          if ((bit & 3U) == 0U) {
            size_t idx = i + bit;
            if (idx < limit) offsets[count++] = (uint32_t)idx;
          }
          mask &= mask - 1U;
        }
      } else if (value_length == 8U) {
        __m128i *chunk_p = (__m128i *)ptr;
        uint32_t max_check = (uint32_t)(limit - i) >> 3;
        for (uint32_t k = 0U; k < 4U && k < max_check; k++) {
          int64_t v;
          memcpy(&v, ptr + k * 8U, sizeof(v));
          int64_t n;
          memcpy(&n, needle, sizeof(n));
          if (v == n && count < max_offsets) {
            offsets[count++] = (uint32_t)(i + k * 8U);
          }
        }
      }
    }

    return count;
  }
#endif

  size_t limit = haystack_len - (size_t)value_length + 1U;
  for (size_t i = 0U; i < limit && count < max_offsets; i += value_length) {
    if (memcmp(haystack + i, needle, value_length) == 0)
      offsets[count++] = (uint32_t)i;
  }

  return count;
}
