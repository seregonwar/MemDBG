/*
 * memDBG - SIMD-accelerated scan comparisons (implementation).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/scanner/scan_simd.h"
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#endif

#if defined(__SSE2__) || defined(__AVX2__) || defined(__AVX__) || defined(__AVX512F__)
#include <emmintrin.h>
#endif
#if defined(__AVX2__) || defined(__AVX512F__)
#include <immintrin.h>
#endif
#if defined(__AVX512F__)
#include <zmmintrin.h>
#endif

int memdbg_simd_exact_available(uint32_t value_type, uint32_t value_length) {
  (void)value_type;
  (void)value_length;
#if defined(__aarch64__) && defined(__ARM_NEON)
  return (value_length == 1U || value_length == 2U ||
          value_length == 4U || value_length == 8U);
#elif defined(__SSE2__)
  return (value_length == 1U || value_length == 2U ||
          value_length == 4U || value_length == 8U);
#else
  return 0;
#endif
}

// Broadcast a value into a vector register

#if defined(__aarch64__) && defined(__ARM_NEON)
static uint8x16_t broadcast_value_neon(const uint8_t *v, uint32_t len) {
  switch (len) {
  case 1U: return vdupq_n_u8(v[0]);
  case 2U: return vreinterpretq_u8_u16(vdupq_n_u16(*(const uint16_t *)v));
  case 4U: return vreinterpretq_u8_u32(vdupq_n_u32(*(const uint32_t *)v));
  case 8U: return vreinterpretq_u8_u64(vdupq_n_u64(*(const uint64_t *)v));
  default: return vdupq_n_u8(0);
  }
}
#endif

#if defined(__AVX512F__)
static __m512i broadcast_value_avx512(const uint8_t *v, uint32_t len) {
  switch (len) {
  case 1U: return _mm512_set1_epi8((char)v[0]);
  case 2U: return _mm512_set1_epi16(*(const int16_t *)v);
  case 4U: return _mm512_set1_epi32(*(const int32_t *)v);
  case 8U: return _mm512_set1_epi64(*(const int64_t *)v);
  default: return _mm512_setzero_si512();
  }
}
#endif

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

#if defined(__SSE2__) && !defined(__AVX2__) && !defined(__AVX512F__)
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

#if defined(__aarch64__) && defined(__ARM_NEON)
  if (value_length <= 8U) {
    const size_t vec16 = 16U;
    uint8x16_t pat = broadcast_value_neon(needle, value_length);
    size_t limit = haystack_len - (size_t)value_length + 1U;

    size_t i = 0U;
    /* vec16 - value_length ensures the last SIMD window covers positions
     * up to limit-1.  Without this, the tail gap between the last aligned
     * 16-byte window and limit is silently skipped. */
    for (; i + (vec16 - value_length) < limit && count < max_offsets; i += vec16) {
      const uint8_t *ptr = haystack + i;
      if (value_length == 1U) {
        uint8x16_t chunk = vld1q_u8(ptr);
        uint8x16_t cmp   = vceqq_u8(chunk, pat);
        uint8_t lanes[16];
        vst1q_u8(lanes, cmp);
        for (int k = 0; k < 16 && count < max_offsets; k++) {
          if (lanes[k]) {
            size_t idx = i + (size_t)k;
            if (idx < limit) offsets[count++] = (uint32_t)idx;
          }
        }
      } else if (value_length == 2U) {
        /* Load as uint8x16 (same as 1-byte path), reinterpret to uint16x8.
         * Pre-cast pattern to uint16x8 once per call, outside the hot loop. */
        uint16x8_t pat16 = vreinterpretq_u16_u8(pat);
        uint8x16_t raw   = vld1q_u8(ptr);
        uint16x8_t chunk = vreinterpretq_u16_u8(raw);
        uint16x8_t cmp   = vceqq_u16(chunk, pat16);
        uint16_t lanes[8];
        vst1q_u16(lanes, cmp);
        for (int k = 0; k < 8 && count < max_offsets; k++) {
          if (lanes[k]) {
            size_t idx = i + (size_t)k * 2U;
            if (idx < limit) offsets[count++] = (uint32_t)idx;
          }
        }
      } else if (value_length == 4U) {
        uint32x4_t chunk = vld1q_u32((const uint32_t *)ptr);
        uint32x4_t cmp   = vceqq_u32(chunk, vreinterpretq_u32_u8(pat));
        /* Only 4 lanes — extract directly from registers, no store needed. */
        if (vgetq_lane_u32(cmp, 0) && count < max_offsets) {
          size_t idx = i;
          if (idx < limit) offsets[count++] = (uint32_t)idx;
        }
        if (vgetq_lane_u32(cmp, 1) && count < max_offsets) {
          size_t idx = i + 4U;
          if (idx < limit) offsets[count++] = (uint32_t)idx;
        }
        if (vgetq_lane_u32(cmp, 2) && count < max_offsets) {
          size_t idx = i + 8U;
          if (idx < limit) offsets[count++] = (uint32_t)idx;
        }
        if (vgetq_lane_u32(cmp, 3) && count < max_offsets) {
          size_t idx = i + 12U;
          if (idx < limit) offsets[count++] = (uint32_t)idx;
        }
      } else if (value_length == 8U) {
        uint64x2_t chunk = vld1q_u64((const uint64_t *)ptr);
        uint64x2_t cmp   = vceqq_u64(chunk, vreinterpretq_u64_u8(pat));
        if (vgetq_lane_u64(cmp, 0) != 0U && count < max_offsets) {
          size_t idx = i;
          if (idx < limit) offsets[count++] = (uint32_t)idx;
        }
        if (vgetq_lane_u64(cmp, 1) != 0U && count < max_offsets) {
          size_t idx = i + 8U;
          if (idx < limit) offsets[count++] = (uint32_t)idx;
        }
      }
    }

    /* Tail: process remaining positions (up to 15) with scalar memcmp.
     * Needed because the SIMD loop advances by vec16 (16 bytes). */
    for (; i < limit && count < max_offsets; i += value_length) {
      if (memcmp(haystack + i, needle, value_length) == 0)
        offsets[count++] = (uint32_t)i;
    }

    return count;
  }
#elif defined(__AVX512F__) && defined(__AVX512BW__)
  if (value_length <= 8U) {
    const size_t vec64 = 64U;
    __m512i pat = broadcast_value_avx512(needle, value_length);
    size_t limit = haystack_len - (size_t)value_length + 1U;

    size_t i = 0U;
    for (; i + (vec64 - value_length) < limit && count < max_offsets; i += vec64) {
      const uint8_t *ptr = haystack + i;
      if (value_length == 1U) {
        __m512i chunk = _mm512_loadu_si512((const __m512i *)ptr);
        __mmask64 mask = _mm512_cmpeq_epi8_mask(chunk, pat);
        while (mask != 0U && count < max_offsets) {
          uint32_t bit = (uint32_t)__builtin_ctzll(mask);
          size_t idx = i + bit;
          if (idx < limit) { offsets[count++] = (uint32_t)idx; }
          mask &= mask - 1U;
        }
      } else if (value_length == 2U) {
        __m512i chunk = _mm512_loadu_si512((const __m512i *)ptr);
        __mmask32 mask = _mm512_cmpeq_epi16_mask(chunk, pat);
        while (mask != 0U && count < max_offsets) {
          uint32_t bit = (uint32_t)__builtin_ctz(mask);
          size_t idx = i + (size_t)bit * 2U;
          if (idx < limit) offsets[count++] = (uint32_t)idx;
          mask &= mask - 1U;
        }
      } else if (value_length == 4U) {
        __m512i chunk = _mm512_loadu_si512((const __m512i *)ptr);
        __mmask16 mask = _mm512_cmpeq_epi32_mask(chunk, pat);
        while (mask != 0U && count < max_offsets) {
          uint32_t bit = (uint32_t)__builtin_ctz(mask);
          size_t idx = i + (size_t)bit * 4U;
          if (idx < limit) offsets[count++] = (uint32_t)idx;
          mask &= mask - 1U;
        }
      } else if (value_length == 8U) {
        __m512i chunk = _mm512_loadu_si512((const __m512i *)ptr);
        __mmask8 mask = _mm512_cmpeq_epi64_mask(chunk, pat);
        while (mask != 0U && count < max_offsets) {
          uint32_t bit = (uint32_t)__builtin_ctz(mask);
          size_t idx = i + (size_t)bit * 8U;
          if (idx < limit) offsets[count++] = (uint32_t)idx;
          mask &= mask - 1U;
        }
      }
    }

    for (; i < limit && count < max_offsets; i += value_length) {
      if (memcmp(haystack + i, needle, value_length) == 0)
        offsets[count++] = (uint32_t)i;
    }

    return count;
  }
#elif defined(__AVX2__) && defined(__SSE2__)
  if (value_length <= 8U) {
    const size_t vec32 = 32U;
    __m256i pat = broadcast_value_avx2(needle, value_length);
    size_t limit = haystack_len - (size_t)value_length + 1U;

    size_t i = 0U;
    for (; i + (vec32 - value_length) < limit && count < max_offsets; i += vec32) {
      const uint8_t *ptr = haystack + i;
      if (value_length == 1U) {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)ptr);
        __m256i cmp   = _mm256_cmpeq_epi8(chunk, pat);
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(cmp);
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
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(cmp);
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
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(cmp);
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

    for (; i < limit && count < max_offsets; i += value_length) {
      if (memcmp(haystack + i, needle, value_length) == 0)
        offsets[count++] = (uint32_t)i;
    }

    return count;
  }
#elif defined(__SSE2__)
  if (value_length <= 8U) {
    const size_t vec16 = 16U;
    __m128i pat = broadcast_value_sse2(needle, value_length);
    size_t limit = haystack_len - (size_t)value_length + 1U;

    size_t i = 0U;
    for (; i + (vec16 - value_length) < limit && count < max_offsets; i += vec16) {
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
        /* SSE2 has no native 64-bit movemask.  Use _mm_cmpeq_epi64 +
         * _mm_extract_epi64 on SSE4.1+, scalar fallback otherwise. */
#if defined(__SSE4_1__)
        __m128i chunk = _mm_loadu_si128((const __m128i *)ptr);
        __m128i cmp   = _mm_cmpeq_epi64(chunk, pat);
        if (_mm_extract_epi64(cmp, 0) && count < max_offsets) {
          size_t idx = i;
          if (idx < limit) offsets[count++] = (uint32_t)idx;
        }
        if (_mm_extract_epi64(cmp, 1) && count < max_offsets) {
          size_t idx = i + 8U;
          if (idx < limit) offsets[count++] = (uint32_t)idx;
        }
#else
        /* SSE2-only: scalar comparison for the 2 × 8-byte lanes
         * within the 16-byte window. */
        for (uint32_t k = 0U; k < 2U; k++) {
          int64_t v, n;
          memcpy(&v, ptr + k * 8U, sizeof(v));
          memcpy(&n, needle, sizeof(n));
          if (v == n && count < max_offsets) {
            size_t idx = i + (size_t)k * 8U;
            if (idx < limit) offsets[count++] = (uint32_t)idx;
          }
        }
#endif
      }
    }

    for (; i < limit && count < max_offsets; i += value_length) {
      if (memcmp(haystack + i, needle, value_length) == 0)
        offsets[count++] = (uint32_t)i;
    }

    return count;
  }
#endif

  /* Scalar fallback — replace memcmp with typed comparisons for the
   * small value lengths (1/2/4/8) used in scan operations. */
  size_t limit = haystack_len - (size_t)value_length + 1U;
  for (size_t i = 0U; i < limit && count < max_offsets; i += value_length) {
    int match = 0;
    switch (value_length) {
    case 1U:  match = (haystack[i] == needle[0]); break;
    case 2U: {
      uint16_t hv, nv;
      memcpy(&hv, haystack + i, sizeof(hv));
      memcpy(&nv, needle, sizeof(nv));
      match = (hv == nv);
      break;
    }
    case 4U: {
      uint32_t hv, nv;
      memcpy(&hv, haystack + i, sizeof(hv));
      memcpy(&nv, needle, sizeof(nv));
      match = (hv == nv);
      break;
    }
    case 8U: {
      uint64_t hv, nv;
      memcpy(&hv, haystack + i, sizeof(hv));
      memcpy(&nv, needle, sizeof(nv));
      match = (hv == nv);
      break;
    }
    default:
      match = (memcmp(haystack + i, needle, value_length) == 0);
      break;
    }
    if (match)
      offsets[count++] = (uint32_t)i;
  }

  return count;
}
