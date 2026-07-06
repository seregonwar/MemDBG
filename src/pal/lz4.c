/*
 * LZ4 - Fast LZ compression algorithm
 * Minimal, correct implementation for memDBG payload.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "memdbg/pal/lz4.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define LZ4_HASHLOG       12U
#define LZ4_HASHTABLESIZE (1U << LZ4_HASHLOG)
#define LZ4_MIN_MATCH      4U
#define LZ4_MF_LIMIT      12U
#define LZ4_LASTLITERALS   5U
#define LZ4_MIN_CINPUT     0x20U
#define LZ4_STEPSIZE       8U

/*
 * Generation-counter hash table.
 *
 * Instead of memset(table, -1, 16KB) on every call, entries pack a
 * 12-bit generation counter in the upper bits and a 20-bit position
 * offset in the lower bits.  Incrementing the generation on each call
 * invalidates all entries from the previous call with zero cost.
 *
 * 20 position bits support inputs up to 1 MiB — the typical memDBG
 * framed-packet payload.  For larger inputs, we fall back to the
 * traditional memset path.
 */
#define LZ4_POS_BITS   20U
#define LZ4_POS_MASK   ((1U << LZ4_POS_BITS) - 1U)
#define LZ4_GEN_SHIFT  LZ4_POS_BITS
#define LZ4_GEN_MASK   ((1U << 12U) - 1U)
#define LZ4_GEN_MAX    LZ4_GEN_MASK

#if defined(_MSC_VER)
#define LZ4_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define LZ4_THREAD_LOCAL _Thread_local
#else
#define LZ4_THREAD_LOCAL __thread
#endif

typedef uint32_t LZ4_hash_t;

/*
 * Per-thread table + generation counter.
 *
 * _Thread_local keeps each thread's table isolated (no races) while
 * avoiding a 16-KiB stack allocation per call.  The generation counter
 * eliminates the per-call memset for inputs up to 1 MiB.
 */
static LZ4_THREAD_LOCAL uint32_t lz4_ht[LZ4_HASHTABLESIZE];
static LZ4_THREAD_LOCAL uint32_t lz4_ht_gen;

static LZ4_hash_t lz4_hash_position(const uint8_t *p) {
  uint32_t v;
  memcpy(&v, p, sizeof(v));
  return (v * 2654435761U) >> (32U - LZ4_HASHLOG);
}

static unsigned lz4_len_bytes(unsigned length, unsigned base) {
  if (length < base) return 0U;
  return 1U + ((length - base) / 255U);
}

static unsigned lz4_first_diff_byte(uint64_t diff) {
#if defined(__GNUC__) || defined(__clang__)
  return (unsigned)__builtin_ctzll(diff) >> 3;
#else
  unsigned byte = 0U;
  while ((diff & 0xFFU) == 0U) {
    diff >>= 8U;
    ++byte;
  }
  return byte;
#endif
}

static void lz4_write_len(uint8_t **op, unsigned length, unsigned base) {
  unsigned rem = length - base;
  while (rem >= 255U) {
    *(*op)++ = UINT8_MAX;
    rem -= 255U;
  }
  *(*op)++ = (uint8_t)rem;
}

/*
 * Put a position into the hash table for the current generation.
 */
static void lz4_ht_put(LZ4_hash_t h, unsigned pos) {
  lz4_ht[h] = (lz4_ht_gen << LZ4_GEN_SHIFT) | (pos & LZ4_POS_MASK);
}

/*
 * Look up a hash bucket.  Returns the stored position, or -1 if the
 * entry belongs to a previous generation (stale) or was never written.
 */
static int lz4_ht_get(LZ4_hash_t h) {
  uint32_t entry = lz4_ht[h];
  if ((entry >> LZ4_GEN_SHIFT) != lz4_ht_gen)
    return -1;
  return (int)(entry & LZ4_POS_MASK);
}

int lz4_compress_default(const char *src, char *dst, int src_size,
                         int dst_capacity) {
  if (src == NULL || dst == NULL || src_size < (int)LZ4_MIN_CINPUT ||
      dst_capacity <= 0) {
    return 0;
  }

  const uint8_t *const src_base = (const uint8_t *)(const void *)src;
  const uint8_t *const src_end = src_base + (size_t)src_size;
  const uint8_t *const src_limit = src_end - LZ4_LASTLITERALS;
  const uint8_t *const src_mf = src_end - LZ4_MF_LIMIT;
  const uint8_t *ip = src_base + 1U;
  const uint8_t *anchor = src_base;
  uint8_t *op = (uint8_t *)(void *)dst;
  uint8_t *const oend = op + (size_t)dst_capacity;

  /*
   * Advance generation counter and decide table-init strategy.
   *
   * If the input fits in 20 bits of position space (≤ 1 MiB) we use
   * the fast generation-counter path.  For larger inputs we fall back
   * to a traditional full-table memset.
   */
  lz4_ht_gen = (lz4_ht_gen + 1U) & LZ4_GEN_MASK;
  if (lz4_ht_gen == 0U) {
    /* Generation wrapped — force a full reset to avoid stale entries
     * from 4096 calls ago becoming visible again.  This happens once
     * every 4096 calls, amortising the 16-KiB memset cost. */
    memset(lz4_ht, 0xFF, sizeof(lz4_ht));
  }
  if ((size_t)src_size <= (size_t)LZ4_POS_MASK) {
    /* Fast path: generation counter invalidates all old entries.
     * No per-call memset needed. */
  } else {
    /* Slow path: position won't fit in 20 bits; full reset. */
    memset(lz4_ht, 0xFF, sizeof(lz4_ht));
    lz4_ht_gen = 0U;
  }

  lz4_ht_put(lz4_hash_position(src_base), 0U);

  for (;;) {
    const uint8_t *match = NULL;
    const uint8_t *forward_ip = ip;
    int step = 1;
    unsigned search_nb = 1U << LZ4_STEPSIZE;

    do {
      LZ4_hash_t h = lz4_hash_position(forward_ip);
      int ref_idx = lz4_ht_get(h);
      lz4_ht_put(h, (unsigned)(forward_ip - src_base));
      if (ref_idx >= 0) {
        const uint8_t *candidate = src_base + ref_idx;
        ptrdiff_t distance = forward_ip - candidate;
        if (distance > 0 && distance <= 65535) {
          /* Direct 32-bit comparison avoids memcmp call overhead
           * in the hot match-finding loop (LZ4_MIN_MATCH == 4). */
          uint32_t cv, fv;
          memcpy(&cv, candidate, sizeof(cv));
          memcpy(&fv, forward_ip, sizeof(fv));
          if (cv == fv) {
            match = candidate;
            break;
          }
        }
      }
      forward_ip += step;
      step = (int)(search_nb++ >> LZ4_STEPSIZE);
    } while (forward_ip <= src_mf);

    if (match == NULL) break;

    for (const uint8_t *p = ip; p < forward_ip && p <= src_mf; ++p) {
      lz4_ht_put(lz4_hash_position(p), (unsigned)(p - src_base));
    }
    ip = forward_ip;

    const uint8_t *match_cursor = match + LZ4_MIN_MATCH;
    const uint8_t *match_end = ip + LZ4_MIN_MATCH;

    /* Word-at-a-time match extension: compare 8 bytes per iteration
     * using 64-bit XOR.  lz4_first_diff_byte finds the first differing
     * byte without branching on every byte on compilers with ctz support,
     * and falls back to a tiny byte loop elsewhere.
     *
     * The remaining-byte guard keeps pointer arithmetic inside the source
     * object while preserving the mandatory LZ4_LASTLITERALS (5)
     * trailing-literal region, since src_limit = src_end - 5. */
    int ext_early = 0;
    while ((size_t)(src_limit - match_end) >= 8U) {
      uint64_t a, b;
      memcpy(&a, match_end, 8);
      memcpy(&b, match_cursor, 8);
      if (a != b) {
        unsigned tz = lz4_first_diff_byte(a ^ b);
        match_end += tz;
        ext_early = 1;
        break;
      }
      match_end += 8U;
      match_cursor += 8U;
    }
    /* Tail: byte-by-byte for the remaining < 8 bytes. */
    if (!ext_early) {
      while (match_end < src_limit && *match_end == *match_cursor) {
        ++match_end;
        ++match_cursor;
      }
    }

    unsigned literal_len = (unsigned)(ip - anchor);
    unsigned match_len = (unsigned)(match_end - ip);
    unsigned match_token = match_len - LZ4_MIN_MATCH;
    unsigned needed = 1U + literal_len + 2U;
    needed += literal_len >= 15U ? lz4_len_bytes(literal_len, 15U) : 0U;
    needed += match_token >= 15U ? lz4_len_bytes(match_token, 15U) : 0U;
    if ((size_t)(oend - op) < needed) return 0;

    uint8_t *token = op++;
    if (literal_len >= 15U) {
      *token = 0xF0U;
      lz4_write_len(&op, literal_len, 15U);
    } else {
      *token = (uint8_t)(literal_len << 4U);
    }

    if (literal_len > 0U) {
      /* Fast wildcopy for short literals when the caller's output buffer has
       * room for the full 8-byte store.  The source read is safe here because
       * matches are found at or before src_mf (src_end - LZ4_MF_LIMIT). */
      if (literal_len <= 8U && (size_t)(oend - op) >= 8U) {
        uint64_t v;
        memcpy(&v, anchor, 8);
        memcpy(op, &v, 8);
        op += literal_len;
      } else {
        memcpy(op, anchor, literal_len);
        op += literal_len;
      }
    }

    unsigned offset = (unsigned)(ip - match);
    *op++ = (uint8_t)(offset & 0xFFU);
    *op++ = (uint8_t)((offset >> 8U) & 0xFFU);

    if (match_token >= 15U) {
      *token |= 0x0FU;
      lz4_write_len(&op, match_token, 15U);
    } else {
      *token |= (uint8_t)match_token;
    }

    ip = match_end;
    anchor = ip;
    if (ip > src_mf) break;
  }

  unsigned last = (unsigned)(src_end - anchor);
  unsigned needed = 1U + last;
  needed += last >= 15U ? lz4_len_bytes(last, 15U) : 0U;
  if ((size_t)(oend - op) < needed) return 0;

  if (last >= 15U) {
    *op++ = 0xF0U;
    lz4_write_len(&op, last, 15U);
  } else {
    *op++ = (uint8_t)(last << 4U);
  }
  if (last > 0U) {
    memcpy(op, anchor, last);
    op += last;
  }

  return (int)(op - (uint8_t *)(void *)dst);
}

int lz4_decompress_safe(const char *src, char *dst, int compressed_size,
                        int dst_capacity) {
  if (src == NULL || dst == NULL || compressed_size < 0 || dst_capacity < 0) {
    return -1;
  }

  const uint8_t *ip = (const uint8_t *)(const void *)src;
  const uint8_t *const iend = ip + (size_t)compressed_size;
  uint8_t *op = (uint8_t *)(void *)dst;
  uint8_t *const out_base = op;
  uint8_t *const oend = op + (size_t)dst_capacity;

  for (;;) {
    if (ip >= iend) return (int)(op - out_base);
    unsigned token = *ip++;

    unsigned lit_len = token >> 4U;
    if (lit_len == 15U) {
      unsigned s;
      do {
        if (ip >= iend) return -1;
        s = *ip++;
        lit_len += s;
      } while (s == 255U);
    }
    if ((size_t)(iend - ip) < lit_len || (size_t)(oend - op) < lit_len) {
      return -1;
    }
    if (lit_len > 0U) {
      memcpy(op, ip, lit_len);
      ip += lit_len;
      op += lit_len;
    }

    if (ip >= iend) break;
    if ((size_t)(iend - ip) < 2U) return -1;

    unsigned offset = ip[0];
    offset |= (unsigned)ip[1] << 8U;
    ip += 2U;
    if (offset == 0U || (size_t)(op - out_base) < offset) return -1;

    unsigned match_len = (token & 0x0FU) + LZ4_MIN_MATCH;
    if ((token & 0x0FU) == 15U) {
      unsigned s;
      do {
        if (ip >= iend) return -1;
        s = *ip++;
        match_len += s;
      } while (s == 255U);
    }
    if ((size_t)(oend - op) < match_len) return -1;

    const uint8_t *match = op - offset;
    /* Word-at-a-time match copy.  For offset ≥ 8 the source is safely
     * behind the destination (no overlap within 8-byte window).
     * For small offsets we use pattern duplication to prime enough
     * bytes for the word-at-a-time loop to take over safely. */
    if (offset >= 8U) {
      while (match_len >= 8U) {
        uint64_t v;
        memcpy(&v, match, 8);
        memcpy(op, &v, 8);
        match += 8U;
        op    += 8U;
        match_len -= 8U;
      }
      while (match_len-- != 0U)
        *op++ = *match++;
    } else if (offset == 1U) {
      /* Single-byte repeat → memset. */
      memset(op, match[0], match_len);
      op += match_len;
    } else {
      /* offset ∈ {2,3,4,5,6,7}: overlapping copy — byte-by-byte is
       * the simplest correct approach since the source and destination
       * can overlap within an 8-byte window.  These small offsets are
       * the minority case in real-world LZ4 streams. */
      while (match_len-- != 0U)
        *op++ = *match++;
    }
  }

  return (int)(op - out_base);
}

int lz4_compress_bound(int input_size) {
  if (input_size < 0 || input_size > (int)LZ4_MAX_INPUT_SIZE) return 0;
  return input_size + (input_size / 255) + 16;
}
