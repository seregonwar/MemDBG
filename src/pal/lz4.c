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

typedef uint32_t LZ4_hash_t;

static LZ4_hash_t lz4_hash_position(const uint8_t *p) {
  uint32_t v;
  memcpy(&v, p, sizeof(v));
  return (v * 2654435761U) >> (32U - LZ4_HASHLOG);
}

static unsigned lz4_len_bytes(unsigned length, unsigned base) {
  if (length < base) return 0U;
  return 1U + ((length - base) / 255U);
}

static void lz4_write_len(uint8_t **op, unsigned length, unsigned base) {
  unsigned rem = length - base;
  while (rem >= 255U) {
    *(*op)++ = UINT8_MAX;
    rem -= 255U;
  }
  *(*op)++ = (uint8_t)rem;
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

  int table[LZ4_HASHTABLESIZE];
  for (unsigned i = 0; i < LZ4_HASHTABLESIZE; ++i) {
    table[i] = -1;
  }
  table[lz4_hash_position(src_base)] = 0;

  for (;;) {
    const uint8_t *match = NULL;
    const uint8_t *forward_ip = ip;
    int step = 1;
    unsigned search_nb = 1U << LZ4_STEPSIZE;

    do {
      LZ4_hash_t h = lz4_hash_position(forward_ip);
      int ref_idx = table[h];
      table[h] = (int)(forward_ip - src_base);
      if (ref_idx >= 0) {
        const uint8_t *candidate = src_base + ref_idx;
        ptrdiff_t distance = forward_ip - candidate;
        if (distance > 0 && distance <= 65535 &&
            memcmp(candidate, forward_ip, LZ4_MIN_MATCH) == 0) {
          match = candidate;
          break;
        }
      }
      forward_ip += step;
      step = (int)(search_nb++ >> LZ4_STEPSIZE);
    } while (forward_ip <= src_mf);

    if (match == NULL) break;

    for (const uint8_t *p = ip; p < forward_ip && p <= src_mf; ++p) {
      table[lz4_hash_position(p)] = (int)(p - src_base);
    }
    ip = forward_ip;

    const uint8_t *match_cursor = match + LZ4_MIN_MATCH;
    const uint8_t *match_end = ip + LZ4_MIN_MATCH;
    while (match_end < src_limit && *match_end == *match_cursor) {
      ++match_end;
      ++match_cursor;
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
      memcpy(op, anchor, literal_len);
      op += literal_len;
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
    while (match_len-- != 0U) {
      *op++ = *match++;
    }
  }

  return (int)(op - out_base);
}

int lz4_compress_bound(int input_size) {
  if (input_size < 0 || input_size > (int)LZ4_MAX_INPUT_SIZE) return 0;
  return input_size + (input_size / 255) + 16;
}
