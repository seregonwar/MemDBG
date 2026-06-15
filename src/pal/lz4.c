/*
 * LZ4 - Fast LZ compression algorithm
 * Minimal, correct implementation for memDBG payload.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "lz4.h"
#include <string.h>

#define LZ4_HASHLOG       12U
#define LZ4_HASHTABLESIZE (1U << LZ4_HASHLOG)
#define LZ4_MIN_MATCH      4U
#define LZ4_MF_LIMIT      12U
#define LZ4_LASTLITERALS   5U
#define LZ4_MIN_CINPUT     0x20U
#define LZ4_STEPSIZE       8U

typedef uint32_t LZ4_hash_t;

static LZ4_hash_t lz4_hash_position(const void *p) {
  uint32_t v; memcpy(&v, p, sizeof(v));
  return (v * 2654435761U) >> (32U - LZ4_HASHLOG);
}

int lz4_compress_default(const char *src, char *dst, int src_size,
                         int dst_capacity) {
  if ((unsigned)src_size < LZ4_MIN_CINPUT || dst_capacity <= 0) return 0;

  const char *const src_end   = src + src_size;
  const char *const src_limit = src_end - LZ4_LASTLITERALS;
  const char *const src_mf    = src_end - LZ4_MF_LIMIT;
  const char *ip   = src;
  const char *anchor = ip;
  char *op = dst;
  const char *const oend = dst + dst_capacity;

  int table[LZ4_HASHTABLESIZE];
  { int i; for (i = 0; i < (int)LZ4_HASHTABLESIZE; ++i) table[i] = 0; }
  { LZ4_hash_t h = lz4_hash_position(ip);
    table[h] = (int)(ip - src); ip++; }

  for (;;) {
    const char *match = NULL;
    const char *forward_ip = ip;
    int step = 1, search_nb = 1 << LZ4_STEPSIZE;

    do {
      LZ4_hash_t h = lz4_hash_position(forward_ip);
      int ref_idx = table[h];
      table[h] = (int)(forward_ip - src);
      if (ref_idx == 0 || (forward_ip - (src + ref_idx)) > 65535 ||
          (forward_ip - (src + ref_idx)) <= 0) {
        forward_ip += step; step = (search_nb++ >> LZ4_STEPSIZE); continue;
      }
      if (memcmp(src + ref_idx, forward_ip, LZ4_MIN_MATCH) == 0) {
        match = src + ref_idx; goto _found;
      }
      forward_ip += step; step = (search_nb++ >> LZ4_STEPSIZE);
    } while (forward_ip <= src_mf);
    goto _last_literals;

  _found:
    { const char *p = ip;
      while (p < forward_ip && p <= src_mf) {
        LZ4_hash_t h2 = lz4_hash_position(p);
        table[h2] = (int)(p - src); p++;
      }
      ip = forward_ip; }

    /* ---- Encode literals (save token position for back-patch) ---- */
    { unsigned lit_len = (unsigned)(ip - anchor);
      if (op + 1 + (lit_len > 14 ? (lit_len - 14 + 254) / 255 : 0) + lit_len + 2 > oend) return 0;
      char *token_ptr = op;
      if (lit_len >= 15U) {
        *op++ = 0xF0U; unsigned rem = lit_len - 15U;
        while (rem >= 255U) { *op++ = 255U; rem -= 255U; }
        *op++ = (unsigned char)rem;
        if (lit_len > 0) memcpy(op, anchor, lit_len); op += lit_len;
      } else {
        *op++ = (unsigned char)(lit_len << 4U);
        if (lit_len > 0) memcpy(op, anchor, lit_len); op += lit_len;
      }

      /* ---- Encode offset ---- */
      { unsigned offset = (unsigned)(ip - match);
        *op++ = (unsigned char)offset; *op++ = (unsigned char)(offset >> 8); }

      /* ---- Compute match length and back-patch token ---- */
      { const char *me = ip + LZ4_MIN_MATCH;
        while (me < src_limit && *me == *match) { me++; match++; }
        unsigned mlen = (unsigned)(me - ip);
        if (mlen >= 19U) {
          *token_ptr |= 0x0FU;
          unsigned rem = mlen - 19U;
          while (rem >= 255U) { *op++ = 255U; rem -= 255U; }
          *op++ = (unsigned char)rem;
        } else {
          *token_ptr |= (unsigned char)(mlen - 4U);
        }
      }
    }

    ip += LZ4_MIN_MATCH; anchor = ip;
    if (ip > src_mf) break;
    continue;
  _last_literals: break;
  }

  /* ---- Last literals ---- */
  { unsigned last = (unsigned)(src_end - anchor);
    if (op + 1 + (last > 14 ? (last - 14 + 254) / 255 : 0) + last > oend) return 0;
    if (last >= 15U) {
      *op++ = 0xF0U; unsigned rem = last - 15U;
      while (rem >= 255U) { *op++ = 255U; rem -= 255U; }
      *op++ = (unsigned char)rem;
    } else { *op++ = (unsigned char)(last << 4U); }
    if (last > 0) memcpy(op, anchor, last);
    op += last;
  }
  return (int)(op - dst);
}

int lz4_decompress_safe(const char *src, char *dst, int compressed_size,
                        int dst_capacity) {
  const char *ip = src, *const iend = src + compressed_size;
  char *op = dst, *const oend = dst + dst_capacity;

  for (;;) {
    if (ip >= iend) return (int)(op - dst);
    unsigned token = (unsigned char)*ip++;

    { unsigned lit_len = token >> 4U;
      if (lit_len == 15U) { unsigned s; do { if (ip >= iend) return -1; s = (unsigned char)*ip++; lit_len += s; } while (s == 255U); }
      if (ip + lit_len > iend || op + lit_len > oend) return -1;
      memcpy(op, ip, lit_len); ip += lit_len; op += lit_len; }

    if (ip >= iend) break;

    if (ip + 1 >= iend) return -1;
    unsigned offset = (unsigned char)*ip++;
    offset |= ((unsigned)((unsigned char)*ip++) << 8U);
    if (offset == 0U) return -1;

    { unsigned mlen = (token & 0x0FU) + LZ4_MIN_MATCH;
      if ((token & 0x0FU) == 15U) { unsigned s; do { if (ip >= iend) return -1; s = (unsigned char)*ip++; mlen += s; } while (s == 255U); }
      if (op + mlen > oend || op - (int)offset < dst) return -1;
      { const char *ms = op - offset; unsigned r = mlen;
        while (r >= 8U) { memcpy(op, ms, 8U); op += 8U; ms += 8U; r -= 8U; }
        while (r--) *op++ = *ms++; }
    }
  }
  return (int)(op - dst);
}

int lz4_compress_bound(int input_size) {
  if (input_size < 0 || input_size > (int)LZ4_MAX_INPUT_SIZE) return 0;
  return input_size + (input_size / 255) + 16;
}
