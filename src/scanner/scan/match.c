/*
 * memDBG - Boyer-Moore tables and match functions.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "scan_internal.h"

/* ---- Bad-character (BMH) skip table ---- */

void bm_build_bc_table(const unsigned char *pattern, size_t pat_len,
                              const unsigned char *mask, bm_table_t *table) {
  for (size_t i = 0U; i < BM_ALPHABET_SIZE; ++i)
    table->skip[i] = pat_len;
  for (size_t i = 0U; i < pat_len - 1U; ++i) {
    if (mask[i] != 0U) {
      /* Exact byte: only this byte skips to position i. */
      if (table->skip[pattern[i]] > pat_len - 1U - i)
        table->skip[pattern[i]] = pat_len - 1U - i;
    } else {
      /* Wildcard: ANY byte could match here, so cap the skip for
         every byte to at most pat_len - 1 - i.  This prevents the
         BMH bad-character heuristic from overshooting past a
         wildcard-tolerant alignment. */
      size_t cap = pat_len - 1U - i;
      for (size_t b = 0U; b < BM_ALPHABET_SIZE; ++b)
        if (table->skip[b] > cap)
          table->skip[b] = cap;
    }
  }
}

/* ---- Good-suffix shift table (Boyer-Moore) ----
 *
 * Only built for exact patterns (no wildcards) of length >= BM_GS_MIN_LENGTH.
 * This is O(pat_len) to build.  For wildcard patterns the gs_shift pointer
 * stays NULL and only bad-character shifts are used.
 *
 * Reference: Gusfield, "Algorithms on Strings, Trees, and Sequences", §2.2 */

bool bm_build_gs_table(const unsigned char *pattern, size_t pat_len,
                              bm_table_t *table) {
  if (pat_len < BM_GS_MIN_LENGTH) return true;

  table->gs_shift = (size_t *)malloc(pat_len * sizeof(size_t));
  if (table->gs_shift == NULL) return false;

  /* Compute suffix lengths: suffix[i] = length of the longest suffix of P[0..i]
     that matches a suffix of P.  Goodman-Liang algorithm, O(pat_len). */
  size_t *suffix = (size_t *)malloc(pat_len * sizeof(size_t));
  if (suffix == NULL) { free(table->gs_shift); table->gs_shift = NULL; return false; }

  /* Goodman-Liang suffix algorithm uses signed arithmetic: when the
     while-loop matches all the way past position 0, g becomes -1 and
     suffix[i] = f - g = f - (-1) = f + 1, which is the correct length.
     With unsigned size_t, g would wrap to SIZE_MAX and corrupt the result. */
  suffix[pat_len - 1U] = pat_len;
  ptrdiff_t f = 0, g = (ptrdiff_t)(pat_len - 1U);
  for (ptrdiff_t i = (ptrdiff_t)(pat_len - 2U); i >= 0; --i) {
    if (i > g && suffix[(size_t)i + pat_len - 1U - (size_t)f] < (size_t)(i - g)) {
      suffix[(size_t)i] = suffix[(size_t)i + pat_len - 1U - (size_t)f];
    } else {
      if (i < g) g = i;
      f = i;
      while (g >= 0 && pattern[(size_t)g] == pattern[(size_t)g + pat_len - 1U - (size_t)f])
        --g;
      suffix[i] = (size_t)(f - g);
    }
  }

  /* Build good-suffix shift table from suffix array.
     gs_shift[j] = shift to apply when a mismatch occurs at position j
     (0-indexed, j = position in pattern where mismatch happened). */
  for (size_t j = 0U; j < pat_len; ++j)
    table->gs_shift[j] = pat_len;

  /* Case 1: The matching suffix occurs elsewhere in the pattern. */
  size_t j = 0U;
  for (size_t i = pat_len - 1U; i != (size_t)-1; --i) {
    if (suffix[i] == i + 1U) {
      /* Full prefix of length i+1 matches suffix */
      for (; j < pat_len - 1U - i; ++j)
        if (table->gs_shift[j] == pat_len)
          table->gs_shift[j] = pat_len - 1U - i;
    }
  }

  /* Case 2: The longest suffix ending at i appears elsewhere. */
  for (size_t i = 0U; i <= pat_len - 2U; ++i) {
    size_t pos = pat_len - 1U - suffix[i];
    if (table->gs_shift[pos] > pat_len - 1U - i)
      table->gs_shift[pos] = pat_len - 1U - i;
  }

  free(suffix);
  return true;
}

void bm_build_table(const unsigned char *pattern, size_t pat_len,
                           const unsigned char *mask, bm_table_t *table) {
  memset(table, 0, sizeof(*table));
  bm_build_bc_table(pattern, pat_len, mask, table);

  /* Good-suffix only for exact patterns (no wildcards). */
  bool all_exact = true;
  for (size_t i = 0U; i < pat_len; ++i) {
    if (mask[i] == 0U) { all_exact = false; break; }
  }
  if (all_exact)
    bm_build_gs_table(pattern, pat_len, table);
  else
    table->gs_shift = NULL;
}

void bm_free_table(bm_table_t *table) {
  free(table->gs_shift);
  table->gs_shift = NULL;
}


/* ---- Value length helper ---- */

uint32_t expected_value_length(uint32_t value_type,
                                      uint32_t requested_length) {
  switch ((memdbg_value_type_t)value_type) {
  case MEMDBG_VALUE_U8:  return 1U;
  case MEMDBG_VALUE_U16: return 2U;
  case MEMDBG_VALUE_U32: case MEMDBG_VALUE_F32: return 4U;
  case MEMDBG_VALUE_U64: case MEMDBG_VALUE_F64: case MEMDBG_VALUE_POINTER: return 8U;
  case MEMDBG_VALUE_BYTES: default: return requested_length;
  }
}

/* ---- Loop-unrolled match functions ---- */

bool match_u8(const unsigned char *c, const unsigned char *n, size_t len) {
  (void)len; return c[0] == n[0];
}

bool match_u16(const unsigned char *c, const unsigned char *n, size_t len) {
  (void)len;
  /* Single uint16 comparison — compiler emits one load+cmp on LE targets. */
  uint16_t cv, nv;
  memcpy(&cv, c, sizeof(cv)); memcpy(&nv, n, sizeof(nv));
  return cv == nv;
}

bool match_u32(const unsigned char *c, const unsigned char *n, size_t len) {
  (void)len;
  uint32_t cv, nv;
  memcpy(&cv, c, sizeof(cv)); memcpy(&nv, n, sizeof(nv));
  return cv == nv;
}

bool match_u64(const unsigned char *c, const unsigned char *n, size_t len) {
  (void)len;
  uint64_t cv, nv;
  memcpy(&cv, c, sizeof(cv)); memcpy(&nv, n, sizeof(nv));
  return cv == nv;
}

bool match_bytes(const unsigned char *candidate,
                        const unsigned char *needle, size_t len) {
  return candidate[0] == needle[0] && memcmp(candidate, needle, len) == 0;
}

scan_match_fn_t match_fn_for(uint32_t value_len) {
  switch (value_len) {
  case 1U: return match_u8;
  case 2U: return match_u16;
  case 4U: return match_u32;
  case 8U: return match_u64;
  default: return match_bytes;
  }
}
