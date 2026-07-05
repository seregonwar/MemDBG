/*
 * memDBG - Region name matching with wildcard glob and regex support.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Shared header providing region_name_matches() as a static inline so it can
 * be used in both the daemon (features.c) and unit tests without duplication.
 */

#ifndef MEMDBG_REGION_MATCH_H
#define MEMDBG_REGION_MATCH_H

#include <regex.h>
#include <stddef.h>
#include <string.h>

// Flag bits for matching behaviour (mirrors MEMDBG_MATCH_* from protocol)
#define RM_MATCH_EXACT          0x00000001U
#define RM_MATCH_CASE_SENSITIVE 0x00000002U
#define RM_MATCH_REGEX          0x00000004U
#define RM_MATCH_FULLPATH       0x00000008U

// Character comparison (case-sensitive or case-insensitive based on flags)
static inline int rm_char_eq(char a, char b, unsigned int match_flags) {
  if (match_flags & RM_MATCH_CASE_SENSITIVE) return a == b;
  if (a >= 'A' && a <= 'Z') a = (char)(a + ('a' - 'A'));
  if (b >= 'A' && b <= 'Z') b = (char)(b + ('a' - 'A'));
  return a == b;
}

// Glob match supporting * (matches zero or more characters).
// Uses rm_char_eq for case sensitivity control.
static inline int rm_glob_match(const char *pat, const char *str,
                                unsigned int match_flags) {
  const char *star = NULL, *ss = NULL;
  const char *p = pat, *s = str;

  while (*s) {
    if (*p == '*') {
      star = p++;
      ss = s;
    } else if (rm_char_eq(*p, *s, match_flags)) {
      p++; s++;
    } else if (star) {
      p = star + 1;
      s = ++ss;
    } else {
      return 0;
    }
  }

  while (*p == '*') p++;
  return *p == '\0';
}

// Returns 1 if target contains a wildcard ('*'), 0 otherwise.
static inline int rm_has_wildcard(const char *target) {
  return strchr(target, '*') != NULL;
}

// POSIX ERE (extended regex) match with case sensitivity control.
static inline int rm_regex_match(const char *pattern, const char *str,
                                 unsigned int match_flags) {
  if (!pattern || !str) return 0;

  int cflags = REG_EXTENDED | REG_NOSUB;
  if (!(match_flags & RM_MATCH_CASE_SENSITIVE)) cflags |= REG_ICASE;

  regex_t re;
  int rc = regcomp(&re, pattern, cflags);
  if (rc != 0) return 0;

  rc = regexec(&re, str, 0, NULL, 0);
  regfree(&re);
  return rc == 0;
}

// Match target_region against a VM map name.
// match_flags controls behaviour: RM_MATCH_EXACT skips substring fallback,
// RM_MATCH_CASE_SENSITIVE enables case-sensitive comparison,
// RM_MATCH_REGEX treats target as POSIX extended regex,
// RM_MATCH_FULLPATH matches against the full path instead of basename.
static inline int region_name_matches(const char *map_name, const char *target,
                                      unsigned int match_flags) {
  if (!map_name || !target || !*target) return 0;

  // Determine the lookup string: full path when FULLPATH, else basename
  const char *lookup;
  if (match_flags & RM_MATCH_FULLPATH) {
    lookup = map_name;
  } else {
    const char *basename = strrchr(map_name, '/');
    lookup = basename ? basename + 1 : map_name;
  }

  // Regex: try lookup first, then full map_name as fallback (unless FULLPATH)
  if (match_flags & RM_MATCH_REGEX) {
    if (rm_regex_match(target, lookup, match_flags)) return 1;
    if (!(match_flags & RM_MATCH_FULLPATH))
      return rm_regex_match(target, map_name, match_flags);
    return 0;
  }

  // Glob: try lookup first, then full map_name as fallback (unless FULLPATH)
  if (rm_has_wildcard(target)) {
    if (rm_glob_match(target, lookup, match_flags)) return 1;
    if (!(match_flags & RM_MATCH_FULLPATH))
      return rm_glob_match(target, map_name, match_flags);
    return 0;
  }

  // Equality
  const char *a = lookup, *b = target;
  while (*a && *b && rm_char_eq(*a, *b, match_flags)) { a++; b++; }
  if (*b == '\0' && *a == '\0') return 1;

  if (match_flags & RM_MATCH_EXACT) return 0;

  // Substring fallback on the full path (always uses full path for substring,
  // since basename is already checked via equality above)
  for (const char *s = map_name; *s; s++) {
    const char *p = s, *t = target;
    while (*p && *t && rm_char_eq(*p, *t, match_flags)) { p++; t++; }
    if (*t == '\0') return 1;
  }
  return 0;
}

#endif /* MEMDBG_REGION_MATCH_H */
