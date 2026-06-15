/*
 * memDBG - Memory debugger payload for jailbroken consoles.
 * Copyright (C) 2026 SeregonWar
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg/scanner/memdbg_scan.h"

#include "memdbg/debug/memdbg_memory.h"
#include "memdbg/debug/memdbg_process.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MEMDBG_SCAN_CHUNK (256U * 1024U)
#define MEMDBG_SCAN_INITIAL_CAPACITY 256U
#define MEMDBG_MAP_PROT_READ 1U

typedef bool (*scan_match_fn_t)(const unsigned char *candidate,
                                const unsigned char *needle, size_t len);

typedef struct scan_builder {
  memdbg_scan_result_t *result;
  size_t capacity;
  size_t max_results;
} scan_builder_t;

typedef struct scan_context {
  int pid;
  uint32_t value_type;
  uint32_t value_len;
  uint32_t alignment;
  unsigned char needle[MEMDBG_SCAN_VALUE_MAX];
  unsigned char *buffer;
  size_t buffer_size;
  scan_match_fn_t match;
} scan_context_t;

static uint64_t monotonic_ns(void) {
#if defined(CLOCK_MONOTONIC)
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
  }
#endif
  return 0U;
}

static uint32_t expected_value_length(uint32_t value_type,
                                      uint32_t requested_length) {
  switch ((memdbg_value_type_t)value_type) {
  case MEMDBG_VALUE_U8:
    return 1U;
  case MEMDBG_VALUE_U16:
    return 2U;
  case MEMDBG_VALUE_U32:
  case MEMDBG_VALUE_F32:
    return 4U;
  case MEMDBG_VALUE_U64:
  case MEMDBG_VALUE_F64:
  case MEMDBG_VALUE_POINTER:
    return 8U;
  case MEMDBG_VALUE_BYTES:
  default:
    return requested_length;
  }
}

static uint16_t load_u16(const unsigned char *p) {
  uint16_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}

static uint32_t load_u32(const unsigned char *p) {
  uint32_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}

static uint64_t load_u64(const unsigned char *p) {
  uint64_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}

static bool match_u8(const unsigned char *candidate,
                     const unsigned char *needle, size_t len) {
  (void)len;
  return candidate[0] == needle[0];
}

static bool match_u16(const unsigned char *candidate,
                      const unsigned char *needle, size_t len) {
  (void)len;
  return load_u16(candidate) == load_u16(needle);
}

static bool match_u32(const unsigned char *candidate,
                      const unsigned char *needle, size_t len) {
  (void)len;
  return load_u32(candidate) == load_u32(needle);
}

static bool match_u64(const unsigned char *candidate,
                      const unsigned char *needle, size_t len) {
  (void)len;
  return load_u64(candidate) == load_u64(needle);
}

static bool match_bytes(const unsigned char *candidate,
                        const unsigned char *needle, size_t len) {
  return candidate[0] == needle[0] && memcmp(candidate, needle, len) == 0;
}

static scan_match_fn_t match_fn_for(uint32_t value_len) {
  switch (value_len) {
  case 1U:
    return match_u8;
  case 2U:
    return match_u16;
  case 4U:
    return match_u32;
  case 8U:
    return match_u64;
  default:
    return match_bytes;
  }
}

static memdbg_status_t scan_builder_append(scan_builder_t *builder,
                                           uint64_t address) {
  memdbg_scan_result_t *result = builder->result;

  if (result->count >= builder->max_results) {
    result->truncated = true;
    return MEMDBG_OK;
  }

  if (result->count == builder->capacity) {
    size_t next_capacity =
        builder->capacity == 0U ? MEMDBG_SCAN_INITIAL_CAPACITY
                                : builder->capacity * 2U;
    if (next_capacity < builder->capacity ||
        next_capacity > builder->max_results) {
      next_capacity = builder->max_results;
    }
    if (next_capacity <= result->count) {
      result->truncated = true;
      return MEMDBG_OK;
    }

    memdbg_scan_result_entry_t *next =
        (memdbg_scan_result_entry_t *)realloc(
            result->entries, next_capacity * sizeof(*result->entries));
    if (next == NULL) {
      return MEMDBG_ERR_NOMEM;
    }
    result->entries = next;
    builder->capacity = next_capacity;
  }

  result->entries[result->count].address = address;
  result->count++;
  return MEMDBG_OK;
}

static size_t first_aligned_offset(uint64_t base, uint64_t alignment_base,
                                   uint64_t range_start, uint32_t alignment) {
  uint64_t offset = base < range_start ? range_start - base : 0U;

  if (alignment <= 1U) {
    return offset > (uint64_t)SIZE_MAX ? SIZE_MAX : (size_t)offset;
  }

  uint64_t address = base + offset;
  uint64_t misalignment = (address - alignment_base) % alignment;
  if (misalignment != 0U) {
    offset += (uint64_t)alignment - misalignment;
  }

  return offset > (uint64_t)SIZE_MAX ? SIZE_MAX : (size_t)offset;
}

static memdbg_status_t scan_window(scan_context_t *ctx, scan_builder_t *builder,
                                   size_t window, uint64_t base_addr,
                                   uint64_t alignment_base,
                                   uint64_t range_start, uint64_t range_end) {
  const uint32_t value_len = ctx->value_len;
  if (window < value_len) {
    return MEMDBG_OK;
  }

  size_t searchable = window - (size_t)value_len + 1U;

  if (value_len == 1U && ctx->alignment == 1U && base_addr >= range_start) {
    size_t pos = 0U;
    while (pos < searchable && !builder->result->truncated) {
      void *hit = memchr(ctx->buffer + pos, ctx->needle[0], searchable - pos);
      if (hit == NULL) {
        break;
      }
      size_t i = (size_t)((unsigned char *)hit - ctx->buffer);
      memdbg_status_t st = scan_builder_append(builder, base_addr + i);
      if (st != MEMDBG_OK) {
        return st;
      }
      pos = i + 1U;
    }
    return MEMDBG_OK;
  }

  size_t first = first_aligned_offset(base_addr, alignment_base, range_start,
                                      ctx->alignment);
  if (first == SIZE_MAX || first >= searchable) {
    return MEMDBG_OK;
  }

  for (size_t i = first; i < searchable && !builder->result->truncated;
       i += ctx->alignment) {
    uint64_t absolute = base_addr + i;
    if (absolute + value_len > range_end) {
      break;
    }
    if (ctx->match(ctx->buffer + i, ctx->needle, value_len)) {
      memdbg_status_t st = scan_builder_append(builder, absolute);
      if (st != MEMDBG_OK) {
        return st;
      }
    }
  }

  return MEMDBG_OK;
}

static memdbg_status_t scan_range(scan_context_t *ctx, scan_builder_t *builder,
                                  uint64_t range_start, uint64_t range_len,
                                  uint64_t alignment_base,
                                  bool skip_read_errors) {
  size_t overlap = ctx->value_len > 1U ? (size_t)ctx->value_len - 1U : 0U;
  uint64_t scanned = 0U;
  size_t carry = 0U;
  uint64_t range_end = range_start + range_len;

  while (scanned < range_len && !builder->result->truncated) {
    uint64_t remaining = range_len - scanned;
    size_t to_read =
        remaining > MEMDBG_SCAN_CHUNK ? MEMDBG_SCAN_CHUNK : (size_t)remaining;
    size_t read_len = 0U;

    builder->result->read_calls++;
    memdbg_status_t st =
        memdbg_memory_read(ctx->pid, range_start + scanned, ctx->buffer + carry,
                           to_read, &read_len);
    if (st != MEMDBG_OK) {
      builder->result->read_errors++;
      return skip_read_errors ? MEMDBG_OK : st;
    }
    if (read_len == 0U) {
      break;
    }
    builder->result->bytes_scanned += (uint64_t)read_len;

    size_t window = carry + read_len;
    uint64_t base_addr = range_start + scanned - (uint64_t)carry;
    st = scan_window(ctx, builder, window, base_addr, alignment_base,
                     range_start, range_end);
    if (st != MEMDBG_OK) {
      return st;
    }

    if (overlap != 0U) {
      carry = window < overlap ? window : overlap;
      memmove(ctx->buffer, ctx->buffer + window - carry, carry);
    }
    scanned += read_len;
  }

  return MEMDBG_OK;
}

static memdbg_status_t scan_context_init(scan_context_t *ctx, int pid,
                                         uint32_t value_type,
                                         uint32_t requested_value_len,
                                         uint32_t alignment,
                                         const uint8_t *value) {
  if (ctx == NULL || pid <= 0 || value == NULL) {
    return MEMDBG_ERR_PARAM;
  }

  memset(ctx, 0, sizeof(*ctx));
  ctx->pid = pid;
  ctx->value_type = value_type;
  ctx->value_len = expected_value_length(value_type, requested_value_len);
  ctx->alignment = alignment == 0U ? 1U : alignment;

  if (ctx->value_len == 0U || ctx->value_len > MEMDBG_SCAN_VALUE_MAX) {
    return MEMDBG_ERR_PARAM;
  }

  memcpy(ctx->needle, value, ctx->value_len);
  ctx->match = match_fn_for(ctx->value_len);
  ctx->buffer_size = MEMDBG_SCAN_CHUNK + (size_t)ctx->value_len - 1U;
  ctx->buffer = (unsigned char *)malloc(ctx->buffer_size);
  if (ctx->buffer == NULL) {
    return MEMDBG_ERR_NOMEM;
  }

  return MEMDBG_OK;
}

static void scan_context_fini(scan_context_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  free(ctx->buffer);
  memset(ctx, 0, sizeof(*ctx));
}

memdbg_status_t memdbg_scan_exact(const memdbg_scan_exact_request_t *request,
                                  memdbg_scan_result_t *out) {
  if (request == NULL || out == NULL) {
    return MEMDBG_ERR_PARAM;
  }
  memset(out, 0, sizeof(*out));

  if (request->length == 0U) {
    return MEMDBG_ERR_PARAM;
  }

  scan_context_t ctx;
  memdbg_status_t st =
      scan_context_init(&ctx, request->pid, request->value_type,
                        request->value_length, request->alignment,
                        request->value);
  if (st != MEMDBG_OK) {
    return st;
  }
  if (ctx.value_len > request->length) {
    scan_context_fini(&ctx);
    return MEMDBG_ERR_PARAM;
  }

  scan_builder_t builder;
  memset(&builder, 0, sizeof(builder));
  builder.result = out;
  builder.max_results =
      request->max_results == 0U ? 1U : (size_t)request->max_results;

  uint64_t start_ns = monotonic_ns();
  out->regions_scanned = 1U;
  st = scan_range(&ctx, &builder, request->start, request->length,
                  request->start, false);
  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) {
    out->elapsed_ns = end_ns - start_ns;
  }

  scan_context_fini(&ctx);
  if (st != MEMDBG_OK) {
    memdbg_scan_result_free(out);
  }
  return st;
}

memdbg_status_t
memdbg_scan_process_exact(const memdbg_scan_process_exact_request_t *request,
                          memdbg_scan_result_t *out) {
  if (request == NULL || out == NULL) {
    return MEMDBG_ERR_PARAM;
  }
  memset(out, 0, sizeof(*out));

  scan_context_t ctx;
  memdbg_status_t st =
      scan_context_init(&ctx, request->pid, request->value_type,
                        request->value_length, request->alignment,
                        request->value);
  if (st != MEMDBG_OK) {
    return st;
  }

  memdbg_map_list_t maps;
  st = memdbg_process_maps(request->pid, &maps);
  if (st != MEMDBG_OK) {
    scan_context_fini(&ctx);
    return st;
  }

  scan_builder_t builder;
  memset(&builder, 0, sizeof(builder));
  builder.result = out;
  builder.max_results =
      request->max_results == 0U ? 1U : (size_t)request->max_results;

  uint32_t prot_mask =
      request->protection_mask == 0U ? MEMDBG_MAP_PROT_READ
                                     : request->protection_mask;
  uint64_t start_ns = monotonic_ns();

  for (size_t i = 0U; i < maps.count && !out->truncated; ++i) {
    const memdbg_map_entry_t *map = &maps.entries[i];
    if ((map->protection & prot_mask) != prot_mask || map->end <= map->start) {
      continue;
    }

    uint64_t scan_start = map->start;
    uint64_t scan_end = map->end;
    if (request->start != 0U && scan_start < request->start) {
      scan_start = request->start;
    }
    if (request->end != 0U && scan_end > request->end) {
      scan_end = request->end;
    }
    if (scan_end <= scan_start || scan_end - scan_start < ctx.value_len) {
      continue;
    }

    out->regions_scanned++;
    st = scan_range(&ctx, &builder, scan_start, scan_end - scan_start,
                    scan_start, true);
    if (st != MEMDBG_OK) {
      break;
    }
  }

  uint64_t end_ns = monotonic_ns();
  if (start_ns != 0U && end_ns >= start_ns) {
    out->elapsed_ns = end_ns - start_ns;
  }

  memdbg_process_maps_free(&maps);
  scan_context_fini(&ctx);
  if (st != MEMDBG_OK) {
    memdbg_scan_result_free(out);
  }
  return st;
}

void memdbg_scan_result_free(memdbg_scan_result_t *result) {
  if (result == NULL) {
    return;
  }
  free(result->entries);
  memset(result, 0, sizeof(*result));
}
