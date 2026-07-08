/*
 * sJson v1.1.0 — safe, fast, single-header JSON library in C99.
 * SPDX-License-Identifier: GPL-3.0-only OR MIT
 *
 * This file is dual-licensed under GPL-3.0-only OR MIT.
 * You may choose either license.
 */

#ifndef JSON_PAL_H
#define JSON_PAL_H

/* ============================================================================
 * §1  PLATFORM DETECTION
 * ============================================================================ */

#if defined(_MSC_VER)
#  define JSON_CC_MSVC   1
#elif defined(__clang__)
#  define JSON_CC_CLANG  1
#elif defined(__GNUC__)
#  define JSON_CC_GCC    1
#else
#  define JSON_CC_OTHER  1
#endif

#if defined(_WIN32) || defined(_WIN64)
#  define JSON_OS_WINDOWS 1
#elif defined(__linux__)
#  define JSON_OS_LINUX   1
#elif defined(__APPLE__)
#  define JSON_OS_APPLE   1
#else
#  define JSON_OS_BAREMETAL 1   /* Embedded / RTOS */
#endif

/* Endianness */
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
#  if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#    define JSON_BIG_ENDIAN 1
#  endif
#endif
#ifndef JSON_BIG_ENDIAN
#  define JSON_LITTLE_ENDIAN 1
#endif

/* ============================================================================
 * §2  PORTABLE TYPE SYSTEM
 * ============================================================================ */

#ifndef JSON_NO_STDLIB
#  include <stdint.h>
#  include <stddef.h>
#  include <stdbool.h>
#  include <string.h>
#  include <math.h>
#  include <float.h>
#  include <limits.h>
#else
/* Minimal type definitions for fully freestanding environments */
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef signed char        int8_t;
typedef signed short       int16_t;
typedef signed int         int32_t;
typedef signed long long   int64_t;
typedef unsigned long      size_t;
typedef int                ptrdiff_t;
typedef int                bool;
#  define true  1
#  define false 0
#  define NULL  ((void*)0)
#endif

/* Compile-time type size checks */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(uint8_t)  == 1, "uint8_t must be 1 byte");
_Static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");
_Static_assert(sizeof(uint64_t) == 8, "uint64_t must be 8 bytes");
_Static_assert(sizeof(int64_t)  == 8, "int64_t must be 8 bytes");
#endif

/* ============================================================================
 * §3  COMPILER HINTS & PORTABILITY MACROS
 * ============================================================================ */

#if defined(JSON_CC_GCC) || defined(JSON_CC_CLANG)
#  define JSON_INLINE      __attribute__((always_inline)) static inline
#  define JSON_NOINLINE    __attribute__((noinline))
#  define JSON_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define JSON_UNLIKELY(x) __builtin_expect(!!(x), 0)
#  define JSON_RESTRICT    __restrict__
#  define JSON_PURE        __attribute__((pure))
#  define JSON_NORETURN    __attribute__((noreturn))
#elif defined(JSON_CC_MSVC)
#  define JSON_INLINE      __forceinline static
#  define JSON_NOINLINE    __declspec(noinline)
#  define JSON_LIKELY(x)   (x)
#  define JSON_UNLIKELY(x) (x)
#  define JSON_RESTRICT    __restrict
#  define JSON_PURE
#  define JSON_NORETURN    __declspec(noreturn)
#else
#  define JSON_INLINE      static inline
#  define JSON_NOINLINE
#  define JSON_LIKELY(x)   (x)
#  define JSON_UNLIKELY(x) (x)
#  define JSON_RESTRICT
#  define JSON_PURE
#  define JSON_NORETURN
#endif

/* ============================================================================
 * §4  PAL OVERRIDABLE PRIMITIVES
 * ============================================================================ */

#ifndef JSON_MEMCPY
#  define JSON_MEMCPY  memcpy
#endif
#ifndef JSON_MEMSET
#  define JSON_MEMSET  memset
#endif
#ifndef JSON_MEMCMP
#  define JSON_MEMCMP  memcmp
#endif
#ifndef JSON_STRLEN
#  define JSON_STRLEN  strlen
#endif
#ifndef JSON_STRTOD
#  define JSON_STRTOD  strtod
#endif
#ifndef JSON_STRTOLL
#  define JSON_STRTOLL strtoll
#endif

#ifndef JSON_ASSERT
#  ifdef NDEBUG
#    define JSON_ASSERT(expr) ((void)(expr))
#  else
#    include <assert.h>
#    define JSON_ASSERT(expr) assert(expr)
#  endif
#endif

/* ============================================================================
 * §5  CONFIGURATION DEFAULTS
 * ============================================================================ */

#ifndef JSON_MAX_DEPTH
#  define JSON_MAX_DEPTH        64U
#endif
#ifndef JSON_MAX_STRING_LEN
#  define JSON_MAX_STRING_LEN   (1024U * 1024U)
#endif
#ifndef JSON_MAX_NODES
#  define JSON_MAX_NODES        (1024U * 1024U)
#endif
#ifndef JSON_INTROSORT_THRESH
#  define JSON_INTROSORT_THRESH 16U
#endif
#ifndef JSON_ARENA_ALIGN
#  define JSON_ARENA_ALIGN      8U
#endif
#ifndef JSON_ARENA_MIN_BLOCK
#  define JSON_ARENA_MIN_BLOCK  (4U * 1024U)
#endif
#ifndef JSON_FAST_FLOAT
#  define JSON_FAST_FLOAT        1
#endif
#ifndef JSON_MAX_ARRAY_LEN
#  define JSON_MAX_ARRAY_LEN    (1024U * 1024U)  /**< Max items per array/object   */
#endif

/* ============================================================================
 * §6  ERROR CODES
 * ============================================================================ */

typedef enum {
    JSON_OK                  =  0,  /**< Success                              */
    JSON_ERR_NULL_PARAM      = -1,  /**< NULL pointer passed to API           */
    JSON_ERR_OOM             = -2,  /**< Out of arena memory                  */
    JSON_ERR_INVALID_JSON    = -3,  /**< Malformed JSON syntax                */
    JSON_ERR_UNEXPECTED_EOF  = -4,  /**< Input ended unexpectedly             */
    JSON_ERR_DEPTH_EXCEEDED  = -5,  /**< Nesting deeper than JSON_MAX_DEPTH   */
    JSON_ERR_INVALID_STRING  = -6,  /**< Bad escape sequence or encoding      */
    JSON_ERR_INVALID_NUMBER  = -7,  /**< Malformed number literal             */
    JSON_ERR_INVALID_UTF8    = -8,  /**< Invalid UTF-8 sequence               */
    JSON_ERR_OVERFLOW        = -9,  /**< Arithmetic or buffer overflow        */
    JSON_ERR_NOT_FOUND       = -10, /**< Key or index not found               */
    JSON_ERR_TYPE_MISMATCH   = -11, /**< Wrong type for requested operation   */
    JSON_ERR_BUFFER_TOO_SMALL= -12, /**< Output buffer too small              */
    JSON_ERR_NODE_LIMIT      = -13  /**< Exceeded JSON_MAX_NODES              */
} JsonError;

/* ============================================================================
 * §7  VALUE TYPES & STRUCTURES
 * ============================================================================ */

typedef enum {
    JSON_NULL    = 0,
    JSON_BOOL    = 1,
    JSON_INTEGER = 2,  /**< Stored as int64_t — exact, no rounding         */
    JSON_FLOAT   = 3,  /**< Stored as double  — NaN/Inf never produced     */
    JSON_STRING  = 4,  /**< UTF-8, NOT NUL-terminated; use .len            */
    JSON_ARRAY   = 5,
    JSON_OBJECT  = 6
} JsonType;

typedef struct JsonValue JsonValue;

typedef struct {
    const char* data;  /**< Points into arena; NOT NUL-terminated          */
    uint32_t    len;
    uint32_t    hash;  /**< FNV-1a for fast key lookup                     */
} JsonStr;

typedef struct {
    JsonValue** items;
    uint32_t    len;
    uint32_t    cap;
} JsonArr;

typedef struct {
    JsonStr    key;
    JsonValue* val;
} JsonPair;

typedef struct {
    JsonPair*  pairs;       /**< Insertion-order pairs                     */
    uint32_t*  sorted_idx;  /**< Indices sorted by key (built on demand)   */
    uint32_t   len;
    uint32_t   cap;
    bool       is_sorted;
} JsonObj;

struct JsonValue {
    JsonType type;
    union {
        bool     b;     /* JSON_BOOL    */
        int64_t  i;     /* JSON_INTEGER */
        double   f;     /* JSON_FLOAT   */
        JsonStr  s;     /* JSON_STRING  */
        JsonArr  a;     /* JSON_ARRAY   */
        JsonObj  o;     /* JSON_OBJECT  */
    } v;
};

/* ============================================================================
 * §8  ARENA ALLOCATOR
 * ============================================================================ */

/**
 * @brief Custom allocator hooks. All fields optional (NULL → use libc).
 * @note  realloc receives old_size to support arena-style backing stores.
 */
typedef struct {
    void* (*alloc)  (void* ctx, size_t size);
    void  (*free)   (void* ctx, void* ptr);
    void* (*realloc)(void* ctx, void* ptr, size_t old_size, size_t new_size);
    void* ctx;
} JsonAllocator;

typedef struct JsonArenaBlock JsonArenaBlock;
struct JsonArenaBlock {
    JsonArenaBlock* next;
    size_t          cap;
    size_t          used;
    /* data[] follows in memory */
};

typedef struct {
    JsonArenaBlock* current;
    JsonArenaBlock* first;
    size_t          block_size;    /**< Default block allocation size        */
    size_t          total_bytes;   /**< Cumulative bytes allocated           */
    uint32_t        node_count;    /**< JsonValue nodes allocated (limit check) */
    JsonAllocator   backing;
} JsonArena;

/* ============================================================================
 * §9  SERIALIZER OPTIONS
 * ============================================================================ */

typedef struct {
    bool     pretty;        /**< Enable indented, multi-line output         */
    uint32_t indent;        /**< Spaces per level (default: 2)              */
    bool     sort_keys;     /**< Alphabetic key ordering in output          */
    bool     ascii_only;    /**< Escape all non-ASCII as \uXXXX            */
    bool     trailing_nl;   /**< Append '\n' at end                        */
} JsonWriteOpts;

/* ============================================================================
 * §10  PUBLIC API DECLARATIONS
 * ============================================================================ */

/* --- Arena --- */

/**
 * @brief  Create arena. Pass NULL allocator to use libc malloc/free/realloc.
 * @param  alloc      Backing allocator (NULL = libc). Copied by value.
 * @param  block_size Initial block size in bytes (0 = default 64 KiB).
 * @return New arena, or NULL on allocation failure.
 * @note   Thread-safety: NOT thread-safe.
 */
JsonArena* json_arena_create(const JsonAllocator* alloc, size_t block_size);

/**
 * @brief  Destroy arena and free all backing memory.
 * @note   All JsonValue* pointers obtained from this arena become invalid.
 */
void json_arena_destroy(JsonArena* arena);

/**
 * @brief  Reset arena: keeps backing blocks, resets all usage to zero.
 *         Faster than destroy+create for repeated parses.
 */
void json_arena_reset(JsonArena* arena);

/**
 * @brief  Low-level aligned allocation from arena.
 * @return Pointer to zeroed memory, or NULL on OOM.
 * @note   Alignment: JSON_ARENA_ALIGN bytes.
 */
void* json_arena_alloc(JsonArena* arena, size_t size);

/* --- Parsing --- */

/**
 * @brief  Parse JSON from buffer. Result lives in arena.
 * @param  arena    Destination arena (must not be NULL).
 * @param  src      Input buffer (need not be NUL-terminated).
 * @param  len      Length of src in bytes.
 * @param  err_out  If non-NULL, receives error code on failure.
 * @return Root JsonValue*, or NULL on error.
 *
 * @pre    arena != NULL
 * @pre    src != NULL || len == 0
 * @post   On success, returned pointer is valid until arena_destroy/reset.
 *
 * @note   WCET depends on input size and JSON_MAX_DEPTH.
 *         Depth-limited to JSON_MAX_DEPTH to prevent stack exhaustion.
 */
JsonValue* json_parse(JsonArena* arena, const char* src, size_t len,
                      JsonError* err_out);

/**
 * @brief  Convenience wrapper for NUL-terminated strings.
 */
JsonValue* json_parse_cstr(JsonArena* arena, const char* src, JsonError* err_out);

/* --- Type predicates --- */
JSON_INLINE bool json_is_null   (const JsonValue* v) { return v && v->type == JSON_NULL;    }
JSON_INLINE bool json_is_bool   (const JsonValue* v) { return v && v->type == JSON_BOOL;    }
JSON_INLINE bool json_is_integer(const JsonValue* v) { return v && v->type == JSON_INTEGER; }
JSON_INLINE bool json_is_float  (const JsonValue* v) { return v && v->type == JSON_FLOAT;   }
JSON_INLINE bool json_is_number (const JsonValue* v) { return v && (v->type == JSON_INTEGER || v->type == JSON_FLOAT); }
JSON_INLINE bool json_is_string (const JsonValue* v) { return v && v->type == JSON_STRING;  }
JSON_INLINE bool json_is_array  (const JsonValue* v) { return v && v->type == JSON_ARRAY;   }
JSON_INLINE bool json_is_object (const JsonValue* v) { return v && v->type == JSON_OBJECT;  }

/* --- Type-safe accessors --- */
JsonError json_get_bool   (const JsonValue* v, bool*        out);
JsonError json_get_int    (const JsonValue* v, int64_t*     out);
JsonError json_get_float  (const JsonValue* v, double*      out);
JsonError json_get_number (const JsonValue* v, double*      out); /**< Accepts int OR float */
JsonError json_get_string (const JsonValue* v, const char** out, uint32_t* len_out);
JsonError json_get_arr_len(const JsonValue* v, uint32_t*    out);
JsonError json_get_obj_len(const JsonValue* v, uint32_t*    out);

/** @brief Get array item by index. O(1). */
JsonError json_arr_get(const JsonValue* v, uint32_t idx, JsonValue** out);

/** @brief Get object value by key (NUL-terminated). O(log n) after sort. */
JsonError json_obj_get(const JsonValue* v, const char* key, JsonValue** out);

/** @brief Get object value by key+length. O(log n) after sort. */
JsonError json_obj_get_n(const JsonValue* v, const char* key, size_t klen,
                         JsonValue** out);

/**
 * @brief  Iterate object pairs in insertion order.
 * @param  idx     Pair index [0, len).
 * @param  key_out If non-NULL, receives key pointer (NOT NUL-terminated).
 * @param  klen    If non-NULL, receives key length.
 * @param  val_out If non-NULL, receives value pointer.
 */
JsonError json_obj_iter(const JsonValue* v, uint32_t idx,
                        const char** key_out, uint32_t* klen,
                        JsonValue** val_out);

/* --- Path query --- */

/**
 * @brief  Query value by path string.
 *
 * Syntax:
 *   .key       → object key lookup (dot notation)
 *   ["key"]    → object key lookup (bracket notation, allows spaces/specials)
 *   [N]        → array index (N is non-negative integer)
 *
 * Example paths:
 *   "users[0].name"
 *   ".config[\"host\"]"
 *   "[2][1]"
 *
 * @param  root     Starting node (may be any type; mismatch → NULL).
 * @param  path     Path string (NUL-terminated).
 * @param  err_out  Optional error output.
 * @return Matching JsonValue*, or NULL on failure.
 */
JsonValue* json_path(const JsonValue* root, const char* path, JsonError* err_out);

/* --- Serialization --- */

/**
 * @brief  Serialize JSON value to caller-provided buffer.
 * @param  buf       Output buffer.
 * @param  buf_size  Buffer capacity in bytes.
 * @param  written   If non-NULL, receives bytes written (excl. NUL).
 * @param  opts      Write options (NULL = compact defaults).
 * @return JSON_OK, JSON_ERR_NULL_PARAM, or JSON_ERR_BUFFER_TOO_SMALL.
 *
 * @pre    v != NULL, buf != NULL, buf_size >= 1
 * @post   On JSON_OK, buf is NUL-terminated.
 */
JsonError json_write(const JsonValue* v, char* buf, size_t buf_size,
                     size_t* written, const JsonWriteOpts* opts);

/**
 * @brief  Serialize to arena-allocated NUL-terminated string.
 * @param  out      Receives pointer to NUL-terminated string.
 * @param  len_out  If non-NULL, receives string length.
 */
JsonError json_write_arena(const JsonValue* v, JsonArena* arena,
                           char** out, size_t* len_out,
                           const JsonWriteOpts* opts);

/* --- Value construction --- */
JsonValue* json_make_null   (JsonArena* arena);
JsonValue* json_make_bool   (JsonArena* arena, bool val);
JsonValue* json_make_int    (JsonArena* arena, int64_t val);
JsonValue* json_make_float  (JsonArena* arena, double val);
JsonValue* json_make_string (JsonArena* arena, const char* s, uint32_t len);
JsonValue* json_make_stringz(JsonArena* arena, const char* s);
JsonValue* json_make_array  (JsonArena* arena);
JsonValue* json_make_object (JsonArena* arena);

JsonError  json_arr_push(JsonValue* arr, JsonArena* arena, JsonValue* item);
JsonError  json_obj_set (JsonValue* obj, JsonArena* arena,
                         const char* key, uint32_t klen, JsonValue* val);
JsonError  json_obj_setz(JsonValue* obj, JsonArena* arena,
                         const char* key, JsonValue* val);
JsonError  json_obj_finalize(JsonArena* arena, JsonValue* obj);

/* --- Utilities --- */
const char* json_error_str(JsonError err);
uint32_t    json_fnv1a(const char* data, size_t len);

/* Compute output size without writing (pass NULL buf, 0 size, non-NULL written) */
JsonError   json_measure(const JsonValue* v, size_t* size_out,
                         const JsonWriteOpts* opts);

/* Deep equality comparison */
bool        json_equal(const JsonValue* a, const JsonValue* b);

/* Clone value into another arena */
JsonValue*  json_clone(JsonArena* dst, const JsonValue* src);


/* ============================================================================
 * §11  IMPLEMENTATION
 * ============================================================================ */

#ifdef JSON_IMPLEMENTATION

#ifndef JSON_NO_STDLIB
#  include <stdlib.h>   /* malloc, free, realloc */
#  include <stdio.h>    /* snprintf              */
#endif

/* ── §11.1  Default libc allocator ─────────────────────────────────────── */

static void* json__libc_alloc(void* ctx, size_t sz)
{
    (void)ctx;
    return malloc(sz);
}
static void json__libc_free(void* ctx, void* p)
{
    (void)ctx;
    free(p);
}
static void* json__libc_realloc(void* ctx, void* p, size_t old_sz, size_t new_sz)
{
    (void)ctx; (void)old_sz;
    return realloc(p, new_sz);
}

static const JsonAllocator k_libc_alloc = {
    json__libc_alloc,
    json__libc_free,
    json__libc_realloc,
    NULL
};

/* ── §11.2  Arena implementation ────────────────────────────────────────── */

/**
 * @brief  Align sz up to JSON_ARENA_ALIGN boundary.
 * @note   JSON_ARENA_ALIGN MUST be a power of two.
 */
JSON_INLINE size_t json__align_up(size_t sz)
{
    /* DESIGN: Power-of-2 alignment allows bitwise AND instead of modulo.
     *         WCET: O(1), 2 instructions on ARM Cortex-M. */
    return (sz + (JSON_ARENA_ALIGN - 1U)) & ~(JSON_ARENA_ALIGN - 1U);
}

static JsonArenaBlock* json__block_new(JsonArena* arena, size_t min_size)
{
    size_t block_sz;
    JsonArenaBlock* blk;
    size_t header_sz;

    JSON_ASSERT(arena != NULL);

    header_sz = json__align_up(sizeof(JsonArenaBlock));

    /* Ensure block fits header + requested data */
    block_sz = (min_size + header_sz > arena->block_size)
               ? json__align_up(min_size + header_sz)
               : arena->block_size;

    blk = (JsonArenaBlock*)arena->backing.alloc(arena->backing.ctx, block_sz);
    if (JSON_UNLIKELY(blk == NULL)) { return NULL; }

    JSON_MEMSET(blk, 0, sizeof(JsonArenaBlock));
    blk->cap  = block_sz - header_sz;
    blk->used = 0U;
    blk->next = NULL;
    return blk;
}

JSON_INLINE uint8_t* json__block_data(JsonArenaBlock* blk)
{
    /* Data starts immediately after the (aligned) block header */
    return (uint8_t*)blk + json__align_up(sizeof(JsonArenaBlock));
}

JsonArena* json_arena_create(const JsonAllocator* alloc, size_t block_size)
{
    JsonArena* arena;
    JsonAllocator eff_alloc;
    JsonArenaBlock* first;

    eff_alloc = (alloc != NULL) ? *alloc : k_libc_alloc;

    /* Validate allocator */
    if (eff_alloc.alloc == NULL || eff_alloc.free == NULL) { return NULL; }

    if (block_size == 0U) {
        block_size = 64U * 1024U;
    }
    if (block_size < JSON_ARENA_MIN_BLOCK) {
        block_size = JSON_ARENA_MIN_BLOCK;
    }

    arena = (JsonArena*)eff_alloc.alloc(eff_alloc.ctx, sizeof(JsonArena));
    if (JSON_UNLIKELY(arena == NULL)) { return NULL; }
    JSON_MEMSET(arena, 0, sizeof(JsonArena));

    arena->backing    = eff_alloc;
    arena->block_size = block_size;

    first = json__block_new(arena, 0U);
    if (JSON_UNLIKELY(first == NULL)) {
        eff_alloc.free(eff_alloc.ctx, arena);
        return NULL;
    }

    arena->first   = first;
    arena->current = first;
    return arena;
}

void json_arena_destroy(JsonArena* arena)
{
    JsonArenaBlock* blk;
    JsonArenaBlock* next;

    if (arena == NULL) { return; }

    blk = arena->first;
    while (blk != NULL) {
        next = blk->next;
        arena->backing.free(arena->backing.ctx, blk);
        blk = next;
    }
    arena->backing.free(arena->backing.ctx, arena);
}

void json_arena_reset(JsonArena* arena)
{
    JsonArenaBlock* blk;

    if (arena == NULL) { return; }

    for (blk = arena->first; blk != NULL; blk = blk->next) {
        blk->used = 0U;
    }
    arena->current     = arena->first;
    arena->total_bytes = 0U;
    arena->node_count  = 0U;
}

static void* json__arena_alloc_raw(JsonArena* arena, size_t size, bool zero_fill)
{
    size_t aligned_size;
    uint8_t* ptr;
    JsonArenaBlock* new_blk;

    if (JSON_UNLIKELY(arena == NULL || size == 0U)) { return NULL; }

    aligned_size = json__align_up(size);
    if (JSON_UNLIKELY(aligned_size < size)) { return NULL; }

    if (JSON_LIKELY(arena->current->used + aligned_size <= arena->current->cap)) {
        ptr = json__block_data(arena->current) + arena->current->used;
        arena->current->used += aligned_size;
        arena->total_bytes   += aligned_size;
        if (zero_fill) { JSON_MEMSET(ptr, 0, aligned_size); }
        return ptr;
    }

    new_blk = json__block_new(arena, aligned_size);
    if (JSON_UNLIKELY(new_blk == NULL)) { return NULL; }

    arena->current->next = new_blk;
    arena->current = new_blk;

    ptr = json__block_data(new_blk);
    new_blk->used       = aligned_size;
    arena->total_bytes += aligned_size;
    if (zero_fill) { JSON_MEMSET(ptr, 0, aligned_size); }
    return ptr;
}

JSON_INLINE void* json__arena_alloc_uninit(JsonArena* arena, size_t size)
{
    return json__arena_alloc_raw(arena, size, false);
}

void* json_arena_alloc(JsonArena* arena, size_t size)
{
    return json__arena_alloc_raw(arena, size, true);
}

/* ── §11.3  FNV-1a Hash ─────────────────────────────────────────────────── */

/**
 * @brief  FNV-1a 32-bit hash for object key lookup.
 *         Non-cryptographic. Fast. Good distribution for short strings.
 *
 * @note   WCET: O(len). No branches inside loop.
 */
uint32_t json_fnv1a(const char* data, size_t len)
{
    static const uint32_t FNV_PRIME  = 0x01000193UL;
    static const uint32_t FNV_OFFSET = 0x811C9DC5UL;
    uint32_t hash = FNV_OFFSET;
    size_t   i;

    if (data == NULL) { return 0U; }

    for (i = 0U; i < len; i++) {
        hash ^= (uint32_t)(uint8_t)data[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

/* ── §11.4  Introsort for object key indices ────────────────────────────── */

/*
 * DESIGN: Introsort combines:
 *   - Quicksort   (median-of-3 pivot, O(n log n) average)
 *   - Heapsort    (fallback when recursion depth > 2*log2(n), O(n log n) worst)
 *   - Insertion sort (n < JSON_INTROSORT_THRESH, O(n^2) but fast for tiny n)
 *
 * This guarantees O(n log n) worst-case with excellent cache locality.
 * Uses recursion bounded by depth_limit to prevent stack overflow.
 */

typedef struct {
    const JsonPair* pairs;  /* Read-only reference to pairs array */
    uint32_t*       idx;    /* The index array being sorted       */
} JsonSortCtx;

/**
 * @brief  Compare two key-index entries by (hash, then lexicographic).
 *         Hash comparison avoids string compare in the common (no-collision) case.
 * @return <0 if a < b, 0 if equal, >0 if a > b
 */
JSON_INLINE int json__key_cmp(const JsonSortCtx* ctx, uint32_t a, uint32_t b)
{
    const JsonStr* ka = &ctx->pairs[a].key;
    const JsonStr* kb = &ctx->pairs[b].key;
    int cmp;
    uint32_t min_len;

    JSON_ASSERT(ctx != NULL);

    /* Fast path: hash mismatch */
    if (ka->hash != kb->hash) {
        return (ka->hash < kb->hash) ? -1 : 1;
    }

    /* Slow path: lexicographic comparison (hash collision) */
    min_len = (ka->len < kb->len) ? ka->len : kb->len;
    cmp = JSON_MEMCMP(ka->data, kb->data, (size_t)min_len);
    if (cmp != 0) { return cmp; }
    if (ka->len < kb->len) { return -1; }
    if (ka->len > kb->len) { return  1; }
    return 0;
}

static void json__isort(const JsonSortCtx* ctx, uint32_t* arr,
                        uint32_t lo, uint32_t hi)
{
    uint32_t i, j, key;

    JSON_ASSERT(ctx != NULL && arr != NULL);

    for (i = lo + 1U; i <= hi; i++) {
        key = arr[i];
        j = i;
        while (j > lo && json__key_cmp(ctx, arr[j - 1U], key) > 0) {
            arr[j] = arr[j - 1U];
            j--;
        }
        arr[j] = key;
    }
}

/* Heapsort helpers */
static void json__sift_down(const JsonSortCtx* ctx, uint32_t* arr,
                            uint32_t root, uint32_t end)
{
    uint32_t parent, child, tmp;

    JSON_ASSERT(ctx != NULL && arr != NULL);

    parent = root;
    for (;;) {
        child = 2U * parent + 1U;
        if (child > end) { break; }

        if (child + 1U <= end &&
            json__key_cmp(ctx, arr[child], arr[child + 1U]) < 0) {
            child++;
        }
        if (json__key_cmp(ctx, arr[parent], arr[child]) >= 0) { break; }

        tmp = arr[parent]; arr[parent] = arr[child]; arr[child] = tmp;
        parent = child;
    }
}

static void json__heapsort(const JsonSortCtx* ctx, uint32_t* arr,
                           uint32_t lo, uint32_t hi)
{
    uint32_t n, i, tmp;

    JSON_ASSERT(ctx != NULL && arr != NULL && hi >= lo);

    n = hi - lo + 1U;

    /* Build max-heap */
    if (n < 2U) { return; }
    i = lo + n / 2U;
    while (i-- > lo) {
        json__sift_down(ctx, arr + lo, i - lo, n - 1U);
    }

    /* Extract */
    for (i = n - 1U; i > 0U; i--) {
        tmp = arr[lo]; arr[lo] = arr[lo + i]; arr[lo + i] = tmp;
        json__sift_down(ctx, arr + lo, 0U, i - 1U);
    }
}

/* Compute floor(log2(n)) safely */
JSON_INLINE uint32_t json__ilog2(uint32_t n)
{
    uint32_t r = 0U;
    while (n > 1U) { n >>= 1U; r++; }
    return r;
}

static void json__introsort(const JsonSortCtx* ctx, uint32_t* arr,
                            uint32_t lo, uint32_t hi, uint32_t depth)
{
    uint32_t pivot, mid, tmp, i, j;

    JSON_ASSERT(ctx != NULL && arr != NULL);

    while (lo < hi) {
        uint32_t span = hi - lo + 1U;

        /* Leaf: insertion sort */
        if (span <= JSON_INTROSORT_THRESH) {
            json__isort(ctx, arr, lo, hi);
            return;
        }

        /* Depth exceeded: heapsort to guarantee O(n log n) */
        if (depth == 0U) {
            json__heapsort(ctx, arr, lo, hi);
            return;
        }

        /* Median-of-three pivot selection */
        mid = lo + span / 2U;

        /* Sort lo, mid, hi — bring median to mid */
        if (json__key_cmp(ctx, arr[lo], arr[mid]) > 0) {
            tmp = arr[lo]; arr[lo] = arr[mid]; arr[mid] = tmp;
        }
        if (json__key_cmp(ctx, arr[lo], arr[hi]) > 0) {
            tmp = arr[lo]; arr[lo] = arr[hi]; arr[hi] = tmp;
        }
        if (json__key_cmp(ctx, arr[mid], arr[hi]) > 0) {
            tmp = arr[mid]; arr[mid] = arr[hi]; arr[hi] = tmp;
        }

        /* Place pivot at hi-1 */
        pivot = arr[mid];
        tmp = arr[mid]; arr[mid] = arr[hi - 1U]; arr[hi - 1U] = tmp;

        /* Partition */
        i = lo;
        j = hi - 1U;
        for (;;) {
            while (json__key_cmp(ctx, arr[++i], pivot) < 0 && i < hi) { }
            while (json__key_cmp(ctx, arr[--j], pivot) > 0 && j > lo) { }
            if (i >= j) { break; }
            tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
        }

        /* Restore pivot */
        tmp = arr[i]; arr[i] = arr[hi - 1U]; arr[hi - 1U] = tmp;

        /* Recurse smaller half; iterate larger (tail-call optimisation) */
        if (i - lo < hi - i) {
            json__introsort(ctx, arr, lo, i - 1U, depth - 1U);
            lo = i + 1U;
        } else {
            json__introsort(ctx, arr, i + 1U, hi, depth - 1U);
            hi = (i > 0U) ? (i - 1U) : 0U;
            if (i == 0U) { break; }
        }
        depth--;
    }
}

/**
 * @brief  Sort object's sorted_idx array and mark object as sorted.
 * @note   Idempotent: no-op if already sorted.
 * @note   WCET: O(n log n) — introsort guarantees this.
 */
static JsonError json__obj_sort(JsonValue* obj, JsonArena* arena)
{
    JsonObj*    o;
    uint32_t    i;
    JsonSortCtx ctx;

    JSON_ASSERT(obj != NULL && obj->type == JSON_OBJECT);
    JSON_ASSERT(arena != NULL);

    o = &obj->v.o;
    if (o->is_sorted || o->len == 0U) { return JSON_OK; }

    /* Allocate sorted_idx if not already present */
    if (o->sorted_idx == NULL) {
        o->sorted_idx = (uint32_t*)json__arena_alloc_uninit(
            arena, (size_t)o->cap * sizeof(uint32_t));
        if (JSON_UNLIKELY(o->sorted_idx == NULL)) { return JSON_ERR_OOM; }
    }

    for (i = 0U; i < o->len; i++) {
        o->sorted_idx[i] = i;
    }

    ctx.pairs = o->pairs;
    ctx.idx   = o->sorted_idx;

    if (o->len > 1U) {
        json__introsort(&ctx, o->sorted_idx, 0U, o->len - 1U,
                        2U * json__ilog2(o->len));
    }

    o->is_sorted = true;
    return JSON_OK;
}

/* ── §11.5  Lexer ───────────────────────────────────────────────────────── */

typedef enum {
    TOK_LBRACE  = '{',
    TOK_RBRACE  = '}',
    TOK_LBRACKET= '[',
    TOK_RBRACKET= ']',
    TOK_COLON   = ':',
    TOK_COMMA   = ',',
    TOK_TRUE    = 't',
    TOK_FALSE   = 'f',
    TOK_NULL_T  = 'n',
    TOK_STRING  = '"',
    TOK_NUMBER  = '0',
    TOK_EOF     = 0,
    TOK_ERROR   = -1
} JsonTok;

typedef struct {
    const char* src;
    size_t      len;
    size_t      pos;
    uint32_t    line;
    uint32_t    col;
    /* Last parsed token data */
    size_t      tok_start; /* Position in src                   */
    size_t      tok_len;   /* Length in src (raw, incl. quotes) */
    JsonError   err;
} JsonLex;

static void json__lex_skip_ws(JsonLex* l)
{
    const char* s;
    size_t p;
    size_t n;

    JSON_ASSERT(l != NULL);

    s = l->src;
    p = l->pos;
    n = l->len;
    while (p < n) {
        char c = s[p];
        if (c != ' ' && c != '\n' && c != '\r' && c != '\t') { break; }
        p++;
    }
    l->pos = p;
}

/** @brief Validate UTF-8 continuation byte. */
JSON_INLINE bool json__is_cont(uint8_t b) { return (b & 0xC0U) == 0x80U; }

/* ── §11.6  String parsing (with \uXXXX decoding) ──────────────────────── */

/** @brief Hex digit to value. Returns 0xFF on invalid input. */
JSON_INLINE uint8_t json__hex_val(char c)
{
    if (c >= '0' && c <= '9') { return (uint8_t)(c - '0'); }
    if (c >= 'a' && c <= 'f') { return (uint8_t)(c - 'a' + 10); }
    if (c >= 'A' && c <= 'F') { return (uint8_t)(c - 'A' + 10); }
    return 0xFFU;
}

/**
 * @brief  Parse 4 hex digits into uint16_t.
 * @return true on success, false on non-hex character.
 */
static bool json__parse_hex4(const char* s, size_t max, uint16_t* out)
{
    uint8_t h0, h1, h2, h3;

    JSON_ASSERT(s != NULL && out != NULL);

    if (max < 4U) { return false; }
    h0 = json__hex_val(s[0]);
    h1 = json__hex_val(s[1]);
    h2 = json__hex_val(s[2]);
    h3 = json__hex_val(s[3]);

    if ((h0 | h1 | h2 | h3) == 0xFFU) { return false; }
    *out = (uint16_t)(((uint16_t)h0 << 12U) |
                      ((uint16_t)h1 <<  8U) |
                      ((uint16_t)h2 <<  4U) |
                       (uint16_t)h3);
    return true;
}

/** @brief Encode Unicode code point (U+0000..U+10FFFF) as UTF-8.
 *         Writes to buf (needs at least 4 bytes). Returns bytes written. */
static uint32_t json__encode_utf8(uint32_t cp, uint8_t* buf)
{
    JSON_ASSERT(buf != NULL);

    if (cp < 0x80U) {
        buf[0] = (uint8_t)cp;
        return 1U;
    } else if (cp < 0x800U) {
        buf[0] = (uint8_t)(0xC0U | (cp >> 6U));
        buf[1] = (uint8_t)(0x80U | (cp & 0x3FU));
        return 2U;
    } else if (cp < 0x10000U) {
        buf[0] = (uint8_t)(0xE0U | (cp >> 12U));
        buf[1] = (uint8_t)(0x80U | ((cp >> 6U) & 0x3FU));
        buf[2] = (uint8_t)(0x80U | (cp & 0x3FU));
        return 3U;
    } else if (cp <= 0x10FFFFU) {
        buf[0] = (uint8_t)(0xF0U | (cp >> 18U));
        buf[1] = (uint8_t)(0x80U | ((cp >> 12U) & 0x3FU));
        buf[2] = (uint8_t)(0x80U | ((cp >>  6U) & 0x3FU));
        buf[3] = (uint8_t)(0x80U | (cp & 0x3FU));
        return 4U;
    }
    return 0U; /* Invalid code point */
}

/**
 * @brief  Parse a JSON string (cursor past opening '"'). Decode all escapes.
 *         Result is stored as arena-allocated UTF-8. NOT NUL-terminated.
 *
 * @param[out] str  Populated with pointer+length+hash on success.
 * @return JSON_OK or error code.
 */
static JsonError json__parse_string(JsonLex* l, JsonArena* arena, JsonStr* str)
{
    /* Two-pass: first measure, then allocate+copy.
     * This avoids reallocations and is cache-friendly. */
    size_t start_pos = l->pos; /* After opening quote */
    size_t out_len   = 0U;
    bool   has_escape= false;
    uint32_t raw_hash = 0x811C9DC5UL;
    size_t scan_pos;
    char*  out_buf;
    size_t write_pos;

    JSON_ASSERT(l != NULL && arena != NULL && str != NULL);

    /* ── Pass 1: Measure output length ─── */
    scan_pos = l->pos;
    while (scan_pos < l->len) {
        uint8_t c = (uint8_t)l->src[scan_pos];

        if (c == '"') { break; }

        if (c == '\\') {
            has_escape = true;
            scan_pos++;
            if (scan_pos >= l->len) {
                l->err = JSON_ERR_UNEXPECTED_EOF;
                return JSON_ERR_UNEXPECTED_EOF;
            }
            switch (l->src[scan_pos]) {
                case '"': case '\\': case '/':
                case 'b': case 'f': case 'n': case 'r': case 't':
                    out_len++;
                    scan_pos++;
                    break;
                case 'u': {
                    /* \uXXXX or \uXXXX\uXXXX (surrogate pair) */
                    uint16_t hi_cp;
                    scan_pos++;
                    if (!json__parse_hex4(l->src + scan_pos,
                                          l->len - scan_pos, &hi_cp)) {
                        l->err = JSON_ERR_INVALID_STRING;
                        return JSON_ERR_INVALID_STRING;
                    }
                    scan_pos += 4U;
                    if (hi_cp >= 0xD800U && hi_cp <= 0xDBFFU) {
                        /* High surrogate — expect low surrogate */
                        uint16_t lo_cp;
                        if (scan_pos + 1U >= l->len ||
                            l->src[scan_pos] != '\\' ||
                            l->src[scan_pos + 1U] != 'u') {
                            l->err = JSON_ERR_INVALID_STRING;
                            return JSON_ERR_INVALID_STRING;
                        }
                        scan_pos += 2U;
                        if (!json__parse_hex4(l->src + scan_pos,
                                              l->len - scan_pos, &lo_cp)) {
                            l->err = JSON_ERR_INVALID_STRING;
                            return JSON_ERR_INVALID_STRING;
                        }
                        scan_pos += 4U;
                        if (lo_cp < 0xDC00U || lo_cp > 0xDFFFU) {
                            l->err = JSON_ERR_INVALID_STRING;
                            return JSON_ERR_INVALID_STRING;
                        }
                        out_len += 4U; /* UTF-8 for supplementary plane */
                    } else if (hi_cp >= 0xDC00U && hi_cp <= 0xDFFFU) {
                        /* Lone low surrogate — invalid */
                        l->err = JSON_ERR_INVALID_STRING;
                        return JSON_ERR_INVALID_STRING;
                    } else {
                        /* DESIGN: exact byte count, not a constant 3.
                         *   U+0000–U+007F  → 1 byte
                         *   U+0080–U+07FF  → 2 bytes
                         *   U+0800–U+FFFF  → 3 bytes
                         * Using the maximum (3) over-allocates and corrupts
                         * str->len, breaking key lookup and equality. */
                        out_len += (hi_cp < 0x80U) ? 1U
                                 : (hi_cp < 0x800U) ? 2U : 3U;
                    }
                    break;
                }
                default:
                    l->err = JSON_ERR_INVALID_STRING;
                    return JSON_ERR_INVALID_STRING;
            }
        } else if (c < 0x20U) {
            /* Control chars must be escaped */
            l->err = JSON_ERR_INVALID_STRING;
            return JSON_ERR_INVALID_STRING;
        } else {
            raw_hash ^= (uint32_t)c;
            raw_hash *= 0x01000193UL;
            out_len++;
            scan_pos++;
        }
    }

    if (scan_pos >= l->len) {
        l->err = JSON_ERR_UNEXPECTED_EOF;
        return JSON_ERR_UNEXPECTED_EOF;
    }

    if (out_len > JSON_MAX_STRING_LEN) {
        l->err = JSON_ERR_OVERFLOW;
        return JSON_ERR_OVERFLOW;
    }

    /* ── Pass 2: Allocate and decode ─── */
    out_buf = (out_len > 0U)
              ? (char*)json__arena_alloc_uninit(arena, out_len)
              : NULL;

    if (out_len > 0U && JSON_UNLIKELY(out_buf == NULL)) {
        l->err = JSON_ERR_OOM;
        return JSON_ERR_OOM;
    }

    write_pos = 0U;
    l->pos    = start_pos;

    if (!has_escape) {
        /* Fast path: no escapes — memcpy and validate UTF-8 */
        if (out_len > 0U) {
            JSON_MEMCPY(out_buf, l->src + l->pos, out_len);
        }
        l->pos += out_len;
    } else {
        /* Slow path: decode escapes */
        while (l->pos < l->len && l->src[l->pos] != '"') {
            uint8_t c = (uint8_t)l->src[l->pos];
            if (c == '\\') {
                l->pos++;
                switch (l->src[l->pos]) {
                    case '"':  out_buf[write_pos++] = '"';  l->pos++; break;
                    case '\\': out_buf[write_pos++] = '\\'; l->pos++; break;
                    case '/':  out_buf[write_pos++] = '/';  l->pos++; break;
                    case 'b':  out_buf[write_pos++] = '\b'; l->pos++; break;
                    case 'f':  out_buf[write_pos++] = '\f'; l->pos++; break;
                    case 'n':  out_buf[write_pos++] = '\n'; l->pos++; break;
                    case 'r':  out_buf[write_pos++] = '\r'; l->pos++; break;
                    case 't':  out_buf[write_pos++] = '\t'; l->pos++; break;
                    case 'u': {
                        uint16_t hi_cp, lo_cp;
                        uint32_t codepoint;
                        uint32_t bytes;
                        l->pos++;
                        json__parse_hex4(l->src + l->pos,
                                         l->len - l->pos, &hi_cp);
                        l->pos += 4U;
                        if (hi_cp >= 0xD800U && hi_cp <= 0xDBFFU) {
                            l->pos += 2U; /* skip \u */
                            json__parse_hex4(l->src + l->pos,
                                             l->len - l->pos, &lo_cp);
                            l->pos += 4U;
                            codepoint = 0x10000U +
                                ((uint32_t)(hi_cp - 0xD800U) << 10U) +
                                 (uint32_t)(lo_cp - 0xDC00U);
                        } else {
                            codepoint = hi_cp;
                        }
                        bytes = json__encode_utf8(codepoint,
                                   (uint8_t*)out_buf + write_pos);
                        write_pos += bytes;
                        break;
                    }
                    default: l->pos++; break; /* unreachable after pass 1 */
                }
            } else {
                out_buf[write_pos++] = (char)c;
                l->pos++;
            }
        }
    }

    if (l->pos >= l->len) {
        l->err = JSON_ERR_UNEXPECTED_EOF;
        return JSON_ERR_UNEXPECTED_EOF;
    }
    l->pos++; /* Consume closing '"' */

    str->data = out_buf;
    str->len  = (uint32_t)out_len;
    str->hash = has_escape ? json_fnv1a(out_buf, out_len) : raw_hash;
    return JSON_OK;
}

/* ── §11.7  Number parsing ──────────────────────────────────────────────── */

static bool json__fast_float_from_parts(uint64_t mant, uint32_t sig,
                                         int32_t exp10, bool neg,
                                         double* out)
{
    static const double pow10_pos[] = {
        1.0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7,
        1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15,
        1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22
    };
    static const double pow10_neg[] = {
        1.0, 1e-1, 1e-2, 1e-3, 1e-4, 1e-5, 1e-6, 1e-7,
        1e-8, 1e-9, 1e-10, 1e-11, 1e-12, 1e-13, 1e-14, 1e-15,
        1e-16, 1e-17, 1e-18, 1e-19, 1e-20, 1e-21, 1e-22
    };
    double v;

    if (out == NULL) { return false; }
    if (sig == 0U) {
        *out = neg ? -0.0 : 0.0;
        return true;
    }
    if (exp10 < -22 || exp10 > 22) { return false; }

    v = (double)mant;
    if (exp10 < 0) { v *= pow10_neg[-exp10]; }
    else if (exp10 > 0) { v *= pow10_pos[exp10]; }
    *out = neg ? -v : v;
    return true;
}

/**
 * @brief  Parse JSON number. Detects integer vs float at parse time.
 *
 * Grammar: -? (0 | [1-9][0-9]*) (.[0-9]+)? ([eE][+-]?[0-9]+)?
 *
 * DESIGN: Parse as integer if no '.' or 'e'/'E'. Use a small fast decimal
 *         path for common floats and fall back to strtod for hard cases.
 */
static JsonError json__parse_number(JsonLex* l, JsonArena* arena,
                                    JsonValue* out)
{
    size_t start = l->pos;
    bool   negative = false;
    bool   is_float = false;
    bool   fast_ok  = true;
    uint64_t fast_mant = 0U;
    uint32_t fast_sig  = 0U;
    int32_t  fast_exp10 = 0;
    int64_t ival    = 0;
    char   num_buf[64];
    char*  num_ptr = num_buf;
    size_t num_len;
    char*  end_ptr;

    JSON_ASSERT(l != NULL && arena != NULL && out != NULL);

    /* Optional minus */
    if (l->pos < l->len && l->src[l->pos] == '-') {
        negative = true;
        l->pos++;
    }

    if (l->pos >= l->len) {
        l->err = JSON_ERR_UNEXPECTED_EOF;
        return JSON_ERR_UNEXPECTED_EOF;
    }

#define JSON__FAST_DIGIT(d_) do {                              \
    uint32_t jd_ = (uint32_t)(d_);                              \
    if (fast_sig != 0U || jd_ != 0U) {                          \
        if (fast_sig >= 19U) { fast_ok = false; }               \
        else { fast_mant = fast_mant * 10U + jd_; fast_sig++; } \
    }                                                           \
} while (0)

    /* Integer part */
    if (l->src[l->pos] == '0') {
        l->pos++;
        if (l->pos < l->len && l->src[l->pos] >= '0' && l->src[l->pos] <= '9') {
            l->err = JSON_ERR_INVALID_NUMBER;
            return JSON_ERR_INVALID_NUMBER;
        }
    } else if (l->src[l->pos] >= '1' && l->src[l->pos] <= '9') {
        while (l->pos < l->len &&
               l->src[l->pos] >= '0' && l->src[l->pos] <= '9') {
            JSON__FAST_DIGIT((uint8_t)(l->src[l->pos] - '0'));
            l->pos++;
        }
    } else {
        l->err = JSON_ERR_INVALID_NUMBER;
        return JSON_ERR_INVALID_NUMBER;
    }

    /* Fractional part */
    if (l->pos < l->len && l->src[l->pos] == '.') {
        is_float = true;
        l->pos++;
        if (l->pos >= l->len ||
            l->src[l->pos] < '0' || l->src[l->pos] > '9') {
            l->err = JSON_ERR_INVALID_NUMBER;
            return JSON_ERR_INVALID_NUMBER;
        }
        while (l->pos < l->len &&
               l->src[l->pos] >= '0' && l->src[l->pos] <= '9') {
            JSON__FAST_DIGIT((uint8_t)(l->src[l->pos] - '0'));
            fast_exp10--;
            l->pos++;
        }
    }

    /* Exponent part */
    if (l->pos < l->len &&
        (l->src[l->pos] == 'e' || l->src[l->pos] == 'E')) {
        int32_t exp_val = 0;
        bool exp_neg = false;
        is_float = true;
        l->pos++;
        if (l->pos < l->len &&
            (l->src[l->pos] == '+' || l->src[l->pos] == '-')) {
            exp_neg = (l->src[l->pos] == '-');
            l->pos++;
        }
        if (l->pos >= l->len ||
            l->src[l->pos] < '0' || l->src[l->pos] > '9') {
            l->err = JSON_ERR_INVALID_NUMBER;
            return JSON_ERR_INVALID_NUMBER;
        }
        while (l->pos < l->len &&
               l->src[l->pos] >= '0' && l->src[l->pos] <= '9') {
            int32_t d = (int32_t)(uint8_t)(l->src[l->pos] - '0');
            if (exp_val > 1000) { fast_ok = false; }
            else { exp_val = exp_val * 10 + d; }
            l->pos++;
        }
        fast_exp10 += exp_neg ? -exp_val : exp_val;
    }

    num_len = l->pos - start;

    if (is_float) {
        double fval;
#if JSON_FAST_FLOAT
        if (fast_ok && json__fast_float_from_parts(fast_mant, fast_sig,
                                                   fast_exp10, negative,
                                                   &fval)) {
            out->type = JSON_FLOAT;
            out->v.f  = fval;
            return JSON_OK;
        }
#endif
        {
            if (num_len >= sizeof(num_buf)) {
                num_ptr = (char*)json__arena_alloc_uninit(arena, num_len + 1U);
                if (JSON_UNLIKELY(num_ptr == NULL)) {
                    l->err = JSON_ERR_OOM;
                    return JSON_ERR_OOM;
                }
            }
            JSON_MEMCPY(num_ptr, l->src + start, num_len);
            num_ptr[num_len] = '\0';

            fval = JSON_STRTOD(num_ptr, &end_ptr);
            if (end_ptr != num_ptr + num_len) {
                l->err = JSON_ERR_INVALID_NUMBER;
                return JSON_ERR_INVALID_NUMBER;
            }
            if (JSON_UNLIKELY(isnan(fval) || isinf(fval))) {
                l->err = JSON_ERR_INVALID_NUMBER;
                return JSON_ERR_INVALID_NUMBER;
            }
            out->type = JSON_FLOAT;
            out->v.f  = fval;
        }
    } else {
        static const uint64_t POS_LIMIT = 9223372036854775807ULL;
        static const uint64_t NEG_LIMIT = 9223372036854775808ULL;
        const uint64_t limit = negative ? NEG_LIMIT : POS_LIMIT;

        if (JSON_UNLIKELY(!fast_ok || fast_mant > limit)) {
            l->err = JSON_ERR_OVERFLOW;
            return JSON_ERR_OVERFLOW;
        }

        if (negative) {
            ival = (fast_mant == NEG_LIMIT)
                 ? (int64_t)(-9223372036854775807LL - 1LL)
                 : -(int64_t)fast_mant;
        } else {
            ival = (int64_t)fast_mant;
        }
        out->type = JSON_INTEGER;
        out->v.i  = ival;
    }
    return JSON_OK;
}

#undef JSON__FAST_DIGIT

/* ── §11.8  Iterative Parser ────────────────────────────────────────────── */

/*
 * DESIGN: Recursive descent is simpler but risks stack overflow on deeply
 * nested input. This iterative implementation uses an explicit heap-allocated
 * parse stack with bounded depth (JSON_MAX_DEPTH), making stack usage O(1)
 * regardless of nesting depth. WCET is O(n * JSON_MAX_DEPTH) in theory,
 * O(n) in practice since depth is constant.
 */

typedef enum {
    PS_VALUE,       /* Expecting any value                      */
    PS_ARR_ITEM,    /* Inside array: expecting value or ']'     */
    PS_ARR_CONT,    /* After array item: expecting ',' or ']'   */
    PS_OBJ_KEY,     /* Inside object: expecting key or '}'      */
    PS_OBJ_COLON,   /* After key: expecting ':'                 */
    PS_OBJ_VAL,     /* After colon: expecting value             */
    PS_OBJ_CONT     /* After value: expecting ',' or '}'        */
} ParseState;

typedef struct {
    JsonValue*   container;  /* Array or Object being built */
    ParseState   state;
    JsonStr      pending_key; /* For PS_OBJ_VAL: key waiting for its value */
} ParseFrame;

/**
 * @brief  Allocate and initialize a new JsonValue node.
 * @note   Node count is tracked and bounded by JSON_MAX_NODES.
 */
static JsonValue* json__new_node(JsonArena* arena)
{
    JsonValue* v;

    JSON_ASSERT(arena != NULL);

    if (JSON_UNLIKELY(arena->node_count >= JSON_MAX_NODES)) { return NULL; }
    v = (JsonValue*)json__arena_alloc_uninit(arena, sizeof(JsonValue));
    if (JSON_LIKELY(v != NULL)) {
        arena->node_count++;
    }
    return v;
}

/** @brief Grow array capacity (doubling strategy). */
static JsonError json__arr_grow(JsonArr* a, JsonArena* arena)
{
    uint32_t  new_cap;
    JsonValue** new_items;

    JSON_ASSERT(a != NULL && arena != NULL);

    new_cap = (a->cap == 0U) ? 8U : a->cap * 2U;

    /* Overflow guard */
    if (JSON_UNLIKELY(new_cap < a->cap)) { return JSON_ERR_OVERFLOW; }
    if (JSON_UNLIKELY(new_cap > JSON_MAX_ARRAY_LEN)) { return JSON_ERR_OVERFLOW; }

    new_items = (JsonValue**)json__arena_alloc_uninit(arena,
                    (size_t)new_cap * sizeof(JsonValue*));
    if (JSON_UNLIKELY(new_items == NULL)) { return JSON_ERR_OOM; }

    if (a->items != NULL && a->len > 0U) {
        JSON_MEMCPY(new_items, a->items, (size_t)a->len * sizeof(JsonValue*));
    }
    a->items = new_items;
    a->cap   = new_cap;
    return JSON_OK;
}

/** @brief Grow object capacity (doubling strategy). */
static JsonError json__obj_grow(JsonObj* o, JsonArena* arena)
{
    uint32_t  new_cap;
    JsonPair* new_pairs;

    JSON_ASSERT(o != NULL && arena != NULL);

    new_cap = (o->cap == 0U) ? 8U : o->cap * 2U;
    if (JSON_UNLIKELY(new_cap < o->cap)) { return JSON_ERR_OVERFLOW; }

    new_pairs = (JsonPair*)json__arena_alloc_uninit(arena,
                    (size_t)new_cap * sizeof(JsonPair));
    if (JSON_UNLIKELY(new_pairs == NULL)) { return JSON_ERR_OOM; }

    if (o->pairs != NULL && o->len > 0U) {
        JSON_MEMCPY(new_pairs, o->pairs, (size_t)o->len * sizeof(JsonPair));
    }
    o->pairs     = new_pairs;
    o->cap       = new_cap;
    o->sorted_idx= NULL;  /* Invalidated on resize */
    o->is_sorted = false;
    return JSON_OK;
}

/**
 * @brief  Main iterative parser.
 * @note   All error paths set err_out before returning NULL.
 * @note   WCET: O(n) where n = input length.
 */
JsonValue* json_parse(JsonArena* arena, const char* src, size_t len,
                      JsonError* err_out)
{
    JsonLex      lex;
    ParseFrame   stack[JSON_MAX_DEPTH];
    uint32_t     depth      = 0U;
    JsonValue*   result     = NULL;
    JsonValue*   root       = NULL;
    JsonError    err        = JSON_OK;
    bool         done       = false;

    /* Validate parameters */
    if (arena == NULL) {
        if (err_out != NULL) { *err_out = JSON_ERR_NULL_PARAM; }
        return NULL;
    }
    if (src == NULL && len > 0U) {
        if (err_out != NULL) { *err_out = JSON_ERR_NULL_PARAM; }
        return NULL;
    }

    JSON_MEMSET(&lex, 0, sizeof(lex));
    lex.src  = src ? src : "";
    lex.len  = len;
    lex.pos  = 0U;
    lex.line = 1U;
    lex.col  = 0U;

    /* Push initial state */
    stack[0].state         = PS_VALUE;
    stack[0].container     = NULL;
    depth                  = 1U;

#define LEX_EXPECT_LITERAL(literal, tok_type) do { \
    size_t llen_ = sizeof(literal) - 1U;           \
    if (lex.pos + llen_ > lex.len ||               \
        JSON_MEMCMP(lex.src + lex.pos, literal, llen_) != 0) { \
        err = JSON_ERR_INVALID_JSON; goto parse_error; \
    }                                               \
    lex.pos += llen_;                               \
} while(0)

    while (!done) {
        ParseFrame* frame = &stack[depth - 1U];

        json__lex_skip_ws(&lex);

        if (lex.pos >= lex.len) {
            if (depth == 1U && root != NULL) {
                done = true;
                break;
            }
            err = JSON_ERR_UNEXPECTED_EOF;
            goto parse_error;
        }

        switch (frame->state) {

        /* ── Expecting a value (any type) ─────────────────────────────── */
        case PS_VALUE: {
            char c = lex.src[lex.pos];
            JsonValue* node = json__new_node(arena);
            if (JSON_UNLIKELY(node == NULL)) {
                err = (arena->node_count >= JSON_MAX_NODES)
                      ? JSON_ERR_NODE_LIMIT : JSON_ERR_OOM;
                goto parse_error;
            }

            if (c == 'n') {
                lex.pos++;
                LEX_EXPECT_LITERAL("ull", 0);
                node->type = JSON_NULL;

            } else if (c == 't') {
                lex.pos++;
                LEX_EXPECT_LITERAL("rue", 0);
                node->type  = JSON_BOOL;
                node->v.b   = true;

            } else if (c == 'f') {
                lex.pos++;
                LEX_EXPECT_LITERAL("alse", 0);
                node->type  = JSON_BOOL;
                node->v.b   = false;

            } else if (c == '"') {
                lex.pos++; /* Skip opening quote */
                node->type = JSON_STRING;
                err = json__parse_string(&lex, arena, &node->v.s);
                if (err != JSON_OK) { goto parse_error; }

            } else if (c == '-' ||
                       (c >= '0' && c <= '9')) {
                err = json__parse_number(&lex, arena, node);
                if (err != JSON_OK) { goto parse_error; }

            } else if (c == '[') {
                lex.pos++;
                node->type  = JSON_ARRAY;
                node->v.a.items = NULL;
                node->v.a.len   = 0U;
                node->v.a.cap   = 0U;

                /* Push array context */
                if (depth >= JSON_MAX_DEPTH) {
                    err = JSON_ERR_DEPTH_EXCEEDED;
                    goto parse_error;
                }
                result = node;

                /* Store in parent if applicable, then push new frame */
                frame->container = node;
                frame->state     = PS_ARR_ITEM;

                /* Check for empty array */
                json__lex_skip_ws(&lex);
                if (lex.pos < lex.len && lex.src[lex.pos] == ']') {
                    lex.pos++;
                    /* Empty array: immediately deliver to parent */
                    goto deliver_to_parent;
                }

                /* Push VALUE frame for first element */
                stack[depth].state     = PS_VALUE;
                stack[depth].container = NULL;
                depth++;
                continue;

            } else if (c == '{') {
                lex.pos++;
                node->type         = JSON_OBJECT;
                node->v.o.pairs    = NULL;
                node->v.o.sorted_idx = NULL;
                node->v.o.len      = 0U;
                node->v.o.cap      = 0U;
                node->v.o.is_sorted= false;

                if (depth >= JSON_MAX_DEPTH) {
                    err = JSON_ERR_DEPTH_EXCEEDED;
                    goto parse_error;
                }

                frame->container = node;
                frame->state     = PS_OBJ_KEY;

                /* Check for empty object */
                json__lex_skip_ws(&lex);
                if (lex.pos < lex.len && lex.src[lex.pos] == '}') {
                    lex.pos++;
                    result = node;
                    goto deliver_to_parent;
                }

                /*
                 * DESIGN: this frame has been transformed in-place to
                 * PS_OBJ_KEY.  The main loop will execute case PS_OBJ_KEY on
                 * the next iteration — no extra frame push is needed.
                 * Pushing a second PS_OBJ_KEY frame here (as done before this
                 * fix) left stack[depth-1] as PS_OBJ_KEY when the closing '}'
                 * tried to deliver the object to its parent, causing an
                 * "invalid JSON" error on every non-empty object.
                 */
                continue;

            } else {
                err = JSON_ERR_INVALID_JSON;
                goto parse_error;
            }

            result = node;

            /* Deliver completed scalar to parent */
            deliver_to_parent:
            {
                if (depth == 1U) {
                    /* Top-level value */
                    root = result;
                    done = true;
                    break;
                }

                /* Pop current frame and deliver to parent */
                depth--;
                ParseFrame* parent = &stack[depth - 1U];

                if (parent->state == PS_ARR_ITEM ||
                    parent->state == PS_ARR_CONT) {
                    /* Add to array */
                    JsonArr* arr = &parent->container->v.a;
                    if (arr->len >= arr->cap) {
                        err = json__arr_grow(arr, arena);
                        if (err != JSON_OK) { goto parse_error; }
                    }
                    arr->items[arr->len++] = result;
                    parent->state = PS_ARR_CONT;

                } else if (parent->state == PS_OBJ_VAL) {
                    /* Add key-value pair to object */
                    JsonObj* obj = &parent->container->v.o;
                    if (obj->len >= obj->cap) {
                        err = json__obj_grow(obj, arena);
                        if (err != JSON_OK) { goto parse_error; }
                    }
                    obj->pairs[obj->len].key = parent->pending_key;
                    obj->pairs[obj->len].val = result;
                    obj->len++;
                    parent->state = PS_OBJ_CONT;
                } else {
                    err = JSON_ERR_INVALID_JSON;
                    goto parse_error;
                }
            }
            break;
        } /* PS_VALUE */

        /* ── After array item: ',' or ']' ─────────────────────────────── */
        case PS_ARR_CONT: {
            char c = lex.src[lex.pos];
            if (c == ']') {
                lex.pos++;
                result = frame->container;
                /* Pop and deliver array to its parent */
                if (depth == 1U) {
                    root = result;
                    done = true;
                } else {
                    depth--;
                    ParseFrame* parent = &stack[depth - 1U];
                    JsonArr* arr;

                    if (parent->state == PS_ARR_ITEM ||
                        parent->state == PS_ARR_CONT) {
                        arr = &parent->container->v.a;
                        if (arr->len >= arr->cap) {
                            err = json__arr_grow(arr, arena);
                            if (err != JSON_OK) { goto parse_error; }
                        }
                        arr->items[arr->len++] = result;
                        parent->state = PS_ARR_CONT;
                    } else if (parent->state == PS_OBJ_VAL) {
                        JsonObj* obj = &parent->container->v.o;
                        if (obj->len >= obj->cap) {
                            err = json__obj_grow(obj, arena);
                            if (err != JSON_OK) { goto parse_error; }
                        }
                        obj->pairs[obj->len].key = parent->pending_key;
                        obj->pairs[obj->len].val = result;
                        obj->len++;
                        parent->state = PS_OBJ_CONT;
                    } else if (parent->state == PS_VALUE) {
                        root = result; done = true;
                    } else {
                        err = JSON_ERR_INVALID_JSON; goto parse_error;
                    }
                }
            } else if (c == ',') {
                lex.pos++;
                frame->state = PS_ARR_ITEM;
                /* Push VALUE frame for next element */
                if (depth >= JSON_MAX_DEPTH) {
                    err = JSON_ERR_DEPTH_EXCEEDED; goto parse_error;
                }
                stack[depth].state     = PS_VALUE;
                stack[depth].container = NULL;
                depth++;
            } else {
                err = JSON_ERR_INVALID_JSON; goto parse_error;
            }
            break;
        }

        /* ── Object: expecting key ─────────────────────────────────────── */
        case PS_OBJ_KEY: {
            char c = lex.src[lex.pos];
            if (c == '"') {
                JsonStr key;
                lex.pos++; /* Skip quote */
                err = json__parse_string(&lex, arena, &key);
                if (err != JSON_OK) { goto parse_error; }
                frame->pending_key = key;
                frame->state = PS_OBJ_COLON;
            } else {
                err = JSON_ERR_INVALID_JSON; goto parse_error;
            }
            break;
        }

        /* ── After object key: expect ':' ─────────────────────────────── */
        case PS_OBJ_COLON: {
            if (lex.src[lex.pos] != ':') {
                err = JSON_ERR_INVALID_JSON; goto parse_error;
            }
            lex.pos++;
            frame->state = PS_OBJ_VAL;
            /* Push VALUE frame for the value */
            if (depth >= JSON_MAX_DEPTH) {
                err = JSON_ERR_DEPTH_EXCEEDED; goto parse_error;
            }
            stack[depth].state     = PS_VALUE;
            stack[depth].container = NULL;
            depth++;
            break;
        }

        /* ── After object value: ',' or '}' ───────────────────────────── */
        case PS_OBJ_CONT: {
            char c = lex.src[lex.pos];
            if (c == '}') {
                lex.pos++;
                result = frame->container;
                if (depth == 1U) {
                    root = result; done = true;
                } else {
                    depth--;
                    ParseFrame* parent = &stack[depth - 1U];
                    if (parent->state == PS_ARR_ITEM ||
                        parent->state == PS_ARR_CONT) {
                        JsonArr* arr = &parent->container->v.a;
                        if (arr->len >= arr->cap) {
                            err = json__arr_grow(arr, arena);
                            if (err != JSON_OK) { goto parse_error; }
                        }
                        arr->items[arr->len++] = result;
                        parent->state = PS_ARR_CONT;
                    } else if (parent->state == PS_OBJ_VAL) {
                        JsonObj* obj = &parent->container->v.o;
                        if (obj->len >= obj->cap) {
                            err = json__obj_grow(obj, arena);
                            if (err != JSON_OK) { goto parse_error; }
                        }
                        obj->pairs[obj->len].key = parent->pending_key;
                        obj->pairs[obj->len].val = result;
                        obj->len++;
                        parent->state = PS_OBJ_CONT;
                    } else if (parent->state == PS_VALUE) {
                        root = result; done = true;
                    } else {
                        err = JSON_ERR_INVALID_JSON; goto parse_error;
                    }
                }
            } else if (c == ',') {
                lex.pos++;
                frame->state = PS_OBJ_KEY;
            } else {
                err = JSON_ERR_INVALID_JSON; goto parse_error;
            }
            break;
        }

        case PS_ARR_ITEM:
        case PS_OBJ_VAL:
        default:
            /* These states should be handled by pushing a PS_VALUE frame */
            err = JSON_ERR_INVALID_JSON;
            goto parse_error;
        } /* switch */
    } /* while */

    /* Verify no trailing non-whitespace */
    if (!done) { err = JSON_ERR_UNEXPECTED_EOF; goto parse_error; }
    json__lex_skip_ws(&lex);
    if (lex.pos < lex.len) {
        err = JSON_ERR_INVALID_JSON;
        goto parse_error;
    }

#undef LEX_EXPECT_LITERAL

    if (err_out != NULL) { *err_out = JSON_OK; }
    return root;

parse_error:
    if (err_out != NULL) { *err_out = (err != JSON_OK) ? err : JSON_ERR_INVALID_JSON; }
    return NULL;
}

JsonValue* json_parse_cstr(JsonArena* arena, const char* src, JsonError* err_out)
{
    if (src == NULL) {
        if (err_out != NULL) { *err_out = JSON_ERR_NULL_PARAM; }
        return NULL;
    }
    return json_parse(arena, src, JSON_STRLEN(src), err_out);
}

/* ── §11.9  Type-safe accessors ─────────────────────────────────────────── */

#define JSON__CHECK_V(v)  do { if ((v) == NULL) return JSON_ERR_NULL_PARAM; } while(0)
#define JSON__CHECK_OUT(o) do { if ((o) == NULL) return JSON_ERR_NULL_PARAM; } while(0)

JsonError json_get_bool(const JsonValue* v, bool* out)
{
    JSON__CHECK_V(v); JSON__CHECK_OUT(out);
    if (v->type != JSON_BOOL)    { return JSON_ERR_TYPE_MISMATCH; }
    *out = v->v.b;
    return JSON_OK;
}

JsonError json_get_int(const JsonValue* v, int64_t* out)
{
    JSON__CHECK_V(v); JSON__CHECK_OUT(out);
    if (v->type == JSON_INTEGER) { *out = v->v.i; return JSON_OK; }
    if (v->type == JSON_FLOAT)   { *out = (int64_t)v->v.f; return JSON_OK; }
    return JSON_ERR_TYPE_MISMATCH;
}

JsonError json_get_float(const JsonValue* v, double* out)
{
    JSON__CHECK_V(v); JSON__CHECK_OUT(out);
    if (v->type == JSON_FLOAT)   { *out = v->v.f; return JSON_OK; }
    if (v->type == JSON_INTEGER) { *out = (double)v->v.i; return JSON_OK; }
    return JSON_ERR_TYPE_MISMATCH;
}

JsonError json_get_number(const JsonValue* v, double* out)
{
    return json_get_float(v, out);
}

JsonError json_get_string(const JsonValue* v, const char** out, uint32_t* len_out)
{
    JSON__CHECK_V(v); JSON__CHECK_OUT(out);
    if (v->type != JSON_STRING)  { return JSON_ERR_TYPE_MISMATCH; }
    *out = v->v.s.data ? v->v.s.data : "";
    if (len_out != NULL) { *len_out = v->v.s.len; }
    return JSON_OK;
}

JsonError json_get_arr_len(const JsonValue* v, uint32_t* out)
{
    JSON__CHECK_V(v); JSON__CHECK_OUT(out);
    if (v->type != JSON_ARRAY)   { return JSON_ERR_TYPE_MISMATCH; }
    *out = v->v.a.len;
    return JSON_OK;
}

JsonError json_get_obj_len(const JsonValue* v, uint32_t* out)
{
    JSON__CHECK_V(v); JSON__CHECK_OUT(out);
    if (v->type != JSON_OBJECT)  { return JSON_ERR_TYPE_MISMATCH; }
    *out = v->v.o.len;
    return JSON_OK;
}

JsonError json_arr_get(const JsonValue* v, uint32_t idx, JsonValue** out)
{
    JSON__CHECK_V(v); JSON__CHECK_OUT(out);
    if (v->type != JSON_ARRAY)          { return JSON_ERR_TYPE_MISMATCH; }
    if (idx >= v->v.a.len)              { return JSON_ERR_NOT_FOUND; }
    JSON_ASSERT(v->v.a.items != NULL);
    *out = v->v.a.items[idx];
    return JSON_OK;
}

JsonError json_obj_get_n(const JsonValue* v, const char* key, size_t klen,
                         JsonValue** out)
{
    const JsonObj* o;
    uint32_t       hash;
    int32_t        lo, hi, mid;
    int            cmp;
    uint32_t       idx;

    JSON__CHECK_V(v); JSON__CHECK_OUT(out);
    if (key == NULL)               { return JSON_ERR_NULL_PARAM; }
    if (v->type != JSON_OBJECT)    { return JSON_ERR_TYPE_MISMATCH; }

    o = &v->v.o;
    if (o->len == 0U)              { return JSON_ERR_NOT_FOUND; }

    /* If not yet sorted, do a linear scan */
    if (!o->is_sorted || o->sorted_idx == NULL) {
        uint32_t i;
        hash = json_fnv1a(key, klen);
        for (i = 0U; i < o->len; i++) {
            const JsonStr* k = &o->pairs[i].key;
            if (k->hash == hash && k->len == (uint32_t)klen &&
                JSON_MEMCMP(k->data, key, klen) == 0) {
                *out = o->pairs[i].val;
                return JSON_OK;
            }
        }
        return JSON_ERR_NOT_FOUND;
    }

    /* Binary search on sorted_idx */
    hash = json_fnv1a(key, klen);
    lo = 0; hi = (int32_t)o->len - 1;

    while (lo <= hi) {
        mid = lo + (hi - lo) / 2;
        idx = o->sorted_idx[(uint32_t)mid];
        const JsonStr* k = &o->pairs[idx].key;

        if (k->hash < hash) {
            lo = mid + 1;
        } else if (k->hash > hash) {
            hi = mid - 1;
        } else {
            /* Hash match: compare lexicographically */
            uint32_t min_len = (k->len < (uint32_t)klen) ? k->len : (uint32_t)klen;
            cmp = JSON_MEMCMP(k->data, key, (size_t)min_len);
            if (cmp == 0) {
                if (k->len < (uint32_t)klen) { cmp = -1; }
                else if (k->len > (uint32_t)klen) { cmp = 1; }
            }
            if (cmp == 0) {
                *out = o->pairs[idx].val;
                return JSON_OK;
            } else if (cmp < 0) {
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
    }
    return JSON_ERR_NOT_FOUND;
}

JsonError json_obj_get(const JsonValue* v, const char* key, JsonValue** out)
{
    if (key == NULL) { return JSON_ERR_NULL_PARAM; }
    return json_obj_get_n(v, key, JSON_STRLEN(key), out);
}

JsonError json_obj_iter(const JsonValue* v, uint32_t idx,
                        const char** key_out, uint32_t* klen,
                        JsonValue** val_out)
{
    JSON__CHECK_V(v);
    if (v->type != JSON_OBJECT) { return JSON_ERR_TYPE_MISMATCH; }
    if (idx >= v->v.o.len)      { return JSON_ERR_NOT_FOUND; }

    if (key_out != NULL) { *key_out = v->v.o.pairs[idx].key.data; }
    if (klen    != NULL) { *klen    = v->v.o.pairs[idx].key.len;  }
    if (val_out != NULL) { *val_out = v->v.o.pairs[idx].val;      }
    return JSON_OK;
}

/* ── §11.10  Path query ─────────────────────────────────────────────────── */

JsonValue* json_path(const JsonValue* root, const char* path, JsonError* err_out)
{
    const JsonValue* cur;
    const char*      p;
    JsonError        err;
    char             key_buf[512];

    if (root == NULL || path == NULL) {
        if (err_out != NULL) { *err_out = JSON_ERR_NULL_PARAM; }
        return NULL;
    }

    cur = root;
    p   = path;

    while (*p != '\0') {
        /* Skip leading dot if present */
        if (*p == '.') { p++; }

        if (*p == '[') {
            /* Bracket notation: [N] or ["key"] */
            p++;
            if (*p == '"') {
                /* ["string key"] */
                const char* ks = ++p;
                while (*p != '\0' && *p != '"') { p++; }
                if (*p == '\0') {
                    err = JSON_ERR_INVALID_JSON; goto fail;
                }
                size_t klen = (size_t)(p - ks);
                p++; /* skip closing " */
                if (*p != ']') { err = JSON_ERR_INVALID_JSON; goto fail; }
                p++;
                JsonValue* out;
                err = json_obj_get_n(cur, ks, klen, &out);
                if (err != JSON_OK) { goto fail; }
                cur = out;
            } else if (*p >= '0' && *p <= '9') {
                /* [N] */
                uint32_t idx = 0U;
                while (*p >= '0' && *p <= '9') {
                    uint32_t prev = idx;
                    idx = idx * 10U + (uint32_t)(*p - '0');
                    if (idx < prev) { err = JSON_ERR_OVERFLOW; goto fail; }
                    p++;
                }
                if (*p != ']') { err = JSON_ERR_INVALID_JSON; goto fail; }
                p++;
                JsonValue* out;
                err = json_arr_get(cur, idx, &out);
                if (err != JSON_OK) { goto fail; }
                cur = out;
            } else {
                err = JSON_ERR_INVALID_JSON; goto fail;
            }
        } else if ((*p >= 'a' && *p <= 'z') ||
                   (*p >= 'A' && *p <= 'Z') ||
                   (*p == '_')              ||
                   ((uint8_t)*p >= 0x80U)) {
            /* Dot notation: .identifier */
            const char* ks = p;
            while (*p != '\0' && *p != '.' && *p != '[') { p++; }
            size_t klen = (size_t)(p - ks);
            if (klen >= sizeof(key_buf)) { err = JSON_ERR_OVERFLOW; goto fail; }
            JSON_MEMCPY(key_buf, ks, klen);
            key_buf[klen] = '\0';
            JsonValue* out;
            err = json_obj_get_n(cur, ks, klen, &out);
            if (err != JSON_OK) { goto fail; }
            cur = out;
        } else {
            err = JSON_ERR_INVALID_JSON; goto fail;
        }
    }

    if (err_out != NULL) { *err_out = JSON_OK; }
    return (JsonValue*)(uintptr_t)cur; /* Cast away const for API convenience */

fail:
    if (err_out != NULL) { *err_out = err; }
    return NULL;
}

/* ── §11.11  Serializer ─────────────────────────────────────────────────── */

typedef struct {
    char*    buf;
    size_t   cap;
    size_t   used;
    bool     measure_only; /* When true: just count, don't write */
    JsonError err;
} JsonWriter;

JSON_INLINE JsonError jw_put(JsonWriter* w, char c)
{
    if (w->measure_only) { w->used++; return JSON_OK; }
    if (w->used >= w->cap - 1U) { w->err = JSON_ERR_BUFFER_TOO_SMALL; return JSON_ERR_BUFFER_TOO_SMALL; }
    w->buf[w->used++] = c;
    return JSON_OK;
}

static JsonError jw_puts(JsonWriter* w, const char* s, size_t n)
{
    size_t i;
    if (w->measure_only) { w->used += n; return JSON_OK; }
    for (i = 0U; i < n; i++) {
        if (jw_put(w, s[i]) != JSON_OK) { return JSON_ERR_BUFFER_TOO_SMALL; }
    }
    return JSON_OK;
}

static JsonError jw_indent(JsonWriter* w, uint32_t depth, uint32_t indent_sz)
{
    uint32_t i;
    for (i = 0U; i < depth * indent_sz; i++) {
        if (jw_put(w, ' ') != JSON_OK) { return JSON_ERR_BUFFER_TOO_SMALL; }
    }
    return JSON_OK;
}

/* Integer-to-decimal without sprintf (embedded-safe) */
static JsonError jw_int64(JsonWriter* w, int64_t v)
{
    char   tmp[22]; /* max int64 = 20 digits + sign + NUL */
    uint32_t len = 0U;
    bool   neg   = (v < 0);
    uint64_t abs_v;

    if (neg) {
        abs_v = (v == INT64_MIN) ? (uint64_t)INT64_MAX + 1ULL
                                 : (uint64_t)(-v);
        if (jw_put(w, '-') != JSON_OK) { return JSON_ERR_BUFFER_TOO_SMALL; }
    } else {
        abs_v = (uint64_t)v;
    }

    if (abs_v == 0U) { return jw_put(w, '0'); }

    while (abs_v > 0U) {
        tmp[len++] = (char)('0' + (int)(abs_v % 10U));
        abs_v /= 10U;
    }

    /* Reverse */
    {
        uint32_t i;
        for (i = 0U; i < len; i++) {
            if (jw_put(w, tmp[len - 1U - i]) != JSON_OK) {
                return JSON_ERR_BUFFER_TOO_SMALL;
            }
        }
    }
    return JSON_OK;
}

/* Double-to-string (uses snprintf if available, else fallback) */
static JsonError jw_double(JsonWriter* w, double v)
{
    char   tmp[32];
    size_t len;

#ifndef JSON_NO_STDLIB
    /* Use snprintf for correct double rendering */
    int r = snprintf(tmp, sizeof(tmp), "%.17g", v);
    if (r < 0 || (size_t)r >= sizeof(tmp)) { return JSON_ERR_OVERFLOW; }
    len = (size_t)r;
    /* Ensure there's a decimal point or exponent so it parses as float */
    {
        bool has_dot = false;
        size_t i;
        for (i = 0U; i < len; i++) {
            if (tmp[i] == '.' || tmp[i] == 'e' || tmp[i] == 'E') {
                has_dot = true; break;
            }
        }
        if (!has_dot && len + 2U < sizeof(tmp)) {
            tmp[len++] = '.'; tmp[len++] = '0'; tmp[len] = '\0';
        }
    }
#else
    /* Freestanding fallback: integer representation if lossless */
    int64_t as_int = (int64_t)v;
    if ((double)as_int == v) {
        snprintf(tmp, sizeof(tmp), "%lld.0", (long long)as_int);
    } else {
        snprintf(tmp, sizeof(tmp), "%g", v);
    }
    len = JSON_STRLEN(tmp);
#endif
    return jw_puts(w, tmp, len);
}

/* Write escaped JSON string content (no surrounding quotes) */
static JsonError jw_string_content(JsonWriter* w, const char* s, uint32_t len,
                                   bool ascii_only)
{
    uint32_t i = 0U;

    while (i < len) {
        uint8_t c = (uint8_t)s[i];

        if (c < 0x20U || c == '"' || c == '\\' ||
            (ascii_only && c >= 0x80U)) {
            /* Escape */
            char esc_buf[7]; /* \uXXXX + NUL */
            if (c == '"')       { esc_buf[0]='\\'; esc_buf[1]='"';  jw_puts(w, esc_buf, 2U); }
            else if (c == '\\') { esc_buf[0]='\\'; esc_buf[1]='\\'; jw_puts(w, esc_buf, 2U); }
            else if (c == '\n') { esc_buf[0]='\\'; esc_buf[1]='n';  jw_puts(w, esc_buf, 2U); }
            else if (c == '\r') { esc_buf[0]='\\'; esc_buf[1]='r';  jw_puts(w, esc_buf, 2U); }
            else if (c == '\t') { esc_buf[0]='\\'; esc_buf[1]='t';  jw_puts(w, esc_buf, 2U); }
            else if (c == '\b') { esc_buf[0]='\\'; esc_buf[1]='b';  jw_puts(w, esc_buf, 2U); }
            else if (c == '\f') { esc_buf[0]='\\'; esc_buf[1]='f';  jw_puts(w, esc_buf, 2U); }
            else {
                /* \uXXXX */
                static const char hex[] = "0123456789abcdef";
                esc_buf[0]='\\'; esc_buf[1]='u';
                esc_buf[2]='0';  esc_buf[3]='0';
                esc_buf[4]=hex[(c>>4)&0xFU];
                esc_buf[5]=hex[c&0xFU];
                jw_puts(w, esc_buf, 6U);
            }
            i++;
        } else {
            jw_put(w, (char)c);
            i++;
        }
    }
    return w->err;
}

/** @brief Core recursive serializer. Uses C stack but depth is bounded at parse time. */
static JsonError json__write_value(JsonWriter* w, const JsonValue* v,
                                   uint32_t depth,
                                   const JsonWriteOpts* opts)
{
    JsonError err;

    JSON_ASSERT(v != NULL && opts != NULL);

    switch (v->type) {
    case JSON_NULL:
        return jw_puts(w, "null", 4U);

    case JSON_BOOL:
        return v->v.b ? jw_puts(w, "true", 4U) : jw_puts(w, "false", 5U);

    case JSON_INTEGER:
        return jw_int64(w, v->v.i);

    case JSON_FLOAT:
        return jw_double(w, v->v.f);

    case JSON_STRING:
        err = jw_put(w, '"');
        if (err != JSON_OK) { return err; }
        err = jw_string_content(w, v->v.s.data ? v->v.s.data : "",
                                v->v.s.len, opts->ascii_only);
        if (err != JSON_OK) { return err; }
        return jw_put(w, '"');

    case JSON_ARRAY: {
        const JsonArr* a = &v->v.a;
        uint32_t i;
        err = jw_put(w, '[');
        if (err != JSON_OK) { return err; }
        for (i = 0U; i < a->len; i++) {
            if (opts->pretty) {
                jw_put(w, '\n');
                jw_indent(w, depth + 1U, opts->indent);
            }
            err = json__write_value(w, a->items[i], depth + 1U, opts);
            if (err != JSON_OK) { return err; }
            if (i + 1U < a->len) {
                jw_put(w, ',');
                if (!opts->pretty) { /* no space */ }
            }
        }
        if (opts->pretty && a->len > 0U) {
            jw_put(w, '\n');
            jw_indent(w, depth, opts->indent);
        }
        return jw_put(w, ']');
    }

    case JSON_OBJECT: {
        const JsonObj* o = &v->v.o;
        uint32_t i;
        err = jw_put(w, '{');
        if (err != JSON_OK) { return err; }
        for (i = 0U; i < o->len; i++) {
            uint32_t pair_idx = (opts->sort_keys && o->is_sorted && o->sorted_idx)
                                ? o->sorted_idx[i] : i;
            const JsonPair* pair = &o->pairs[pair_idx];
            if (opts->pretty) {
                jw_put(w, '\n');
                jw_indent(w, depth + 1U, opts->indent);
            }
            jw_put(w, '"');
            jw_string_content(w, pair->key.data ? pair->key.data : "",
                              pair->key.len, opts->ascii_only);
            jw_put(w, '"');
            jw_put(w, ':');
            if (opts->pretty) { jw_put(w, ' '); }
            err = json__write_value(w, pair->val, depth + 1U, opts);
            if (err != JSON_OK) { return err; }
            if (i + 1U < o->len) {
                jw_put(w, ',');
            }
        }
        if (opts->pretty && o->len > 0U) {
            jw_put(w, '\n');
            jw_indent(w, depth, opts->indent);
        }
        return jw_put(w, '}');
    }

    default:
        return JSON_ERR_INVALID_JSON;
    }
}

static const JsonWriteOpts k_default_opts = { false, 2U, false, false, false };

JsonError json_write(const JsonValue* v, char* buf, size_t buf_size,
                     size_t* written, const JsonWriteOpts* opts)
{
    JsonWriter w;
    JsonError  err;

    if (v == NULL)   { return JSON_ERR_NULL_PARAM; }
    if (buf == NULL && buf_size > 0U) { return JSON_ERR_NULL_PARAM; }

    if (opts == NULL) { opts = &k_default_opts; }

    JSON_MEMSET(&w, 0, sizeof(w));
    w.buf          = buf;
    w.cap          = buf_size;
    w.measure_only = (buf == NULL);

    err = json__write_value(&w, v, 0U, opts);

    if (err == JSON_OK && !w.measure_only) {
        /* NUL-terminate */
        if (w.used < buf_size) {
            buf[w.used] = '\0';
        } else {
            return JSON_ERR_BUFFER_TOO_SMALL;
        }
        if (opts->trailing_nl && w.used + 1U < buf_size) {
            buf[w.used++] = '\n';
            buf[w.used]   = '\0';
        }
    }

    if (written != NULL) { *written = w.used; }
    return err;
}

JsonError json_measure(const JsonValue* v, size_t* size_out,
                       const JsonWriteOpts* opts)
{
    if (v == NULL || size_out == NULL) { return JSON_ERR_NULL_PARAM; }
    return json_write(v, NULL, 0U, size_out, opts);
}

JsonError json_write_arena(const JsonValue* v, JsonArena* arena,
                           char** out, size_t* len_out,
                           const JsonWriteOpts* opts)
{
    size_t    needed = 0U;
    char*     buf;
    JsonError err;

    if (v == NULL || arena == NULL || out == NULL) { return JSON_ERR_NULL_PARAM; }

    /* Measure first */
    err = json_measure(v, &needed, opts);
    if (err != JSON_OK) { return err; }

    needed += 2U; /* NUL + optional newline */

    buf = (char*)json__arena_alloc_uninit(arena, needed);
    if (JSON_UNLIKELY(buf == NULL)) { return JSON_ERR_OOM; }

    err = json_write(v, buf, needed, len_out, opts);
    if (err != JSON_OK) { return err; }

    *out = buf;
    return JSON_OK;
}

/* ── §11.12  Value construction ─────────────────────────────────────────── */

JsonValue* json_make_null(JsonArena* arena)
{
    JsonValue* v = json__new_node(arena);
    if (v != NULL) { v->type = JSON_NULL; }
    return v;
}

JsonValue* json_make_bool(JsonArena* arena, bool val)
{
    JsonValue* v = json__new_node(arena);
    if (v != NULL) { v->type = JSON_BOOL; v->v.b = val; }
    return v;
}

JsonValue* json_make_int(JsonArena* arena, int64_t val)
{
    JsonValue* v = json__new_node(arena);
    if (v != NULL) { v->type = JSON_INTEGER; v->v.i = val; }
    return v;
}

JsonValue* json_make_float(JsonArena* arena, double val)
{
    JsonValue* v;
    /* Safety: never store NaN or Inf */
    if (isnan(val) || isinf(val)) { return NULL; }
    v = json__new_node(arena);
    if (v != NULL) { v->type = JSON_FLOAT; v->v.f = val; }
    return v;
}

JsonValue* json_make_string(JsonArena* arena, const char* s, uint32_t len)
{
    JsonValue* v;
    char*      copy;

    if (arena == NULL) { return NULL; }
    v = json__new_node(arena);
    if (v == NULL) { return NULL; }

    if (len == 0U || s == NULL) {
        v->type    = JSON_STRING;
        v->v.s.data= NULL;
        v->v.s.len = 0U;
        v->v.s.hash= json_fnv1a(NULL, 0U);
        return v;
    }

    copy = (char*)json__arena_alloc_uninit(arena, (size_t)len);
    if (JSON_UNLIKELY(copy == NULL)) { return NULL; }
    JSON_MEMCPY(copy, s, (size_t)len);

    v->type    = JSON_STRING;
    v->v.s.data= copy;
    v->v.s.len = len;
    v->v.s.hash= json_fnv1a(copy, len);
    return v;
}

JsonValue* json_make_stringz(JsonArena* arena, const char* s)
{
    if (s == NULL) { return json_make_string(arena, NULL, 0U); }
    return json_make_string(arena, s, (uint32_t)JSON_STRLEN(s));
}

JsonValue* json_make_array(JsonArena* arena)
{
    JsonValue* v = json__new_node(arena);
    if (v != NULL) {
        v->type      = JSON_ARRAY;
        v->v.a.items = NULL;
        v->v.a.len   = 0U;
        v->v.a.cap   = 0U;
    }
    return v;
}

JsonValue* json_make_object(JsonArena* arena)
{
    JsonValue* v = json__new_node(arena);
    if (v != NULL) {
        v->type            = JSON_OBJECT;
        v->v.o.pairs       = NULL;
        v->v.o.sorted_idx  = NULL;
        v->v.o.len         = 0U;
        v->v.o.cap         = 0U;
        v->v.o.is_sorted   = false;
    }
    return v;
}

JsonError json_arr_push(JsonValue* arr, JsonArena* arena, JsonValue* item)
{
    JsonArr* a;
    JsonError err;

    if (arr == NULL || arena == NULL || item == NULL) { return JSON_ERR_NULL_PARAM; }
    if (arr->type != JSON_ARRAY) { return JSON_ERR_TYPE_MISMATCH; }

    a = &arr->v.a;
    if (a->len >= a->cap) {
        err = json__arr_grow(a, arena);
        if (err != JSON_OK) { return err; }
    }
    a->items[a->len++] = item;
    return JSON_OK;
}

JsonError json_obj_set(JsonValue* obj, JsonArena* arena,
                       const char* key, uint32_t klen, JsonValue* val)
{
    JsonObj*  o;
    JsonError err;
    char*     key_copy;

    if (obj == NULL || arena == NULL || key == NULL || val == NULL) {
        return JSON_ERR_NULL_PARAM;
    }
    if (obj->type != JSON_OBJECT) { return JSON_ERR_TYPE_MISMATCH; }

    o = &obj->v.o;

    /* Check for existing key (update in place) */
    {
        uint32_t  hash = json_fnv1a(key, klen);
        uint32_t  i;
        for (i = 0U; i < o->len; i++) {
            JsonStr* k = &o->pairs[i].key;
            if (k->hash == hash && k->len == klen &&
                JSON_MEMCMP(k->data, key, klen) == 0) {
                o->pairs[i].val = val;
                return JSON_OK;
            }
        }
    }

    /* Insert new pair */
    if (o->len >= o->cap) {
        err = json__obj_grow(o, arena);
        if (err != JSON_OK) { return err; }
    }

    key_copy = (char*)json__arena_alloc_uninit(arena, (size_t)klen);
    if (JSON_UNLIKELY(key_copy == NULL)) { return JSON_ERR_OOM; }
    JSON_MEMCPY(key_copy, key, klen);

    o->pairs[o->len].key.data = key_copy;
    o->pairs[o->len].key.len  = klen;
    o->pairs[o->len].key.hash = json_fnv1a(key_copy, klen);
    o->pairs[o->len].val      = val;
    o->len++;
    o->is_sorted = false; /* Invalidate sort */
    return JSON_OK;
}

JsonError json_obj_setz(JsonValue* obj, JsonArena* arena,
                        const char* key, JsonValue* val)
{
    if (key == NULL) { return JSON_ERR_NULL_PARAM; }
    return json_obj_set(obj, arena, key, (uint32_t)JSON_STRLEN(key), val);
}

/* ── §11.13  Equality & Clone ───────────────────────────────────────────── */

bool json_equal(const JsonValue* a, const JsonValue* b)
{
    uint32_t i;

    if (a == b)   { return true; }
    if (!a || !b) { return false; }
    if (a->type != b->type) {
        /* Allow integer/float cross-comparison */
        if (json_is_number(a) && json_is_number(b)) {
            double da, db;
            json_get_float(a, &da);
            json_get_float(b, &db);
            return da == db;
        }
        return false;
    }

    switch (a->type) {
    case JSON_NULL:    return true;
    case JSON_BOOL:    return a->v.b == b->v.b;
    case JSON_INTEGER: return a->v.i == b->v.i;
    case JSON_FLOAT:   return a->v.f == b->v.f;
    case JSON_STRING:
        if (a->v.s.len != b->v.s.len) { return false; }
        if (a->v.s.hash != b->v.s.hash) { return false; }
        return JSON_MEMCMP(a->v.s.data, b->v.s.data, a->v.s.len) == 0;
    case JSON_ARRAY:
        if (a->v.a.len != b->v.a.len) { return false; }
        for (i = 0U; i < a->v.a.len; i++) {
            if (!json_equal(a->v.a.items[i], b->v.a.items[i])) { return false; }
        }
        return true;
    case JSON_OBJECT:
        if (a->v.o.len != b->v.o.len) { return false; }
        /* Check all keys in a exist in b with equal values */
        for (i = 0U; i < a->v.o.len; i++) {
            const JsonStr* k = &a->v.o.pairs[i].key;
            JsonValue* bval  = NULL;
            if (json_obj_get_n(b, k->data, k->len, &bval) != JSON_OK) {
                return false;
            }
            if (!json_equal(a->v.o.pairs[i].val, bval)) { return false; }
        }
        return true;
    default: return false;
    }
}

JsonValue* json_clone(JsonArena* dst, const JsonValue* src)
{
    JsonValue* out;
    uint32_t   i;

    if (dst == NULL || src == NULL) { return NULL; }

    out = json__new_node(dst);
    if (out == NULL) { return NULL; }

    out->type = src->type;

    switch (src->type) {
    case JSON_NULL:                                               break;
    case JSON_BOOL:    out->v.b = src->v.b;                     break;
    case JSON_INTEGER: out->v.i = src->v.i;                     break;
    case JSON_FLOAT:   out->v.f = src->v.f;                     break;
    case JSON_STRING: {
        char* copy = NULL;
        if (src->v.s.len > 0U && src->v.s.data != NULL) {
            copy = (char*)json__arena_alloc_uninit(dst, src->v.s.len);
            if (copy == NULL) { return NULL; }
            JSON_MEMCPY(copy, src->v.s.data, src->v.s.len);
        }
        out->v.s.data = copy;
        out->v.s.len  = src->v.s.len;
        out->v.s.hash = src->v.s.hash;
        break;
    }
    case JSON_ARRAY: {
        JsonArr* da = &out->v.a;
        const JsonArr* sa = &src->v.a;
        da->len = sa->len;
        da->cap = sa->len;
        da->items = NULL;
        if (sa->len > 0U) {
            da->items = (JsonValue**)json__arena_alloc_uninit(dst,
                            sa->len * sizeof(JsonValue*));
            if (da->items == NULL) { return NULL; }
            for (i = 0U; i < sa->len; i++) {
                da->items[i] = json_clone(dst, sa->items[i]);
                if (da->items[i] == NULL) { return NULL; }
            }
        }
        break;
    }
    case JSON_OBJECT: {
        JsonObj* do_ = &out->v.o;
        const JsonObj* so = &src->v.o;
        do_->len = so->len;
        do_->cap = so->len;
        do_->sorted_idx = NULL;
        do_->is_sorted  = false;
        do_->pairs = NULL;
        if (so->len > 0U) {
            do_->pairs = (JsonPair*)json__arena_alloc_uninit(dst,
                            so->len * sizeof(JsonPair));
            if (do_->pairs == NULL) { return NULL; }
            for (i = 0U; i < so->len; i++) {
                const JsonStr* sk = &so->pairs[i].key;
                char* kc = NULL;
                if (sk->len > 0U && sk->data != NULL) {
                    kc = (char*)json__arena_alloc_uninit(dst, sk->len);
                    if (kc == NULL) { return NULL; }
                    JSON_MEMCPY(kc, sk->data, sk->len);
                }
                do_->pairs[i].key.data = kc;
                do_->pairs[i].key.len  = sk->len;
                do_->pairs[i].key.hash = sk->hash;
                do_->pairs[i].val = json_clone(dst, so->pairs[i].val);
                if (do_->pairs[i].val == NULL) { return NULL; }
            }
        }
        break;
    }
    default: break;
    }
    return out;
}

/* ── §11.14  Object sort (public trigger) ───────────────────────────────── */

/**
 * @brief  Build sorted index for object to enable O(log n) lookup.
 *         Call after parsing if many lookups are expected.
 *
 * @note   Called automatically by json_obj_get if is_sorted == false.
 *         To sort eagerly: json_obj_finalize(arena, root).
 */
JsonError json_obj_finalize(JsonArena* arena, JsonValue* obj)
{
    if (obj == NULL || arena == NULL)    { return JSON_ERR_NULL_PARAM; }
    if (obj->type != JSON_OBJECT)        { return JSON_ERR_TYPE_MISMATCH; }
    return json__obj_sort(obj, arena);
}

/* ── §11.15  Error strings ──────────────────────────────────────────────── */

const char* json_error_str(JsonError err)
{
    switch (err) {
    case JSON_OK:                   return "OK";
    case JSON_ERR_NULL_PARAM:       return "NULL parameter";
    case JSON_ERR_OOM:              return "Out of memory";
    case JSON_ERR_INVALID_JSON:     return "Invalid JSON";
    case JSON_ERR_UNEXPECTED_EOF:   return "Unexpected end of input";
    case JSON_ERR_DEPTH_EXCEEDED:   return "Nesting depth exceeded";
    case JSON_ERR_INVALID_STRING:   return "Invalid string / escape sequence";
    case JSON_ERR_INVALID_NUMBER:   return "Invalid number";
    case JSON_ERR_INVALID_UTF8:     return "Invalid UTF-8 sequence";
    case JSON_ERR_OVERFLOW:         return "Arithmetic or buffer overflow";
    case JSON_ERR_NOT_FOUND:        return "Key or index not found";
    case JSON_ERR_TYPE_MISMATCH:    return "Type mismatch";
    case JSON_ERR_BUFFER_TOO_SMALL: return "Output buffer too small";
    case JSON_ERR_NODE_LIMIT:       return "Node count limit exceeded";
    default:                        return "Unknown error";
    }
}

#undef JSON__CHECK_V
#undef JSON__CHECK_OUT

#endif /* JSON_IMPLEMENTATION */
#endif /* JSON_PAL_H */
