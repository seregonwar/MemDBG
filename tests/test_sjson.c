/*
 * memDBG - sJson unit tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Verifies the sJson tree-builder API (arena, objects, arrays, strings,
 * ints, serialisation helpers) and the JSON output produced by the
 * handlers_dump code path.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JSON_IMPLEMENTATION
#include "memdbg/sjson.h"

/* ======================================================================
 * Test harness
 * ====================================================================== */

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s\n", name);                                            \
    }                                                                          \
  } while (0)

#define TEST_EQ_I(name, actual, expected)                                      \
  do {                                                                         \
    int _a = (int)(actual);                                                    \
    int _e = (int)(expected);                                                  \
    if (_a == _e) {                                                            \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s  (got %d, expected %d)\n", name, _a, _e);             \
    }                                                                          \
  } while (0)

#define TEST_STREQ(name, actual, expected)                                     \
  do {                                                                         \
    const char *_a = (actual);                                                 \
    const char *_e = (expected);                                               \
    if (_a != NULL && _e != NULL && strcmp(_a, _e) == 0) {                     \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s  (got \"%s\", expected \"%s\")\n",                    \
             name, _a ? _a : "(null)", _e ? _e : "(null)");                    \
    }                                                                          \
  } while (0)

#define TEST_CONTAINS(name, haystack, needle)                                  \
  do {                                                                         \
    const char *_h = (haystack);                                               \
    const char *_n = (needle);                                                 \
    if (_h != NULL && _n != NULL && strstr(_h, _n) != NULL) {                  \
      g_passed++;                                                              \
      printf("  PASS  %s\n", name);                                            \
    } else {                                                                   \
      g_failed++;                                                              \
      printf("  FAIL  %s  (output does not contain \"%s\")\n", name, _n);      \
    }                                                                          \
  } while (0)

/* ======================================================================
 * Helpers (mirror handlers_dump.c patterns)
 * ====================================================================== */

static JsonValue *hex_u64(JsonArena *arena, uint64_t value) {
  char buf[20];
  int n = snprintf(buf, sizeof(buf), "0x%016" PRIx64, value);
  return json_make_string(arena, buf, (uint32_t)(n > 0 ? n : 0));
}

/* ======================================================================
 * Test cases
 * ====================================================================== */

/* ---- 1. Arena create / destroy ---- */

static void test_arena_lifecycle(void) {
  printf("\n--- Arena Lifecycle ---\n");

  JsonArena *arena = json_arena_create(NULL, 65536);
  TEST("arena created", arena != NULL);

  json_arena_destroy(arena);
  TEST("arena destroyed (no crash)", true);

  /* Custom block size */
  arena = json_arena_create(NULL, 65536);
  TEST("arena with 64 KiB block", arena != NULL);
  json_arena_destroy(arena);

  /* NULL is safe */
  json_arena_destroy(NULL);
  TEST("destroy NULL is safe", true);
}

/* ---- 2. Primitive value creation ---- */

static void test_primitives(void) {
  printf("\n--- Primitives ---\n");

  JsonArena *arena = json_arena_create(NULL, 65536);
  TEST("arena created", arena != NULL);

  /* json_make_int */
  JsonValue *v_int = json_make_int(arena, 42);
  TEST("json_make_int(42) != NULL", v_int != NULL);
  TEST_EQ_I("json_make_int type", v_int->type, JSON_INTEGER);

  JsonValue *v_neg = json_make_int(arena, -12345);
  TEST("json_make_int(-12345) != NULL", v_neg != NULL);

  /* json_make_string */
  JsonValue *v_str = json_make_string(arena, "hello", 5);
  TEST("json_make_string != NULL", v_str != NULL);
  TEST_EQ_I("json_make_string type", v_str->type, JSON_STRING);

  /* json_make_stringz */
  JsonValue *v_strz = json_make_stringz(arena, "world");
  TEST("json_make_stringz != NULL", v_strz != NULL);

  /* Empty string */
  JsonValue *v_empty = json_make_stringz(arena, "");
  TEST("empty string != NULL", v_empty != NULL);

  /* json_make_null */
  JsonValue *v_null = json_make_null(arena);
  TEST("json_make_null != NULL", v_null != NULL);
  TEST_EQ_I("json_make_null type", v_null->type, JSON_NULL);

  /* json_make_bool */
  JsonValue *v_true = json_make_bool(arena, true);
  JsonValue *v_false = json_make_bool(arena, false);
  TEST("json_make_bool(true) != NULL", v_true != NULL);
  TEST("json_make_bool(false) != NULL", v_false != NULL);
  TEST_EQ_I("json_make_bool type", v_true->type, JSON_BOOL);
  TEST_EQ_I("json_make_bool type", v_false->type, JSON_BOOL);

  json_arena_destroy(arena);
}

/* ---- 3. hex_u64 helper (from handlers_dump.c) ---- */

static void test_hex_u64(void) {
  printf("\n--- hex_u64 Helper ---\n");

  JsonArena *arena = json_arena_create(NULL, 65536);

  /* Serialise to verify correct hex formatting */
  {
    JsonValue *v = hex_u64(arena, 0xDEADBEEFULL);
    TEST("hex_u64 != NULL", v != NULL);

    JsonValue *obj = json_make_object(arena);
    (void)json_obj_setz(obj, arena, "addr", v);

    size_t len = 0;
    JsonError err = json_measure(obj, &len, NULL);
    TEST_EQ_I("hex measure OK", err, JSON_OK);

    char *buf = (char *)malloc(len + 1);
    err = json_write(obj, buf, len + 1, NULL, NULL);
    TEST_EQ_I("hex write OK", err, JSON_OK);
    buf[len] = '\0';

    TEST_CONTAINS("hex contains 0x00000000deadbeef", buf,
                  "0x00000000deadbeef");
    free(buf);
  }

  /* Zero value */
  {
    JsonValue *v = hex_u64(arena, 0);
    JsonValue *obj = json_make_object(arena);
    (void)json_obj_setz(obj, arena, "zero", v);
    size_t len = 0;
    (void)json_measure(obj, &len, NULL);
    char *buf = (char *)malloc(len + 1);
    (void)json_write(obj, buf, len + 1, NULL, NULL);
    buf[len] = '\0';
    TEST_CONTAINS("hex zero output", buf, "0x0000000000000000");
    free(buf);
  }

  json_arena_destroy(arena);
}

/* ---- 4. Object building ---- */

static void test_object_building(void) {
  printf("\n--- Object Building ---\n");

  JsonArena *arena = json_arena_create(NULL, 65536);

  JsonValue *obj = json_make_object(arena);
  TEST("object created", obj != NULL);

  JsonError err;
  err = json_obj_setz(obj, arena, "pid", json_make_int(arena, 100));
  TEST_EQ_I("set pid OK", err, JSON_OK);

  err = json_obj_setz(obj, arena, "name",
                      json_make_stringz(arena, "SceShellCore"));
  TEST_EQ_I("set name OK", err, JSON_OK);

  err = json_obj_setz(obj, arena, "active", json_make_bool(arena, true));
  TEST_EQ_I("set active OK", err, JSON_OK);

  err = json_obj_setz(obj, arena, "entry", hex_u64(arena, 0x7FFF1000ULL));
  TEST_EQ_I("set entry hex OK", err, JSON_OK);

  /* Duplicate key -- should overwrite */
  err = json_obj_setz(obj, arena, "pid", json_make_int(arena, 200));
  TEST_EQ_I("overwrite pid OK", err, JSON_OK);

  /* Serialise and verify */
  size_t len = 0;
  err = json_measure(obj, &len, NULL);
  TEST_EQ_I("measure OK", err, JSON_OK);
  TEST("measure length > 0", len > 0);

  char *buf = (char *)malloc(len + 1);
  err = json_write(obj, buf, len + 1, NULL, NULL);
  TEST_EQ_I("write OK", err, JSON_OK);
  buf[len] = '\0';

  TEST_CONTAINS("output has pid 200", buf, "200");
  TEST_CONTAINS("output has SceShellCore", buf, "SceShellCore");
  TEST_CONTAINS("output has true", buf, "true");
  TEST_CONTAINS("output has hex entry", buf, "0x000000007fff1000");
  TEST_CONTAINS("valid JSON braces", buf, "{");

  free(buf);
  json_arena_destroy(arena);
}

/* ---- 5. Array building ---- */

static void test_array_building(void) {
  printf("\n--- Array Building ---\n");

  JsonArena *arena = json_arena_create(NULL, 65536);

  JsonValue *arr = json_make_array(arena);
  TEST("array created", arr != NULL);

  JsonError err;

  for (int i = 0; i < 5; i++) {
    err = json_arr_push(arr, arena, json_make_int(arena, (int64_t)(i * 10)));
    TEST_EQ_I("push int to array", err, JSON_OK);
  }

  err = json_arr_push(arr, arena, json_make_stringz(arena, "end"));
  TEST_EQ_I("push string to array", err, JSON_OK);

  size_t len = 0;
  err = json_measure(arr, &len, NULL);
  TEST_EQ_I("measure array OK", err, JSON_OK);

  char *buf = (char *)malloc(len + 1);
  err = json_write(arr, buf, len + 1, NULL, NULL);
  TEST_EQ_I("write array OK", err, JSON_OK);
  buf[len] = '\0';

  TEST_CONTAINS("array has [", buf, "[");
  TEST_CONTAINS("array has 0", buf, "0");
  TEST_CONTAINS("array has 20", buf, "20");
  TEST_CONTAINS("array has 40", buf, "40");
  TEST_CONTAINS("array has end", buf, "end");

  free(buf);
  json_arena_destroy(arena);
}

/* ---- 6. Nested structure (handlers_dump simulation) ---- */

static void test_nested_dump_structure(void) {
  printf("\n--- Nested Dump Structure ---\n");

  JsonArena *arena = json_arena_create(NULL, 65536);
  TEST("arena created", arena != NULL);

  JsonValue *root = json_make_object(arena);

  (void)json_obj_setz(root, arena, "pid", json_make_int(arena, 100));
  (void)json_obj_setz(root, arena, "name",
                      json_make_stringz(arena, "eboot.bin"));
  (void)json_obj_setz(root, arena, "title_id",
                      json_make_stringz(arena, "CUSA12345"));
  (void)json_obj_setz(root, arena, "content_id",
                      json_make_stringz(arena, "UP0001-CUSA12345_00"));

  /* Threads array */
  {
    JsonValue *threads = json_make_array(arena);
    for (int ti = 0; ti < 2; ti++) {
      JsonValue *tobj = json_make_object(arena);
      (void)json_obj_setz(tobj, arena, "lwp",
                          json_make_int(arena, (int64_t)(1001 + ti)));
      (void)json_obj_setz(tobj, arena, "state",
                          json_make_int(arena, ti == 0 ? 0 : 1));

      char tname[24];
      (void)snprintf(tname, sizeof(tname), "thread-%d", ti);
      (void)json_obj_setz(tobj, arena, "name",
                          json_make_stringz(arena, tname));

      JsonValue *regs = json_make_object(arena);
      (void)json_obj_setz(regs, arena, "rip",
          hex_u64(arena, 0x7FFF1000ULL + (uint64_t)ti * 0x1000ULL));
      (void)json_obj_setz(regs, arena, "rsp",
          hex_u64(arena, 0x7FFEE000ULL));
      (void)json_obj_setz(regs, arena, "rax",
          hex_u64(arena, (uint64_t)(42 + ti)));
      (void)json_obj_setz(tobj, arena, "regs", regs);

      (void)json_arr_push(threads, arena, tobj);
    }
    (void)json_obj_setz(root, arena, "threads", threads);
  }

  /* Maps array */
  {
    JsonValue *maps = json_make_array(arena);
    for (int mi = 0; mi < 3; mi++) {
      JsonValue *mobj = json_make_object(arena);
      uint64_t start = 0x10000ULL + (uint64_t)mi * 0x10000ULL;
      (void)json_obj_setz(mobj, arena, "start", hex_u64(arena, start));
      (void)json_obj_setz(mobj, arena, "end",
                          hex_u64(arena, start + 0x8000));
      (void)json_obj_setz(mobj, arena, "size",
                          json_make_int(arena, 0x8000));
      (void)json_obj_setz(mobj, arena, "prot",
                          json_make_int(arena, mi == 0 ? 5 : 3));

      char mname[32];
      (void)snprintf(mname, sizeof(mname), "map-%d", mi);
      (void)json_obj_setz(mobj, arena, "name",
                          json_make_stringz(arena, mname));

      (void)json_arr_push(maps, arena, mobj);
    }
    (void)json_obj_setz(root, arena, "maps", maps);
  }

  size_t len = 0;
  JsonError err = json_measure(root, &len, NULL);
  TEST_EQ_I("measure nested OK", err, JSON_OK);
  TEST("nested length > 500", len > 500);

  char *buf = (char *)malloc(len + 1);
  err = json_write(root, buf, len + 1, NULL, NULL);
  TEST_EQ_I("write nested OK", err, JSON_OK);
  buf[len] = '\0';

  TEST_CONTAINS("nested has pid", buf, "\"pid\"");
  TEST_CONTAINS("nested has eboot", buf, "eboot.bin");
  TEST_CONTAINS("nested has title_id", buf, "CUSA12345");
  TEST_CONTAINS("nested has threads", buf, "\"threads\"");
  TEST_CONTAINS("nested has maps", buf, "\"maps\"");
  TEST_CONTAINS("nested has lwp 1001", buf, "1001");
  TEST_CONTAINS("nested has regs rip hex", buf, "0x000000007fff1000");
  TEST_CONTAINS("nested has map prot 5", buf, "5");
  TEST_CONTAINS("nested has map prot 3", buf, "3");

  TEST("starts with {", buf[0] == '{');
  TEST("ends with }", len > 0 && (buf[len - 1] == '}' ||
                                  buf[len - 1] == '\n'));

  free(buf);
  json_arena_destroy(arena);
}

/* ---- 7. json_measure error path ---- */

static void test_measure_errors(void) {
  printf("\n--- Measure Errors ---\n");

  size_t len = 0;
  JsonError err = json_measure(NULL, &len, NULL);
  TEST_EQ_I("measure NULL returns error", err, JSON_ERR_NULL_PARAM);

  JsonArena *arena = json_arena_create(NULL, 65536);
  JsonValue *obj = json_make_object(arena);
  (void)json_obj_setz(obj, arena, "x", json_make_int(arena, 1));
  size_t dummy_len = 0;
  err = json_measure(obj, &dummy_len, NULL);
  TEST_EQ_I("measure with valid len_out succeeds", err, JSON_OK);
  TEST("dummy_len > 0", dummy_len > 0);

  json_arena_destroy(arena);
}

/* ---- 8. json_write error path ---- */

static void test_write_errors(void) {
  printf("\n--- Write Errors ---\n");

  JsonArena *arena = json_arena_create(NULL, 65536);
  JsonValue *obj = json_make_object(arena);
  (void)json_obj_setz(obj, arena, "key",
                      json_make_stringz(arena, "value"));

  JsonError err = json_write(NULL, NULL, 0, NULL, NULL);
  TEST_EQ_I("write NULL returns error", err, JSON_ERR_NULL_PARAM);

  /* Buffer too small -- use a safe stack buffer but pass small capacity */
  size_t needed = 0;
  (void)json_measure(obj, &needed, NULL);
  char tiny[64];
  memset(tiny, 0, sizeof(tiny));
  size_t written = 999;
  err = json_write(obj, tiny, 4, &written, NULL);
  TEST("write to 4-byte limit fails or truncates",
       err != JSON_OK || written < needed);

  json_arena_destroy(arena);
}

/* ---- 9. Empty structures ---- */

static void test_empty_structures(void) {
  printf("\n--- Empty Structures ---\n");

  JsonArena *arena = json_arena_create(NULL, 65536);

  /* Empty object */
  {
    JsonValue *obj = json_make_object(arena);
    size_t len = 0;
    JsonError err = json_measure(obj, &len, NULL);
    TEST_EQ_I("empty obj measure OK", err, JSON_OK);

    char *buf = (char *)malloc(len + 1);
    err = json_write(obj, buf, len + 1, NULL, NULL);
    TEST_EQ_I("empty obj write OK", err, JSON_OK);
    buf[len] = '\0';
    TEST_STREQ("empty obj is {}", buf, "{}");
    free(buf);
  }

  /* Empty array */
  {
    JsonValue *arr = json_make_array(arena);
    size_t len = 0;
    JsonError err = json_measure(arr, &len, NULL);
    TEST_EQ_I("empty arr measure OK", err, JSON_OK);

    char *buf = (char *)malloc(len + 1);
    err = json_write(arr, buf, len + 1, NULL, NULL);
    TEST_EQ_I("empty arr write OK", err, JSON_OK);
    buf[len] = '\0';
    TEST_STREQ("empty arr is []", buf, "[]");
    free(buf);
  }

  json_arena_destroy(arena);
}

/* ======================================================================
 * Main
 * ====================================================================== */

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("=== sJson Unit Tests ===\n");
  printf("Testing: arena lifecycle, primitives, hex_u64, object/array\n");
  printf("         building, nested structures, error paths\n\n");

  test_arena_lifecycle();
  test_primitives();
  test_hex_u64();
  test_object_building();
  test_array_building();
  test_nested_dump_structure();
  test_measure_errors();
  test_write_errors();
  test_empty_structures();

  printf("\n=== Results ======================================\n");
  int total = g_passed + g_failed;
  printf("Total:  %d\n", total);
  printf("Passed: %d\n", g_passed);
  printf("Failed: %d\n", g_failed);
  printf("================================================\n");

  return g_failed > 0 ? 1 : 0;
}
