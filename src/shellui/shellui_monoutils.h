/*
 * MemDBG - ShellUI Mono runtime interface (v2 — symbol table, no base64).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * All Mono API function pointers are pre-resolved at init time into a single
 * memdbg_mono_vtable_t struct.  Host builds get no-op stubs.
 */

#ifndef MEMDBG_SHELLUI_MONOUTILS_H
#define MEMDBG_SHELLUI_MONOUTILS_H

#include "shellui_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Mono type stubs (always defined — cross-compiler needs them too) ---- */

#ifndef PLATFORM_PS5

typedef void MonoDomain;
typedef void MonoAssembly;
typedef void MonoImage;
typedef void MonoClass;
typedef void MonoObject;
typedef void MonoString;
typedef void MonoMethod;
typedef void MonoProperty;
typedef void MonoArray;

#else /* PLATFORM_PS5 — cross-compilation needs real struct layouts */

/* Minimal MonoVTable: only the 'klass' field we actually dereference.
 * On the real PS5, the Sony SDK provides the full struct definition. */
typedef struct {
  void *klass;       /* MonoClass * */
  /* ... other fields we don't use ... */
} MonoVTable;

/* Minimal MonoObject: only the 'vtable' field we actually dereference. */
typedef struct {
  MonoVTable *vtable;
  /* ... other fields we don't use ... */
} MonoObject;

/* Other Mono types remain as void pointers (never dereferenced). */
typedef void MonoDomain;
typedef void MonoAssembly;
typedef void MonoImage;
typedef void MonoClass;
typedef void MonoString;
typedef void MonoMethod;
typedef void MonoProperty;
typedef void MonoArray;

#endif /* PLATFORM_PS5 */

/* ---- Mono vtable: all API function pointers in one struct ---- */

typedef struct {
  MonoDomain   *(*get_root_domain)(void);
  MonoClass    *(*class_from_name)(MonoImage *image,
                                   const char *ns, const char *name);
  MonoMethod   *(*class_get_method)(MonoClass *klass,
                                    const char *name, int param_count);
  MonoProperty *(*class_get_property)(MonoClass *klass, const char *name);
  MonoMethod   *(*property_get_get)(MonoProperty *prop);
  MonoMethod   *(*property_get_set)(MonoProperty *prop);
  MonoObject   *(*runtime_invoke)(MonoMethod *method, void *obj,
                                  void **args, void **exc);
  MonoObject   *(*object_new)(MonoDomain *domain, MonoClass *klass);
  MonoString   *(*string_new)(MonoDomain *domain, const char *str);
  const char   *(*string_to_utf8)(MonoString *str);
  uint64_t      (*compile_method)(MonoMethod *method);
  MonoAssembly *(*domain_assembly_open)(MonoDomain *domain,
                                        const char *name);
  MonoImage    *(*assembly_get_image)(MonoAssembly *assembly);
  MonoClass    *(*get_byte_class)(void);
  MonoArray    *(*array_new)(MonoDomain *domain, MonoClass *klass,
                             uintptr_t length);
  char         *(*array_addr)(MonoArray *array, int elem_size,
                              uintptr_t index);
  void          (*free_fn)(void *ptr);
} memdbg_mono_vtable_t;

/* The global symbol table, populated by shellui_resolve_mono(). */
extern memdbg_mono_vtable_t g_mono;

/* ---- Detour stub (always available) ---- */
typedef uint64_t (*DetourFunc)(uint64_t target, void *hook);

#ifndef PLATFORM_PS5

/* Host: no-op impl */
static inline uint64_t DetourFunction(uint64_t t, void *h) {
  (void)h; return t;
}

/* Host: no-op stub for shellui_mono_resolve (called from main.c on PS5 only). */
static inline void shellui_mono_resolve(memdbg_mono_vtable_t *m,
                                         const char **resource) {
  (void)m; (void)resource;
}

#else /* PLATFORM_PS5 */

/* PS5: DetourFunction is provided by the payload SDK / kernel */
extern uint64_t DetourFunction(uint64_t target, void *hook);

/* Resolves all Mono symbols from SceShellUI and fills g_mono.
 * Defined in shellui_main.c. */
void shellui_mono_resolve(memdbg_mono_vtable_t *m, const char **resource_name);

extern int  get_module_handle(int pid, const char *name);
extern int  kernel_dlsym(int handle, const char *name, void **func);

#endif /* PLATFORM_PS5 */

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SHELLUI_MONOUTILS_H */
