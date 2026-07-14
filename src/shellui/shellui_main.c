/*
 * MemDBG - ShellUI module entry point v2 (no base64, own resource name).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "shellui_internal.h"
#include "shellui_monoutils.h"

#ifdef PLATFORM_PS5

#include <ps5/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- Global state ---- */
MonoDomain            *g_root_domain   = NULL;
MonoImage             *g_legacy_image  = NULL;
memdbg_mono_vtable_t   g_mono          = { 0 };
memdbg_shellui_config_t g_config;
shellui_plugin_def_t   g_plugins[16];
int                    g_plugin_count  = 0;

/* The hijacked resource name (plain text) */
const char *g_resource_name = SHELLUI_RESOURCE_DEBUG_SETTINGS;

/* ---- Forward declarations from hooks.c ---- */
extern int shellui_on_press_hook(MonoObject *, MonoObject *, MonoObject *);
extern int shellui_on_pre_create_hook(MonoObject *, MonoObject *);
extern MonoString *shellui_cxml_uri_hook(MonoObject *, MonoString *);
extern uint64_t shellui_get_manifest_resource_stream_hook(uint64_t,
                                                           MonoString *);
extern int shellui_open_hook(const char *path, int flags, int mode);
extern void shellui_register_builtin_handlers(void);

/* Original function pointers (set by detours) */
uint64_t   (*g_original_get_stream)(uint64_t, MonoString *) = NULL;
MonoString *(*g_original_cxml_uri)(MonoObject *, MonoString *) = NULL;
int (*g_original_on_press)(MonoObject *, MonoObject *, MonoObject *) = NULL;
int (*g_original_on_pre_create)(MonoObject *, MonoObject *) = NULL;

/* open() syscall detour original — resolved from libkernel_sys.sprx by
 * install_open_hook(). Used in shellui_hooks.c to redirect the missing
 * Sce.Vsh.ShellUI.Settings.Core.rco on newer firmware (see memory.md).
 * open() is the kernel syscall wrapper — the lowest user-space interception
 * point; Sony-internal IO in ResourceObj bypasses libc fopen but cannot
 * bypass open() -> sceKernelOpen(). */
int (*g_original_open)(const char *, int, ...) = NULL;

/* Forward declaration: install_open_hook() is defined below install_hooks()
 * but called from inside it. */
static int install_open_hook(void);

/* ---- Resolve all Mono symbols into the vtable ---- */
void shellui_mono_resolve(memdbg_mono_vtable_t *m,
                           const char **resource_name) {
  pid_t pid = getpid();
  int handle = get_module_handle(pid, "libmonosgen-2.0.sprx");
  if (handle < 0) return;

  kernel_dlsym(handle, "mono_get_root_domain",
               (void **)&m->get_root_domain);
  kernel_dlsym(handle, "mono_class_from_name",
               (void **)&m->class_from_name);
  kernel_dlsym(handle, "mono_class_get_method_from_name",
               (void **)&m->class_get_method);
  kernel_dlsym(handle, "mono_class_get_property_from_name",
               (void **)&m->class_get_property);
  kernel_dlsym(handle, "mono_property_get_get_method",
               (void **)&m->property_get_get);
  kernel_dlsym(handle, "mono_property_get_set_method",
               (void **)&m->property_get_set);
  kernel_dlsym(handle, "mono_runtime_invoke",
               (void **)&m->runtime_invoke);
  kernel_dlsym(handle, "mono_object_new",
               (void **)&m->object_new);
  kernel_dlsym(handle, "mono_string_new",
               (void **)&m->string_new);
  kernel_dlsym(handle, "mono_string_to_utf8",
               (void **)&m->string_to_utf8);
  kernel_dlsym(handle, "mono_compile_method",
               (void **)&m->compile_method);
  kernel_dlsym(handle, "mono_domain_assembly_open",
               (void **)&m->domain_assembly_open);
  kernel_dlsym(handle, "mono_assembly_get_image",
               (void **)&m->assembly_get_image);
  kernel_dlsym(handle, "mono_get_byte_class",
               (void **)&m->get_byte_class);
  kernel_dlsym(handle, "mono_array_new",
               (void **)&m->array_new);
  kernel_dlsym(handle, "mono_array_addr_with_size",
               (void **)&m->array_addr);
  kernel_dlsym(handle, "mono_free",
               (void **)&m->free_fn);

  *resource_name = SHELLUI_RESOURCE_DEBUG_SETTINGS;
}

/* ---- Utility: touch a file ---- */
static void touch_file(const char *path) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
  if (fd >= 0) close(fd);
}

/* ---- Install hooks on the ShellUI Mono runtime ---- */
static int install_hooks(void) {
  MonoAssembly *leg_asm =
      g_mono.domain_assembly_open(g_root_domain, MONO_LEGACY_DLL);
  if (!leg_asm) return -1;
  g_legacy_image = g_mono.assembly_get_image(leg_asm);

  /* Detour: GetManifestResourceStream */
  {
    MonoAssembly *mslib =
        g_mono.domain_assembly_open(g_root_domain, MONO_MSLIB_DLL);
    MonoImage *ms_img = g_mono.assembly_get_image(mslib);
    MonoClass *ms_class = g_mono.class_from_name(
        ms_img, MONO_NS_REFLECTION, MONO_CLASS_RUNTIME);
    uint64_t addr = g_mono.compile_method(
        g_mono.class_get_method(ms_class, MONO_METHOD_GET_STREAM, 1));
    g_original_get_stream =
        (uint64_t (*)(uint64_t, MonoString *))DetourFunction(
            addr, (void *)&shellui_get_manifest_resource_stream_hook);
  }

  /* Detour: CxmlUri */
  {
    uint64_t addr = g_mono.compile_method(
        g_mono.class_get_method(
            g_mono.class_from_name(g_legacy_image, MONO_UI3_DLL,
                                   MONO_CLASS_SETTINGS),
            MONO_METHOD_CXML, 1));
    g_original_cxml_uri =
        (MonoString * (*)(MonoObject *, MonoString *))DetourFunction(
            addr, (void *)&shellui_cxml_uri_hook);
  }

  /* Detour: OnPress */
  {
    uint64_t addr = g_mono.compile_method(
        g_mono.class_get_method(
            g_mono.class_from_name(g_legacy_image, MONO_UI3_DLL,
                                   MONO_CLASS_PAGE),
            MONO_METHOD_ONPRESS, 2));
    g_original_on_press =
        (int (*)(MonoObject *, MonoObject *, MonoObject *))DetourFunction(
            addr, (void *)&shellui_on_press_hook);
  }

  /* Detour: OnPreCreate */
  {
    uint64_t addr = g_mono.compile_method(
        g_mono.class_get_method(
            g_mono.class_from_name(g_legacy_image, MONO_UI3_DLL,
                                   MONO_CLASS_PAGE),
            MONO_METHOD_ONCREATE, 1));
    g_original_on_pre_create =
        (int (*)(MonoObject *, MonoObject *))DetourFunction(
            addr, (void *)&shellui_on_pre_create_hook);
  }

  /* Detour: libc fopen — redirect missing legacy PUI .rco (FW 9.4.0+).
   * Non-fatal: keep installing the other hooks even if the libc module
   * handle / fopen symbol can't be resolved. The shellui_fopen_hook reads
   * g_original_fopen and forwards every call to it; if it stays NULL the
   * hook is simply a no-op pass-through (PS5 libc guarantees a non-weak fopen
   * so this should essentially never fail in practice). */
  install_open_hook();

  return 0;
}

/* ---- Install kernel open() detour ----
 * Resolves the open() syscall wrapper from libkernel_sys.sprx and installs
 * shellui_open_hook as a DetourFunction. open() is the lowest user-space
 * interception point for file opens on PS5 — Sony-internal IO in
 * ResourceObj (Sce.PlayStation.Core.dll) bypasses libc fopen but cannot
 * bypass open() -> sceKernelOpen(). When the missing RCO is requested, the
 * hook redirects to /dev/null (or a user-provided copy in the asset dir),
 * preventing the FileNotFoundException that kills SceShellUI. */
static int install_open_hook(void) {
  pid_t pid = getpid();
  int handle = get_module_handle(pid, SHELLUI_KERNEL_MODULE);
  if (handle < 0) return -1;

  void *open_addr = NULL;
  if (kernel_dlsym(handle, "open", &open_addr) != 0 || !open_addr)
    return -1;

  g_original_open =
      (int (*)(const char *, int, ...))DetourFunction(
          (uint64_t)open_addr, (void *)&shellui_open_hook);
  return 0;
}

/* ---- Entry point ---- */
int shellui_main(void) {
  const char *res_name = NULL;
  shellui_mono_resolve(&g_mono, &res_name);

  g_root_domain = g_mono.get_root_domain();
  if (!g_root_domain) return -1;

  shellui_config_load(&g_config, SHELLUI_CONFIG_FILE);
  shellui_register_builtin_handlers();
  g_plugin_count = shellui_plugin_discover(g_plugins, 16);

  if (install_hooks() != 0) return -2;

  mkdir(SHELLUI_CONFIG_DIR, 0777);
  mkdir(SHELLUI_ASSET_DIR, 0777);
  touch_file("/system_tmp/memdbg_shellui_online");

  while (1) { sleep(3600); }
  return 0;
}

#endif /* PLATFORM_PS5 */
