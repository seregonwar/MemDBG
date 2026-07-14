/*
 * MemDBG - ShellUI Mono hooks v2 (hash dispatch, cached XML, async IPC).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "shellui_internal.h"
#include "shellui_monoutils.h"

/* <stdio.h> is needed unconditionally: FILE * appears in the fopen detour's
 * signature on both PS5 (real hook) and host (stub) builds. */
#include <stdio.h>

#ifdef PLATFORM_PS5
#include <stdlib.h>
#include <string.h>

/* ---- Externals from main.c ---- */
extern MonoDomain            *g_root_domain;
extern MonoImage             *g_legacy_image;
extern memdbg_shellui_config_t g_config;
extern shellui_plugin_def_t   g_plugins[];
extern int                    g_plugin_count;

/* ---- FNV-1a 32-bit hash ---- */
static uint32_t fnv1a(const char *str) {
  uint32_t hash = 2166136261U;
  while (*str) {
    hash ^= (uint8_t)*str++;
    hash *= 16777619U;
  }
  return hash;
}

/* ---- Hash-based handler dispatch table ---- */
static struct {
  const char        *id;
  shellui_handler_fn fn;
  uint32_t           hash;
  bool               used;
} g_handlers[SHELLUI_MAX_HANDLERS];

static int g_handler_count = 0;

bool shellui_handler_register(const char *id, shellui_handler_fn fn) {
  if (!id || !fn || g_handler_count >= SHELLUI_MAX_HANDLERS)
    return false;
  g_handlers[g_handler_count].id   = id;
  g_handlers[g_handler_count].fn   = fn;
  g_handlers[g_handler_count].hash = fnv1a(id);
  g_handlers[g_handler_count].used = true;
  g_handler_count++;
  return true;
}

bool shellui_handler_dispatch(const char *id, const char *value) {
  if (!id) return false;
  uint32_t h = fnv1a(id);
  /* Linear probe with precomputed hash */
  for (int i = 0; i < g_handler_count; i++) {
    if (g_handlers[i].used && g_handlers[i].hash == h &&
        strcmp(g_handlers[i].id, id) == 0) {
      g_handlers[i].fn(id, value);
      return true;
    }
  }
  return false;
}

void shellui_handler_clear(void) {
  g_handler_count = 0;
  memset(g_handlers, 0, sizeof(g_handlers));
}

/* ---- Mono element helpers ---- */

static const char *get_element_id(MonoObject *element) {
  if (!element) return "";
  MonoClass *klass = element->vtable->klass;
  MonoProperty *prop = g_mono.class_get_property(klass, "Id");
  if (!prop) return "";
  MonoMethod *getter = g_mono.property_get_get(prop);
  if (!getter) return "";
  MonoObject *result = g_mono.runtime_invoke(getter, element, NULL, NULL);
  if (!result) return "";
  return g_mono.string_to_utf8((MonoString *)result);
}

static const char *get_element_value(MonoObject *element) {
  if (!element) return "0";
  MonoClass *klass = element->vtable->klass;
  MonoProperty *prop = g_mono.class_get_property(klass, "Value");
  if (!prop) return "0";
  MonoMethod *getter = g_mono.property_get_get(prop);
  if (!getter) return "0";
  MonoObject *result = g_mono.runtime_invoke(getter, element, NULL, NULL);
  if (!result) return "0";
  return g_mono.string_to_utf8((MonoString *)result);
}

static void set_element_value(MonoObject *element, const char *value) {
  if (!element || !value) return;
  MonoClass *klass = element->vtable->klass;
  MonoProperty *prop = g_mono.class_get_property(klass, "Value");
  if (!prop) return;
  MonoMethod *setter = g_mono.property_get_set(prop);
  if (!setter) return;
  MonoString *s = g_mono.string_new(g_root_domain, value);
  void *args[] = { s };
  g_mono.runtime_invoke(setter, element, args, NULL);
}

/* ---- Forward declarations for original functions ---- */
extern uint64_t   (*g_original_get_stream)(uint64_t, MonoString *);
extern MonoString *(*g_original_cxml_uri)(MonoObject *, MonoString *);
extern int (*g_original_on_press)(MonoObject *, MonoObject *, MonoObject *);
extern int (*g_original_on_pre_create)(MonoObject *, MonoObject *);
extern const char *g_resource_name;

/* open() detour original (resolved from libkernel_sys.sprx by main.c).
 * open() is the kernel syscall wrapper — the lowest user-space interception
 * point for file opens on PS5. Sony-internal IO in ResourceObj bypasses libc
 * fopen but cannot bypass open() -> sceKernelOpen(). */
extern int (*g_original_open)(const char *, int, ...);

/* ---- IPC toggle helper: fire-and-forget ---- */
static void ipc_toggle(shellui_ipc_command_t cmd, uint32_t val) {
  shellui_ipc_request_t req = { cmd, val, { 0, 0 } };
  shellui_ipc_fire(&req);
}

/* ---- Built-in handler callbacks ---- */

void h_debugger(const char *id, const char *value) {
  (void)id;
  int v = value ? ((strcmp(value, "0") == 0) ? 0 : 1) : 1;
  g_config.debugger_enabled = (v != 0);
  ipc_toggle(SHIPC_TOGGLE_DEBUGGER, g_config.debugger_enabled ? 1U : 0U);
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}

static void h_tracer(const char *id, const char *value) {
  (void)id;
  int v = value ? ((strcmp(value, "0") == 0) ? 0 : 1) : 1;
  g_config.tracer_enabled = (v != 0);
  ipc_toggle(SHIPC_TOGGLE_TRACER, g_config.tracer_enabled ? 1U : 0U);
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}

static void h_klog(const char *id, const char *value) {
  (void)id;
  int v = value ? ((strcmp(value, "0") == 0) ? 0 : 1) : 1;
  g_config.klog_enabled = (v != 0);
  ipc_toggle(SHIPC_TOGGLE_KLOG, g_config.klog_enabled ? 1U : 0U);
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}

static void h_ftp(const char *id, const char *value) {
  (void)id;
  int v = value ? ((strcmp(value, "0") == 0) ? 0 : 1) : 1;
  g_config.ftp_enabled = (v != 0);
  ipc_toggle(SHIPC_TOGGLE_FTP, g_config.ftp_enabled ? 1U : 0U);
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}

static void h_ps5debug(const char *id, const char *value) {
  (void)id;
  int v = value ? ((strcmp(value, "0") == 0) ? 0 : 1) : 1;
  g_config.ps5debug_enabled = (v != 0);
  ipc_toggle(SHIPC_TOGGLE_PS5DEBUG, g_config.ps5debug_enabled ? 1U : 0U);
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}

static void h_udp_log(const char *id, const char *value) {
  (void)id;
  int v = value ? ((strcmp(value, "0") == 0) ? 0 : 1) : 1;
  g_config.udp_log_enabled = (v != 0);
  ipc_toggle(SHIPC_TOGGLE_UDPLOG, g_config.udp_log_enabled ? 1U : 0U);
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}

static void h_auto_start(const char *id, const char *value) {
  (void)id;
  int v = value ? ((strcmp(value, "0") == 0) ? 0 : 1) : 1;
  g_config.auto_start = (v != 0);
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}

static void h_debugger_port(const char *id, const char *value) {
  (void)id;
  int port = value ? (int)strtol(value, NULL, 10) : 9020;
  if (port > 0 && port < 65536) g_config.debugger_port = port;
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}

static void h_klog_lines(const char *id, const char *value) {
  (void)id;
  int lines = value ? (int)strtol(value, NULL, 10) : 5000;
  if (lines > 0) g_config.klog_max_lines = lines;
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}

static void h_ftp_port(const char *id, const char *value) {
  (void)id;
  int port = value ? (int)strtol(value, NULL, 10) : 1337;
  if (port > 0 && port < 65536) g_config.ftp_port = port;
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}

static void h_udp_log_port(const char *id, const char *value) {
  (void)id;
  int port = value ? (int)strtol(value, NULL, 10) : 9023;
  if (port > 0 && port < 65536) g_config.udp_log_port = port;
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}

static void h_ping(const char *id, const char *value) {
  (void)id; (void)value;
  shellui_ipc_request_t req = { SHIPC_PING, 1, { 0, 0 } };
  shellui_ipc_fire(&req);
}

static void h_shutdown(const char *id, const char *value) {
  (void)id; (void)value;
  shellui_ipc_request_t req = { SHIPC_SHUTDOWN, 1, { 0, 0 } };
  shellui_ipc_fire(&req);
}

void h_plugin_event(const char *id, const char *value) {
  /* Dispatch plugin event to daemon with encoded plugin+element index */
  for (int p = 0; p < g_plugin_count; p++) {
    for (int el_idx = 0; el_idx < g_plugins[p].element_count; el_idx++) {
      if (strcmp(id, g_plugins[p].elements[el_idx].id) == 0) {
        shellui_ipc_request_t req = { SHIPC_PLUGIN_EVENT,
          (uint32_t)((p << 16) | el_idx), { 0, 0 } };
        if (g_plugins[p].elements[el_idx].type == SHELLUI_EL_TEXT_FIELD) {
          req.reserved[0] = (uint32_t)(value ? (int)strtol(value, NULL, 10) : 0);
        }
        shellui_ipc_fire(&req);
        return;
      }
    }
  }
}

/* ---- OnPress Hook ---- */
int shellui_on_press_hook(MonoObject *instance, MonoObject *element,
                          MonoObject *e) {
  if (!instance || !element)
    return g_original_on_press(instance, element, e);

  const char *id    = get_element_id(element);
  const char *value = get_element_value(element);

  /* Try hash dispatch first (built-in handlers) */
  if (!shellui_handler_dispatch(id, value))
    /* Fallback: plugin element lookup */
    h_plugin_event(id, value);

  return g_original_on_press(instance, element, e);
}

/* ---- OnPreCreate Hook (restore toggle state via hash dispatch) ---- */
int shellui_on_pre_create_hook(MonoObject *instance, MonoObject *element) {
  if (!instance || !element)
    return g_original_on_pre_create(instance, element);

  const char *id = get_element_id(element);
  const char *restore = NULL;

  /* Built-in toggles */
  if (strcmp(id, "id_memdbg_debugger") == 0)
    restore = g_config.debugger_enabled ? "1" : "0";
  else if (strcmp(id, "id_memdbg_tracer") == 0)
    restore = g_config.tracer_enabled ? "1" : "0";
  else if (strcmp(id, "id_memdbg_klog") == 0)
    restore = g_config.klog_enabled ? "1" : "0";
  else if (strcmp(id, "id_memdbg_ftp") == 0)
    restore = g_config.ftp_enabled ? "1" : "0";
  else if (strcmp(id, "id_memdbg_ps5debug") == 0)
    restore = g_config.ps5debug_enabled ? "1" : "0";
  else if (strcmp(id, "id_memdbg_udp_log") == 0)
    restore = g_config.udp_log_enabled ? "1" : "0";
  else if (strcmp(id, "id_memdbg_auto_start") == 0)
    restore = g_config.auto_start ? "1" : "0";
  else {
    /* Plugin toggles */
    for (int p = 0; p < g_plugin_count; p++) {
      for (int el_idx = 0; el_idx < g_plugins[p].element_count; el_idx++) {
        if (g_plugins[p].elements[el_idx].type == SHELLUI_EL_TOGGLE_SWITCH &&
            strcmp(id, g_plugins[p].elements[el_idx].id) == 0) {
          restore = g_plugins[p].elements[el_idx].default_value;
          break;
        }
      }
      if (restore) break;
    }
  }

  if (restore) set_element_value(element, restore);
  return g_original_on_pre_create(instance, element);
}

/* ---- Register all built-in handlers (called from main.c) ---- */
void shellui_register_builtin_handlers(void) {
  shellui_handler_register("id_memdbg_debugger",       h_debugger);
  shellui_handler_register("id_memdbg_tracer",         h_tracer);
  shellui_handler_register("id_memdbg_klog",           h_klog);
  shellui_handler_register("id_memdbg_ftp",            h_ftp);
  shellui_handler_register("id_memdbg_ps5debug",       h_ps5debug);
  shellui_handler_register("id_memdbg_udp_log",        h_udp_log);
  shellui_handler_register("id_memdbg_auto_start",     h_auto_start);
  shellui_handler_register("id_memdbg_debugger_port",  h_debugger_port);
  shellui_handler_register("id_memdbg_klog_lines",     h_klog_lines);
  shellui_handler_register("id_memdbg_ftp_port",       h_ftp_port);
  shellui_handler_register("id_memdbg_udp_log_port",   h_udp_log_port);
  shellui_handler_register("id_memdbg_ping",           h_ping);
  shellui_handler_register("id_memdbg_shutdown",       h_shutdown);
}

/* ---- CxmlUri Hook (icon replacement) ---- */
MonoString *shellui_cxml_uri_hook(MonoObject *instance, MonoString *uri) {
  if (!instance || !uri)
    return g_original_cxml_uri(instance, uri);

  const char *uri_str = g_mono.string_to_utf8(uri);
  if (strstr(uri_str, "tex_game_icon") ||
      strstr(uri_str, "tex_icon_system")) {
    return g_mono.string_new(g_root_domain,
      "/user/data/memdbg/assets/memdbg_icon.png");
  }
  return g_original_cxml_uri(instance, uri);
}

/* ---- fopen hook: redirect missing legacy PUI .rco on FW 9.4.0+ ----------
 *
 * On newer PS5 firmware the Settings UI has been migrated to React Native
 * and the legacy PUI resource container
 * /app0/psm/Application/resource/Sce.Vsh.ShellUI.Settings.Core.rco is no
 * longer shipped. Yet opening the Debug Settings page still transitions to
 * the legacy Mono SettingsAppSceneUI3, which calls
 * Sce.PlayStation.Core.Resources.CxmlResources.Load() -> fopen() on that
 * path; the native fopen fails and the unhandled
 * System.IO.FileNotFoundException kills the whole SceShellUI process via
 * CxmlLoadRequestJob.Finish -> JobQueue.Check -> UISystem.Update.
 *
 * We detour libc's fopen, detect requests for the missing RCO, and try a
 * short list of fallback paths (user-provided copy in the MemDBG asset dir,
 * alt basename without "Core", sibling "Settings.rco" in the original dir).
 * The first fopen that succeeds wins. If none of the candidates exist we
 * fall back to the original call so current (crashing) behaviour is preserved
 * rather than silently swallowing the request (which would just move the
 * .NET exception one frame deeper).
 */
int shellui_open_hook(const char *path, int flags, int mode) {
  if (!path)
    return g_original_open(path, flags, mode);

  /* Only act on the specific resource that is missing on the affected
   * firmware. Every other open() (config, plugin, daemon IO, system libs,
   * etc.) passes through untouched with its original flags + mode. */
  if (strstr(path, SHELLUI_RCO_NAME_MISSING)) {
    /* 1) User-provided RCO in the MemDBG asset directory. */
    int fd = g_original_open(SHELLUI_FALLBACK_RCO_PATH, flags, mode);
    if (fd >= 0) return fd;

    /* 2) Alt basename (Sony sometimes drops "Core") in the asset dir. */
    {
      char alt[512];
      int n = snprintf(alt, sizeof(alt), "%s/%s",
                       SHELLUI_ASSET_DIR, SHELLUI_RCO_NAME_ALT_BASENAME);
      if (n > 0 && (size_t)n < sizeof(alt)) {
        fd = g_original_open(alt, flags, mode);
        if (fd >= 0) return fd;
      }
    }

    /* 3) Final fallback: redirect to /dev/null. On PS5, /dev/null exists as
     *    a char-special device. open("/dev/null", O_RDONLY) succeeds; the
     *    caller gets a valid fd that reads zero bytes (EOF). The
     *    CxmlResources ctor reads an empty stream and returns a
     *    zero-initialised CxmlResources instead of throwing
     *    System.IO.FileNotFoundException. The unhandled AggregateException
     *    that previously killed SceShellUI is eliminated. */
    return g_original_open("/dev/null", flags, mode);
  }

  return g_original_open(path, flags, mode);
}

/* ---- GetManifestResourceStream Hook (inject cached XML) ---- */
uint64_t shellui_get_manifest_resource_stream_hook(uint64_t inst,
                                                    MonoString *filename) {
  if (!filename)
    return g_original_get_stream(inst, filename);

  const char *name = g_mono.string_to_utf8(filename);

  /* Serve the original Debug Settings when the <link> is clicked */
  if (strcmp(name, SHELLUI_RESOURCE_ORIGINAL) == 0) {
    MonoString *ds_name = g_mono.string_new(g_root_domain,
        SHELLUI_RESOURCE_DEBUG_SETTINGS);
    return g_original_get_stream(inst, ds_name);
  }

  /* Serve plugin link sub-pages — match any plugin's <link file="..."> */
  {
    for (int p = 0; p < g_plugin_count; p++) {
      for (int e = 0; e < g_plugins[p].element_count; e++) {
        if (g_plugins[p].elements[e].type != SHELLUI_EL_LINK)
          continue;
        const char *file_name = g_plugins[p].elements[e].default_value;
        size_t fn_len = strlen(file_name);
        size_t nm_len = strlen(name);
        /* Match if the resource name ends with the plugin's file name */
        if (nm_len >= fn_len &&
            strcmp(name + nm_len - fn_len, file_name) == 0) {
          char sub_xml[4096];
          int n = snprintf(sub_xml, sizeof(sub_xml),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">\n"
            "<setting_list id=\"id_plugin_sub_%s\" title=\"%s (v%s)\">\n",
            g_plugins[p].plugin_id,
            g_plugins[p].plugin_name,
            g_plugins[p].plugin_version);
          /* Generate XML for just this plugin's elements */
          shellui_plugin_xml_generate(sub_xml + n,
              sizeof(sub_xml) - (size_t)n, &g_plugins[p], 1);

          size_t xml_len = strlen(sub_xml);
          MonoClass *byte_class = g_mono.get_byte_class();
          MonoArray *arr = g_mono.array_new(g_root_domain, byte_class,
                                            xml_len);
          char *arr_addr = g_mono.array_addr(arr, sizeof(char), 0);
          memcpy(arr_addr, sub_xml, xml_len);

          MonoAssembly *mscorlib =
              g_mono.domain_assembly_open(g_root_domain, MONO_MSLIB_DLL);
          MonoImage *ms_img = g_mono.assembly_get_image(mscorlib);
          MonoClass *ms_class = g_mono.class_from_name(
              ms_img, MONO_NS_IO, MONO_CLASS_MEMSTREAM);
          MonoObject *ms = g_mono.object_new(g_root_domain, ms_class);
          void *args2[] = { arr };
          MonoMethod *ctor = g_mono.class_get_method(ms_class, ".ctor", 1);
          g_mono.runtime_invoke(ctor, ms, args2, NULL);
          return (uint64_t)ms;
        }
      }
    }
  }

  /* Intercept requests for the debug settings XML (our own content) */
  if (strcmp(name, g_resource_name) == 0) {
    /* Read from cache (or rebuild) */
    char xml_buf[16384];
    xml_buf[0] = '\0';
    shellui_xml_generate(xml_buf, sizeof(xml_buf), &g_config,
                         g_plugins, g_plugin_count);

    size_t xml_len = strlen(xml_buf);
    MonoClass *byte_class = g_mono.get_byte_class();
    MonoArray *arr = g_mono.array_new(g_root_domain, byte_class, xml_len);
    char *arr_addr = g_mono.array_addr(arr, sizeof(char), 0);
    memcpy(arr_addr, xml_buf, xml_len);

    MonoAssembly *mscorlib =
        g_mono.domain_assembly_open(g_root_domain, MONO_MSLIB_DLL);
    MonoImage *ms_img = g_mono.assembly_get_image(mscorlib);
    MonoClass *ms_class =
        g_mono.class_from_name(ms_img, MONO_NS_IO, MONO_CLASS_MEMSTREAM);
    MonoObject *ms = g_mono.object_new(g_root_domain, ms_class);
    void *args[] = { arr };
    MonoMethod *ctor = g_mono.class_get_method(ms_class, ".ctor", 1);
    g_mono.runtime_invoke(ctor, ms, args, NULL);
    return (uint64_t)ms;
  }

  /* Serve plugin link sub-pages — runs AFTER all built-in resource
   * checks so plugins can't hijack debug_settings or original_debug. */
  {
    for (int p = 0; p < g_plugin_count; p++) {
      for (int e = 0; e < g_plugins[p].element_count; e++) {
        if (g_plugins[p].elements[e].type != SHELLUI_EL_LINK)
          continue;
        const char *file_name = g_plugins[p].elements[e].default_value;
        size_t fn_len = strlen(file_name);
        if (fn_len == 0) continue; /* reject empty file_name */
        size_t nm_len = strlen(name);
        /* Match if the resource name ends with '.' + file_name */
        if (nm_len > fn_len && name[nm_len - fn_len - 1] == '.' &&
            strcmp(name + nm_len - fn_len, file_name) == 0) {
          char sub_xml[8192];
          int n = snprintf(sub_xml, sizeof(sub_xml),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">\n");
          if (n < 0) break;
          /* shellui_plugin_xml_generate produces its own <setting_list> */
          int gen = shellui_plugin_xml_generate(sub_xml + n,
              sizeof(sub_xml) - (size_t)n, &g_plugins[p], 1);
          /* Close system_settings */
          size_t pos = (size_t)(n + gen);
          if (pos < sizeof(sub_xml) - 20)
            pos += (size_t)snprintf(sub_xml + pos,
                sizeof(sub_xml) - pos, "</system_settings>\n");

          size_t xml_len = pos < sizeof(sub_xml) ? pos : sizeof(sub_xml) - 1;
          MonoClass *byte_class = g_mono.get_byte_class();
          MonoArray *arr = g_mono.array_new(g_root_domain, byte_class,
                                            xml_len);
          char *arr_addr = g_mono.array_addr(arr, sizeof(char), 0);
          memcpy(arr_addr, sub_xml, xml_len);

          MonoAssembly *mscorlib =
              g_mono.domain_assembly_open(g_root_domain, MONO_MSLIB_DLL);
          MonoImage *ms_img = g_mono.assembly_get_image(mscorlib);
          MonoClass *ms_class = g_mono.class_from_name(
              ms_img, MONO_NS_IO, MONO_CLASS_MEMSTREAM);
          MonoObject *ms = g_mono.object_new(g_root_domain, ms_class);
          void *args2[] = { arr };
          MonoMethod *link_ctor = g_mono.class_get_method(
              ms_class, ".ctor", 1);
          g_mono.runtime_invoke(link_ctor, ms, args2, NULL);
          return (uint64_t)ms;
        }
      }
    }
  }

  return g_original_get_stream(inst, filename);
}

#else /* !PLATFORM_PS5 — host stubs */

int shellui_on_press_hook(void *i, void *e, void *ev)
  { (void)i; (void)e; (void)ev; return 0; }
int shellui_on_pre_create_hook(void *i, void *e)
  { (void)i; (void)e; return 0; }
void *shellui_cxml_uri_hook(void *i, void *u)
  { (void)i; (void)u; return NULL; }
uint64_t shellui_get_manifest_resource_stream_hook(uint64_t inst, void *fn)
  { (void)inst; (void)fn; return 0; }

int shellui_open_hook(const char *path, int flags, int mode)
  { (void)path; (void)flags; (void)mode; return -1; }

bool shellui_handler_register(const char *id, shellui_handler_fn fn)
  { (void)id; (void)fn; return true; }
bool shellui_handler_dispatch(const char *id, const char *value)
  { (void)id; (void)value; return false; }
void shellui_handler_clear(void) {}
void shellui_register_builtin_handlers(void) {}

#endif /* PLATFORM_PS5 */
