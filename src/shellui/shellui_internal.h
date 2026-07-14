/*
 * MemDBG - ShellUI internal header v2 (PS5 settings module).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Redesigned architecture (no etaHEN patterns):
 *   - Own resource name (memdbg.xml, not hijacking DebugSettings)
 *   - Pre-resolved Mono symbol table (memdbg_mono_vtable_t)
 *   - Hash-based handler dispatch (FNV-1a, O(1))
 *   - XML cache with dirty-flag invalidation
 *   - Persistent IPC connection (async fire-and-forget)
 */

#ifndef MEMDBG_SHELLUI_INTERNAL_H
#define MEMDBG_SHELLUI_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Paths ---- */

#define SHELLUI_CONFIG_DIR   "/user/data/memdbg"
#define SHELLUI_CONFIG_FILE  "/user/data/memdbg/shellui.ini"
#define SHELLUI_ASSET_DIR    "/user/data/memdbg/assets"
#define SHELLUI_DATA_DIR     "/user/data/memdbg"
#define SHELLUI_PLUGIN_DIR   "/user/data/memdbg/plugins"
#define SHELLUI_IPC_PORT     9020

/* ---- Resource names (plain text, no base64) ----
 * We hijack debug_settings.xml to inject MemDBG as the FIRST entry.
 * A <link> element points to our captured resource for the original
 * Debug Settings content, served by calling the real GetManifestResourceStream. */
#define SHELLUI_RESOURCE_DEBUG_SETTINGS \
  "Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.DebugSettings.data.debug_settings.xml"

/* Resource name the <link> triggers — our hook serves the original content.
 * ShellUI resolves file="original_debug.xml" relative to ...Plugins/. */
#define SHELLUI_RESOURCE_ORIGINAL \
  "Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.original_debug.xml"

/* ---- Missing legacy PUI RCO redirect (.rco file not shipped on FW 9.4.0+)
 *
 * Newer PS5 firmware has migrated the Settings UI to React Native and no
 * longer ships the legacy PUI resource container
 * /app0/psm/Application/resource/Sce.Vsh.ShellUI.Settings.Core.rco.
 * When the user opens the Debug Settings page, ShellUI still falls back to
 * the legacy Mono scene SettingsAppSceneUI3, which calls
 * Sce.PlayStation.Core.Resources.CxmlResources.Load on the .rco; the native
 * fopen fails with SCE_NET_ENOENT(-ish) and the unhandled
 * System.IO.FileNotFoundException inside CxmlLoadRequestJob.Finish() kills
 * the SceShellUI process.
 *
 * MemDBG now detours the libc `fopen` to detect requests for that RCO and
 * redirect them. The first fallback path tried is a user-provided copy inside
 * SHELLUI_ASSET_DIR; if a user dumps the original RCO (from an older
 * firmware) at SHELLUI_FALLBACK_RCO_PATH, Debug Settings renders normally
 * again. Otherwise the hook also tries dropping "Core" from the basename
 * (Sce.Vsh.ShellUI.Settings.rco) both under the asset dir and under the
 * original requested directory. If no candidate exists, the hook returns the
 * original fopen result so the failure mode is unchanged (no worse than the
 * pre-hook behaviour). */
#define SHELLUI_RCO_NAME_MISSING         "Sce.Vsh.ShellUI.Settings.Core.rco"
#define SHELLUI_RCO_NAME_ALT_BASENAME    "Sce.Vsh.ShellUI.Settings.rco"
#define SHELLUI_FALLBACK_RCO_PATH \
  SHELLUI_ASSET_DIR "/" SHELLUI_RCO_NAME_MISSING

/* Kernel module that exports the open() syscall wrapper on PS5. Every file
 * open on the PS5 goes through open() -> sceKernelOpen() kernel syscall, so
 * hooking here is the lowest user-space interception point and cannot be
 * bypassed by Sony-internal IO wrappers (e.g. ResourceObj inside
 * Sce.PlayStation.Core.dll). */
#define SHELLUI_KERNEL_MODULE            "libkernel_sys.sprx"

/* ---- Mono assembly/class/method names (plain text) ---- */

#define MONO_LEGACY_DLL       "Sce.Vsh.ShellUI.Legacy.dll"
#define MONO_UI3_DLL          "Sce.Vsh.ShellUI.Settings.CoreUI3"
#define MONO_MSLIB_DLL        "mscorlib.dll"
#define MONO_CLASS_SETTINGS   "SettingsPlugin"
#define MONO_CLASS_PAGE       "SettingPage"
#define MONO_CLASS_RUNTIME    "RuntimeAssembly"
#define MONO_NS_REFLECTION    "System.Reflection"
#define MONO_NS_IO            "System.IO"
#define MONO_CLASS_MEMSTREAM  "MemoryStream"

#define MONO_METHOD_GET_STREAM   "GetManifestResourceStream"
#define MONO_METHOD_CXML         "CxmlUri"
#define MONO_METHOD_ONPRESS      "OnPressed"
#define MONO_METHOD_ONCREATE     "OnCreating"
#define MONO_METHOD_GETSTRING    "GetString"

/* ---- Maximum handler dispatch table size ---- */
#define SHELLUI_MAX_HANDLERS  128

/* ---- Configuration structure (unchanged from v1) ---- */

typedef struct {
  bool debugger_enabled;      int debugger_port;    /* 9020 */
  bool tracer_enabled;
  bool klog_enabled;          int klog_max_lines;   /* 5000 */
  bool ftp_enabled;           int ftp_port;         /* 1337 */
  bool ps5debug_enabled;
  bool udp_log_enabled;       int udp_log_port;     /* 9023 */
  bool auto_start;
  bool display_version;
} memdbg_shellui_config_t;

/* ---- IPC command enum ---- */

typedef enum {
  SHIPC_TOGGLE_DEBUGGER = 0x1000,
  SHIPC_TOGGLE_TRACER   = 0x1001,
  SHIPC_TOGGLE_KLOG     = 0x1002,
  SHIPC_TOGGLE_FTP      = 0x1003,
  SHIPC_TOGGLE_PS5DEBUG = 0x1004,
  SHIPC_TOGGLE_UDPLOG   = 0x1005,
  SHIPC_RELOAD_CONFIG   = 0x1006,
  SHIPC_SHUTDOWN        = 0x1007,
  SHIPC_PING            = 0x1008,
  SHIPC_GET_STATUS      = 0x1009,
  SHIPC_PLUGIN_EVENT    = 0x2000,
} shellui_ipc_command_t;

typedef struct {
  uint32_t command;
  uint32_t value;
  uint32_t reserved[2];
} shellui_ipc_request_t;

typedef struct {
  uint32_t command;
  int32_t  result;
  uint32_t value;
  uint32_t reserved[1];
} shellui_ipc_response_t;

/* ---- Persistent IPC state ---- */

typedef struct {
  int      fd;           /* persistent socket, -1 if disconnected */
  bool     connected;
  uint64_t last_ping_ms; /* monotonic timestamp */
} shellui_ipc_state_t;

extern shellui_ipc_state_t g_ipc;

/* ---- XML cache ---- */

typedef struct {
  char   *buf;       /* heap-allocated cached XML */
  size_t  len;       /* current length */
  size_t  cap;       /* buffer capacity */
  bool    dirty;     /* needs rebuild before next read */
  bool    valid;     /* cache is populated */
} shellui_xml_cache_t;

extern shellui_xml_cache_t g_xml_cache;

/* Mark XML cache as dirty (call after config/plugin change) */
void shellui_xml_invalidate(void);

/* ---- Handler dispatch (hash-based) ---- */

typedef void (*shellui_handler_fn)(const char *id, const char *value);

/* Register a handler for a given element ID. Returns false if table full. */
bool shellui_handler_register(const char *id, shellui_handler_fn fn);

/* Dispatch an OnPress event for the given element ID and value.
 * Returns true if a handler was found and invoked. */
bool shellui_handler_dispatch(const char *id, const char *value);

/* Clear all registered handlers (for re-registration on plugin reload). */
void shellui_handler_clear(void);

/* Register all built-in element handlers (called once at init). */
void shellui_register_builtin_handlers(void);

/* ---- Plugin types ---- */

typedef enum {
  SHELLUI_EL_TOGGLE_SWITCH = 0,
  SHELLUI_EL_BUTTON        = 1,
  SHELLUI_EL_LABEL         = 2,
  SHELLUI_EL_TEXT_FIELD    = 3,
  SHELLUI_EL_LINK          = 4,
} shellui_element_type_t;

typedef struct {
  char     prefix[14];        /* "MEMDBG_PLUGIN" */
  uint16_t shellui_elements;
} memdbg_plugin_header_t;

typedef struct {
  shellui_element_type_t type;
  char id[64];
  char title[128];
  char second_title[256];
  char default_value[16];
} shellui_plugin_element_t;

typedef struct {
  char plugin_id[64];
  char plugin_name[128];
  char plugin_version[16];
  int  element_count;
  shellui_plugin_element_t elements[16];
} shellui_plugin_def_t;

int  shellui_plugin_discover(shellui_plugin_def_t *plugins, int max);
void shellui_plugin_set_dir(const char *dir);
int  shellui_plugin_xml_generate(char *buf, size_t buf_size,
                                  const shellui_plugin_def_t *plugins,
                                  int plugin_count);

/* ---- Public API ---- */

/* Config */
void shellui_config_defaults(memdbg_shellui_config_t *cfg);
bool shellui_config_load(memdbg_shellui_config_t *cfg, const char *path);
bool shellui_config_save(const memdbg_shellui_config_t *cfg, const char *path);

/* XML generation (reads from cache if valid && !dirty) */
void shellui_xml_generate(char *buf, size_t buf_size,
                          const memdbg_shellui_config_t *cfg,
                          const shellui_plugin_def_t *plugins,
                          int plugin_count);

/* IPC */
int  shellui_ipc_connect(void);
void shellui_ipc_disconnect(int fd);
bool shellui_ipc_send(int fd, const shellui_ipc_request_t *req,
                      shellui_ipc_response_t *resp);

/* Persistent IPC: fire-and-forget (no response wait) */
bool shellui_ipc_fire(const shellui_ipc_request_t *req);
/* Poll daemon status (blocking up to timeout_ms, 0 = non-blocking) */
bool shellui_ipc_poll(shellui_ipc_response_t *resp, int timeout_ms);
/* Check if persistent connection is alive */
bool shellui_ipc_is_alive(void);

/* Version */
const char *shellui_version_string(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMDBG_SHELLUI_INTERNAL_H */
