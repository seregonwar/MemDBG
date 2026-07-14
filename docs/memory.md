# MemDBG PS5 ShellUI Integration

This document describes how MemDBG integrates into the PS5 system settings menu
through the `src/shellui/` module — a standalone SPRX injected into the
`SceShellUI` process.

## Architecture Overview

```
                         ┌──────────────────────────────────┐
                         │         SceShellUI process       │
                         │  ┌─────────────────────────────┐ │
memdbg_shellui.sprx ────▶│  │  Mono (.NET) runtime        │ │
  (injected via elfldr)  │  │  ┌───────────────────────┐  │ │
                         │  │  │ GetManifestResource   │  │ │
                         │  │  │   Stream (hook #1)    │◀─┼─┼── serves custom XML
                         │  │  │ OnPressed (hook #2)   │ ◀┼─┼── dispatches toggles
                         │  │  │ OnCreating (hook #3)  │◀─┼─┼── restores state
                         │  │  │ CxmlUri (hook #4)     │◀─┼─┼── replaces icons
                         │  │  └───────────────────────┘  │ │
                         │  └─────────────────────────────┘ │
                         │              │ TCP :9020         │
                         └──────────────┼───────────────────┘
                                        ▼
                         ┌─────────────────────────────────┐
                         │       MemDBG Daemon             │
                         │  (separate payload process)     │
                         └─────────────────────────────────┘
```

The ShellUI module is a **shared process resource** (`.sprx`) injected into
SceShellUI at boot. It hooks four Mono methods to:

1. **Inject custom XML** — replace the `debug_settings.xml` embedded resource
   with MemDBG's toolbox page, preserving the original content via a `<link>`.
2. **Handle user input** — dispatch OnPressed events through a hash table to
   per-element handler callbacks.
3. **Restore toggle state** — apply saved config values to UI elements on page
   render.
4. **Replace icons** — swap the default game icon with the MemDBG logo.

A fifth detour (libc-level, not Mono) is installed for forward
compatibility with firmware that has migrated Settings to React Native:

5. **Redirect missing `.rco`** — detour libc `fopen` so that requests for the
   legacy PUI resource container `Sce.Vsh.ShellUI.Settings.Core.rco` are
   redirected to a user-provided copy in `/user/data/memdbg/assets/` (or a
   couple of alternate fall-throughs). See [Legacy `.rco` Redirect](#legacy-rco-redirect)
   below.

## Entry Point (`shellui_main.c`)

The module's `shellui_main()` is the PRX entry point. It performs these steps
in order:

### 1. Mono Symbol Resolution

All Mono runtime symbols are resolved once at init into a **single vtable**
(`memdbg_mono_vtable_t`) rather than individual global function pointers:

```c
typedef struct {
  MonoDomain   *(*get_root_domain)(void);
  MonoClass    *(*class_from_name)(MonoImage*, const char*, const char*);
  MonoMethod   *(*class_get_method)(MonoClass*, const char*, int);
  MonoProperty *(*class_get_property)(MonoClass*, const char*);
  MonoMethod   *(*property_get_get)(MonoProperty*);
  MonoMethod   *(*property_get_set)(MonoProperty*);
  MonoObject   *(*runtime_invoke)(MonoMethod*, void*, void**, void**);
  MonoObject   *(*object_new)(MonoDomain*, MonoClass*);
  MonoString   *(*string_new)(MonoDomain*, const char*);
  const char   *(*string_to_utf8)(MonoString*);
  uint64_t      (*compile_method)(MonoMethod*);
  MonoAssembly *(*domain_assembly_open)(MonoDomain*, const char*);
  MonoImage    *(*assembly_get_image)(MonoAssembly*);
  MonoClass    *(*get_byte_class)(void);
  MonoArray    *(*array_new)(MonoDomain*, MonoClass*, uintptr_t);
  char         *(*array_addr)(MonoArray*, int, uintptr_t);
  void          (*free_fn)(void*);
} memdbg_mono_vtable_t;
```

All 17 symbols are resolved via `kernel_dlsym()` from `libmonosgen-2.0.sprx`.
Assembly/class/method names are **plain string literals** — no base64
obfuscation:

```c
#define MONO_LEGACY_DLL     "Sce.Vsh.ShellUI.Legacy.dll"
#define MONO_CLASS_PAGE     "SettingPage"
#define MONO_METHOD_ONPRESS "OnPressed"
```

### 2. Configuration Loading

The INI config file (`/user/data/memdbg/shellui.ini`) is loaded with
`shellui_config_load()`. Defaults are applied for missing keys.

### 3. Handler Registration

Built-in element handlers are registered via `shellui_register_builtin_handlers()`,
which populates a hash-based dispatch table (see Handler Dispatch below).

### 4. Plugin Discovery

`shellui_plugin_discover()` scans `/user/data/memdbg/plugins/` for
`.memdbg_plugin` files and populates the plugin registry.

### 5. Hook Installation

Four Mono method detours are installed, plus one libc `fopen` detour:

| Symbol | Hook | Resolved from | Purpose |
|---|---|---|---|
| `RuntimeAssembly.GetManifestResourceStream` | `shellui_get_manifest_resource_stream_hook` | mscorlib.dll (Mono) | Inject custom XML / serve original Debug Settings |
| `SettingsPlugin.CxmlUri` | `shellui_cxml_uri_hook` | Sce.Vsh.ShellUI.Settings.CoreUI3 (Mono) | Replace icon URIs |
| `SettingPage.OnPressed` | `shellui_on_press_hook` | Sce.Vsh.ShellUI.Settings.CoreUI3 (Mono) | Handle toggle/button presses |
| `SettingPage.OnCreating` | `shellui_on_pre_create_hook` | Sce.Vsh.ShellUI.Settings.CoreUI3 (Mono) | Restore toggle states from config |
| `fopen` | `shellui_fopen_hook` | libSceLibcInternal.sprx (libc) | Redirect missing legacy `.rco` (see below) |

## Resource Path Hijacking

### How ShellUI Loads Settings

PS5 system settings are embedded as XML resources in SceShellUI assemblies.
The `Debug Settings` menu is loaded from the resource path:

```
Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.
  DebugSettings.data.debug_settings.xml
```

On retail consoles, this menu is hidden by default and becomes available only
when kernel debug flags are enabled. MemDBG hijacks this resource to display
its own toolbox.

### XML Injection

When ShellUI requests `debug_settings.xml`, our `GetManifestResourceStream`
hook intercepts the call and returns MemDBG's custom `<system_settings>` XML:

```xml
<system_settings version="1.0" plugin="debug_settings_plugin">
  <setting_list id="id_memdbg_toolbox" title="MemDBG Toolbox">
    <!-- Toggles: Debugger, Tracer, KLog, FTP, PS5Debug, UDP Log -->
    <!-- Text fields: ports, line counts -->
    <!-- Buttons: Ping Daemon, Shutdown Daemon -->
    <!-- Info label: version + endpoint summary -->
    <!-- Plugin sections (auto-generated) -->

    <!-- Link to original Debug Settings -->
    <link id="id_memdbg_original_debug" title="Debug Settings"
          file="original_debug.xml"
          second_title="System debug settings"/>
  </setting_list>
</system_settings>
```

### Preserving Original Debug Settings

The `<link>` element creates a clickable sub-page entry. When clicked,
ShellUI constructs the resource name by prepending the plugin namespace:

```
Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.original_debug.xml
```

Our hook intercepts this request and calls the **original** (undetoured)
`GetManifestResourceStream` with the real `debug_settings.xml` path,
serving the unmodified system content. This preserves the original Debug
Settings functionality without pre-capturing or duplicating the content.

### XML Cache

The generated XML is cached in a heap-allocated buffer (`g_xml_cache`).
The cache is rebuilt only when the **dirty flag** is set:

- `shellui_config_save()` → calls `shellui_xml_invalidate()` → sets dirty
- `shellui_xml_generate()` → if dirty, calls `rebuild_cache()` → copies from cache

This avoids regenerating the XML string on every page visit (O(1) read
instead of O(n) format on each Mono request).

<a name="legacy-rco-redirect"></a>
### Legacy `.rco` Redirect (FW 9.4.0+)

Starting with system software 9.4.0 Sony migrated the Settings UI to React
Native and no longer ships the legacy PUI resource container at
`/app0/psm/Application/resource/Sce.Vsh.ShellUI.Settings.Core.rco`. When the
user opens the Debug Settings page, the React Native shell still transitions
to the legacy Mono scene `SettingsAppScene : SettingsAppSceneUI3`, which
calls `Sce.PlayStation.Core.Resources.CxmlResources.Load()`. That ctor does
a plain `fopen()` on the `.rco`; on affected firmware the file is gone, the
native `fopen` returns `SCE_NET_ENOENT(-ish)`, and the
`System.IO.FileNotFoundException` raised inside `CxmlLoadRequestJob.Finish()`
propagates unhandled to `Application.Run()` and kills the whole SceShellUI
process (see `UnhandledException ... cannot open ...Debug Settings.Core.rco`).

MemDBG installs a detour on libc `fopen` (resolved from
`libSceLibcInternal.sprx` via `kernel_dlsym`) to mitigate this without
touching the `.NET` exception machinery:

1. When the requested path contains the literal token
   `Sce.Vsh.ShellUI.Settings.Core.rco`, the hook tries the user-provided
   copy at `SHELLUI_FALLBACK_RCO_PATH`
   (`/user/data/memdbg/assets/Sce.Vsh.ShellUI.Settings.Core.rco`).
2. If that fails it tries the alternate basename `Sce.Vsh.ShellUI.Settings.rco`
   (Sony sometimes drops "Core") under the same MemDBG asset directory.
3. If that also fails, it tries the same alt basename in the directory that
   was originally requested (in case the file was simply renamed on disk).
4. If nothing matches, the hook returns the original `fopen` result so the
   failure mode stays explicit — we don't mask a half-initialised
   `CxmlResources` that would throw later from a harder-to-debug spot.

**Required user action on affected firmware**: dump the original
`Sce.Vsh.ShellUI.Settings.Core.rco` from an older firmware (or from a
debug/dev unit) and drop it at
`/user/data/memdbg/assets/Sce.Vsh.ShellUI.Settings.Core.rco`. The MemDBG
daemon already creates `/user/data/memdbg/assets/` at boot, so no extra
setup is needed.

The detour only intercepts the specific missing resource name; every other
`fopen` (config IO, plugin discovery, daemon file IO, etc.) is forwarded
untouched to the original libc function, so the hook has O(1) cost for the
common case.

## Handler Dispatch (Hash-Based)

### FNV-1a Hash Table

Element ID strings are dispatched through a hash table using the FNV-1a
algorithm. Each handler is a small focused callback:

```c
typedef void (*shellui_handler_fn)(const char *id, const char *value);

static void h_debugger(const char *id, const char *value) {
  int v = value ? ((strcmp(value, "0") == 0) ? 0 : 1) : 1;
  g_config.debugger_enabled = (v != 0);
  shellui_ipc_fire(&(shellui_ipc_request_t){
    SHIPC_TOGGLE_DEBUGGER, g_config.debugger_enabled ? 1 : 0, {0,0}});
  shellui_config_save(&g_config, SHELLUI_CONFIG_FILE);
}
```

13 built-in handlers are registered at init:

| Element ID | Handler | Action |
|---|---|---|
| `id_memdbg_debugger` | `h_debugger` | Toggle debugger |
| `id_memdbg_tracer` | `h_tracer` | Toggle syscall tracer |
| `id_memdbg_klog` | `h_klog` | Toggle kernel log |
| `id_memdbg_ftp` | `h_ftp` | Toggle FTP server |
| `id_memdbg_ps5debug` | `h_ps5debug` | Toggle PS5Debug compat |
| `id_memdbg_udp_log` | `h_udp_log` | Toggle UDP forwarding |
| `id_memdbg_auto_start` | `h_auto_start` | Toggle auto-start |
| `id_memdbg_debugger_port` | `h_debugger_port` | Set debugger port |
| `id_memdbg_klog_lines` | `h_klog_lines` | Set max log lines |
| `id_memdbg_ftp_port` | `h_ftp_port` | Set FTP port |
| `id_memdbg_udp_log_port` | `h_udp_log_port` | Set UDP log port |
| `id_memdbg_ping` | `h_ping` | Ping daemon |
| `id_memdbg_shutdown` | `h_shutdown` | Shutdown daemon |

Plugin elements are dispatched through a separate scan loop
(`h_plugin_event`), encoded as `SHELLUI_IPC_PLUGIN_EVENT`.

### OnPressed Flow

```
ShellUI OnPressed
  → shellui_on_press_hook()
    → get_element_id() / get_element_value()
    → shellui_handler_dispatch()  ← FNV-1a hash lookup
      → handler callback
        → shellui_ipc_fire()      ← async fire-and-forget
        → shellui_config_save()   ← persist + invalidate cache
```

## Persistent IPC (`shellui_ipc.c`)

The v2 IPC client maintains a **persistent TCP connection** to the MemDBG
daemon on `localhost:9020`:

```c
typedef struct {
  int      fd;           /* persistent socket, -1 if disconnected */
  bool     connected;
  uint64_t last_ping_ms;
} shellui_ipc_state_t;
```

Key operations:

- **`shellui_ipc_fire()`** — Fire-and-forget: sends a request without waiting
  for a response. Connection is established lazily on first use and
  auto-reconnects on failure.
- **`shellui_ipc_poll()`** — Blocking status query: sends `SHIPC_GET_STATUS`
  and reads back the daemon's current state.
- **`shellui_ipc_is_alive()`** — Checks if the persistent connection is valid.

This replaces the v1 pattern of `connect() → send() → recv() → close()` per
event (3 syscalls per toggle) with a single `send()` per event.

## Configuration Persistence (`shellui_config.c`)

Settings are stored in INI format at `/user/data/memdbg/shellui.ini`:

```ini
[MemDBG]
debugger=1
debugger_port=9020
tracer=1
klog=0
klog_max_lines=5000
ftp=0
ftp_port=1337
ps5debug=0
udp_log=1
udp_log_port=9023
auto_start=1
display_version=1
```

Boolean values accept: `1`/`0`, `true`/`false`, `on`/`off`, `yes`/`no`.

Config writes (`shellui_config_save()`) automatically invalidate the XML cache.

## Plugin Integration (`shellui_plugin.c`)

Desktop plugins can declare ShellUI elements via `.memdbg_plugin` metadata
files placed in `/user/data/memdbg/plugins/`. Each file has a 16-byte
binary header followed by element lines:

```
Binary header (16 bytes):
  char prefix[14]    = "MEMDBG_PLUGIN"
  uint16_t elements  = number of element lines following

Element lines (colon-separated):
  TYPE:ID:TITLE:SECOND_TITLE:DEFAULT_VALUE

Example:
  toggle_switch:my_toggle:My Feature:Enable my feature:1
  button:my_button:Trigger Action:Click to run:
  label:my_info:Status:active:
  text_field:my_port:Port:1-65535:8080
```

Elements are merged into the main XML as additional `<setting_list>` blocks
after the MemDBG toolbox section.

## Build System

The ShellUI module compiles as a standalone `.sprx` using the PS5 payload SDK:

```makefile
SHELLUI_SOURCES := src/shellui/shellui_xml_gen.c \
                   src/shellui/shellui_config.c \
                   src/shellui/shellui_ipc.c     \
                   src/shellui/shellui_plugin.c  \
                   src/shellui/shellui_hooks.c   \
                   src/shellui/shellui_main.c

$(SHELLUI_TARGET): $(SHELLUI_OBJECTS)
	$(PS5_CC) -shared -fPIC \
	  -Wl,--unresolved-symbols=ignore-all $^ -o $@
```

Runtime symbols (`get_module_handle`, `kernel_dlsym`, `DetourFunction`) are
left unresolved at link time — they are provided by the PS5 kernel and payload
SDK when the SPRX is loaded into SceShellUI by the bootstrapper.

Host tests cover the XML generation, config persistence, and plugin discovery
logic (108 total tests, all passing):
- `make test-shellui-xml` — 26 tests
- `make test-shellui-config` — 36 tests
- `make test-shellui-plugin` — 46 tests

## File Index

| File | Purpose |
|---|---|
| `shellui_internal.h` | Shared types, config struct, IPC enum, handler table, resource paths |
| `shellui_monoutils.h` | Mono vtable type, host stubs, PS5 `DetourFunction`/`kernel_dlsym` |
| `shellui_main.c` | PRX entry point, symbol resolution, hook installation |
| `shellui_hooks.c` | FNV-1a handler dispatch, OnPressed/OnCreating/CxmlUri/GetManifestResourceStream hooks |
| `shellui_xml_gen.c` | XML generation with heap cache and dirty-flag invalidation |
| `shellui_config.c` | INI config load/save with bool variants and cache invalidation |
| `shellui_ipc.c` | Persistent TCP connection, fire-and-forget, status polling |
| `shellui_plugin.c` | `.memdbg_plugin` discovery, dynamic XML generation for plugins |
