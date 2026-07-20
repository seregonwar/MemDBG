# MemDBG Plugin and Script Repositories

MemDBG supports desktop-side Lua and Python plugins through repository manifests.
The default source is:

`https://github.com/seregonwar/MemDBG-Plugin`

A bundled fallback copy lives in `plugin-repository/` so the frontend has a
working catalog even before the remote source is reachable.

Installed GUI plugins tagged with `gui` appear in the sidebar **Plugin Apps**
launcher. The launcher shows the active plugin state, opens GUI plugins without
leaving the navigation flow, and links back to the full Plugins manager.

## Repository Layout

```text
MemDBG-Plugin/
├── manifest.json
└── plugins/
    ├── context_dump.py
    ├── example_gui_plugin.py
    ├── example_gui_plugin.ui.json
    └── session_brief.lua
```

## Manifest Format

`manifest.json` is intentionally close to a small  source: repository
metadata at the top, then a package list under `plugins`.

```json
{
  "schema": 1,
  "name": "My MemDBG Plugins",
  "identifier": "com.example.memdbg.plugins",
  "plugins": [
    {
      "id": "com.example.memdbg.my-plugin",
      "name": "My Plugin",
      "version": "1.0.0",
      "language": "python",
      "entry": "my_plugin.py",
      "summary": "Short catalog text shown in the plugin list.",
      "description": "Full plugin description shown in the details panel when expanded.",
      "author": "YourName",
      "icon": "assets/my_plugin.png",
      "tags": ["python", "trainer"],
      "permissions": ["read_context"],
      "files": [
        { "path": "my_plugin.py", "url": "plugins/my_plugin.py" }
      ]
    }
  ]
}
```

Optional catalog metadata:

- `icon`, `image`, `thumbnail`, or `artwork`: relative path, local path, or URL
  for the plugin image shown by the catalog.
- `summary`, `short_description`, or `shortDescription`: compact description
  for plugin cards. Keep it short; MemDBG truncates long card text.
- `description`, `full_description`, or `long_description`: complete readable
  description shown in plugin details behind the expand control.
- `downloads`, `download_count`, or `stats.downloads`: community download count
  shown in plugin cards and details.
- `author` or `maintainer`: creator name shown next to the plugin image.

Accepted source inputs in the Plugins page:

- GitHub repo URL, for example `https://github.com/user/MemDBG-Plugin`
- Raw manifest URL
- Local `manifest.json` path
- Local folder containing `manifest.json`

## Runtime Contract

When MemDBG runs a plugin it launches the local `python3`/`python`/`py -3` or
`lua`/`luajit` interpreter and passes one argument: a JSON context file.

With the plugin sandbox enabled, Python runs through the supervised OS sandbox.
Restrictive Python plugins are currently supported on macOS; Linux and Windows
fail closed until their native isolation backends are available. Disabling the
sandbox is reserved for explicitly trusted plugins.

The context includes:

- `console`: broker host/port, real target host/debug port, UDP port, connection
  state, and transport kind
- `process`: selected PID and process name
- `paths`: dump path, trainer file path, installed plugin path
- `state`: map count, scan hit count, trainer entry count
- `memdbg`: protocol version and capability bitmap

Plugins run on the desktop, not inside the console payload. Use the existing
payload protocol through MemDBG features for memory operations.

### Shared protocol transport

GUI plugins must use the `console.host` and `console.debug_port` values from the
runtime context. While a GUI plugin is active these point to a loopback protocol
broker owned by MemDBG, not directly to the console. The broker validates each
frame and routes it through the application's existing control, memory, scan,
or event connection. This keeps the console at the intended four sessions even
when an older SDK opens a new TCP socket for every request.

The physical console endpoint remains available as `console.target_host` and
`console.target_debug_port` for display and diagnostics only. Plugins must not
connect to that endpoint themselves: doing so consumes payload connection slots,
duplicates connection notifications, and bypasses the frontend's request
correlation and reconnect handling. Plugins launched outside the GUI bridge may
still receive the physical endpoint because no shared application session exists.

## Python App API

Python plugins can include the bundled SDK file:

```json
{ "path": "memdbg.py", "url": "sdk/memdbg.py" }
```

Then a plugin can call MemDBG like this:

```python
from memdbg import MemDBG

api = MemDBG.from_context()
print(api.process_list())
print(api.process_maps())      # selected PID from the app context
data = api.memory_read(0x1000, 16)
```

The SDK reads `MEMDBG_CONTEXT` or the context path passed as argv[1]. It exposes
`hello`, `process_list`, `process_maps`, `process_info`, `memory_read`, and
`memory_write`. It also includes `run_mcp_stdio(api)` for building MCP stdio
servers that expose MemDBG tools to external clients.

## Declarative GUI Layouts

Python GUI plugins can keep their runtime logic in Python while moving the
widget tree to an external JSON file. Include `mcp_server/gui_layout.py`, ship a
layout next to the plugin, then render it with a small view model:

```python
from mcp_server.gui import GuiBuilder
from mcp_server.gui_layout import GuiLayout

gui = GuiBuilder()
layout = GuiLayout.from_file("my_plugin.ui.json")
layout.render(gui, {
    "status": "Ready",
    "items": ["PID 1: game"],
})
```

The JSON uses the same widget names the native bridge already understands, such
as `text`, `button`, `checkbox`, `combo`, `input_text`, `table`, and
`batch_read_table`. It also supports lightweight helpers for `if`, `row`, and
`repeat` blocks plus `$name` bindings into the view model.
