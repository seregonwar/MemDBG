## Plugin Sources

Open **Plugins** to manage Lua and Python scripts. The default source is the
forkable `seregonwar/MemDBG-Plugin` repository, with a bundled local fallback in
`plugin-repository/`.

You can add a GitHub repo URL, a raw `manifest.json` URL, or a local folder/file
path. A source repository only needs a `manifest.json` and script files.

## Installing and Running

1. Press **Refresh** to update enabled sources.
2. Select a plugin from the catalog.
3. Press **Install** or **Update**.
4. Press **Run**.

MemDBG launches the local Lua or Python interpreter and passes a JSON context
file containing the active console endpoint, selected PID, dump path, trainer
file path, map count, scan hit count, and trainer entry count.

## Creating Your Own Repository

Fork the default repository, add scripts under `plugins/`, then add package
entries to `manifest.json`.

```json
{
  "id": "com.example.memdbg.my-plugin",
  "name": "My Plugin",
  "version": "1.0.0",
  "language": "python",
  "entry": "my_plugin.py",
  "summary": "Short catalog text shown in the plugin list.",
  "description": "Full plugin description shown in details when expanded.",
  "author": "YourName",
  "icon": "assets/my_plugin.png",
  "files": [
    { "path": "my_plugin.py", "url": "plugins/my_plugin.py" }
  ]
}
```

Catalog entries can also use `image`, `thumbnail`, or `artwork` instead of
`icon`, `summary`/`short_description` for card text, `full_description` or
`long_description` for complete details, and `download_count` or
`stats.downloads` instead of `downloads`.

Plugins run on the desktop frontend. They should treat the context file as the
stable integration point.

Python plugins can include `sdk/memdbg.py` as `memdbg.py` and call
`MemDBG.from_context()` to access process, map, and memory APIs. The SDK also
contains `run_mcp_stdio()` for MCP stdio bridge plugins.

## GUI Layout JSON

Interactive Python GUI plugins can move the ImGui widget tree out of Python and
into a sibling `*.ui.json` file. Python keeps the event handling and MemDBG API
calls; the JSON describes the widgets rendered by the native frontend.

```json
{
  "schema": 1,
  "widgets": [
    { "type": "text_colored", "text": "My Plugin", "color": "primary2" },
    { "type": "combo", "id": "process", "label": "Process", "items_from": "$processes" },
    { "type": "button", "id": "refresh", "label": "Refresh", "variant": "soft" }
  ]
}
```

Use `mcp_server.gui_layout.GuiLayout` to load and render the file with a view
model. The default `example_gui_plugin` shows the complete pattern.
