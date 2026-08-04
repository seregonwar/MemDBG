# MemDBG engineering docs

Canonical language is **English** (`foo.md`). Translations live under
[`i18n/`](i18n/) with a language suffix (`.it.md`, `.de.md`, …). There are no
`.en.md` duplicates.

English layout:

- root — protocol, features, packaging
- [`bridges/`](bridges/) — host debugger bridges
- [`platform/`](platform/) — console launch notes
- [`archive/`](archive/) — historical / non-normative notes
- [`i18n/`](i18n/) — all non-English translations

For the end-user product guide (setup, scanner, trainer, troubleshooting), see
[`../github-pages/`](../github-pages/).

## Protocol and compatibility

| Document | Purpose |
|---|---|
| [protocol.md](protocol.md) | Internal MDBG wire protocol specification and extension rules |
| [ps5debug_compat.md](ps5debug_compat.md) | ps5debug compatibility layer (legacy TCP `744`) |

## Bridges

| Document | Purpose |
|---|---|
| [bridges/ida_gdb_bridge.md](bridges/ida_gdb_bridge.md) | Host GDB RSP proxy for IDA Pro ([Italiano](i18n/ida_gdb_bridge.it.md)) |
| [bridges/x64dbg_bridge.md](bridges/x64dbg_bridge.md) | x64dbg plugin bridge ([Italiano](i18n/x64dbg_bridge.it.md)) |

## Platform

| Document | Purpose |
|---|---|
| [platform/ps4_goldhen_launch.md](platform/ps4_goldhen_launch.md) | PS4 / GoldHEN launch notes and stale PID handling ([translations](i18n/)) |

## Features and architecture

| Document | Purpose |
|---|---|
| [reconnect.md](reconnect.md) | Rest-mode reconnect state machine |
| [codecave.md](codecave.md) | Code-cave alloc / write / detour workflow |
| [plugins.md](plugins.md) | Plugin manifest and runtime contract |
| [mobile_architecture.md](mobile_architecture.md) | iOS / Android shell architecture |
| [showcase.md](showcase.md) | UI screenshot tour (operational guide is github-pages) |

## Packaging

| Document | Purpose |
|---|---|
| [release_packaging.md](release_packaging.md) | Release artifacts, nightlies, and packaging details |

## Archive

Historical / non-normative notes live under [archive/](archive/). Prefer live
docs and issues for current behavior.
