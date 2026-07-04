#!/usr/bin/env python3
#
# MemDBG - bundled context dump plugin.
# Copyright (C) 2026 SeregonWar
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import sys


def _context_path():
    if len(sys.argv) > 1 and sys.argv[1]:
        return sys.argv[1]
    return os.environ.get("MEMDBG_CONTEXT", "")


def _load_context():
    path = _context_path()
    if not path:
        raise RuntimeError("MEMDBG_CONTEXT is not set")
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main():
    context = _load_context()
    console = context.get("console", {})
    process = context.get("process", {})
    paths = context.get("paths", {})
    state = context.get("state", {})
    memdbg = context.get("memdbg", {})

    print("MemDBG Python plugin context")
    print(f"console={console.get('host', '')}:{console.get('debug_port', '')}")
    print(f"udp={console.get('udp_port', '')}")
    print(f"connected={console.get('connected', False)}")
    print(f"pid={process.get('pid', 0)}")
    print(f"process={process.get('name', '')}")
    print(f"maps={state.get('map_count', 0)}")
    print(f"scan_hits={state.get('scan_hit_count', 0)}")
    print(f"trainer_entries={state.get('trainer_entry_count', 0)}")
    print(f"dump_path={paths.get('dump', '')}")
    print(f"trainer_path={paths.get('trainer', '')}")
    print(f"protocol={memdbg.get('protocol_version', 0)}")
    print(f"capabilities=0x{int(memdbg.get('capabilities', 0)):08X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
