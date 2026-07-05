#!/usr/bin/env python3
"""
check_headers.py — Verify that every header under include/memdbg/
                    has a corresponding source file under src/.

Exits 0 when all headers are accounted for; exits 1 with diagnostics otherwise.

Reasoning: the Makefile's HOST_CPPFLAGS only adds -Iinclude, so every header
included as `#include "memdbg/foo/bar.h"` must resolve through
include/memdbg/foo/bar.h.  If that file is a symlink or a copy to
src/foo/bar.c, it can rot — this check catches both missing sources
and headers that no C file ever includes.
"""

import os
import sys
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCLUDE_DIR = ROOT / "include" / "memdbg"
SRC_DIR = ROOT / "src"

# Headers that are protocol definitions, inline helpers, or otherwise
# have no dedicated .c implementation file.
NO_SOURCE_EXCEPTIONS = {
    "memdbg_protocol.h",
    "region_match.h",
}

# Headers whose primary implementation lives inside daemon/memdbg.c
# (the dispatcher) rather than in a separate .c.
DAEMON_HEADERS = {
    "memdbg.h",
}

# Generated headers (do not count as actual source files).
# memdbg_version.h is generated from memdbg_version.h.in at build time
# and lives under build/generated/include/; the check_headers tool only
# scans include/memdbg/ so it won't encounter the output file.  Keeping
# both names here guards against an accidental copy-in of the generated
# file into the include tree.
GENERATED_HEADERS = {
    "memdbg_version.h.in",
    "memdbg_version.h",
}


def find_all_source_files() -> dict[str, str]:
    """Return {basename_without_ext: full_relative_path} for every .c under src/."""
    sources: dict[str, str] = {}
    for cfile in SRC_DIR.rglob("*.c"):
        rel = str(cfile.relative_to(ROOT))
        stem = cfile.stem  # basename without .c
        sources[stem] = rel
    return sources


def find_header_includes_in_source(src_path: Path, header_include: str) -> bool:
    """Check whether a .c file includes a specific header path."""
    if not src_path.exists():
        return False
    try:
        text = src_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    pattern = re.escape(f'#include "{header_include}"')
    return re.search(pattern, text) is not None


def header_include_path(header_rel: str) -> str:
    """
    Convert include/memdbg/foo/bar.h → "memdbg/foo/bar.h"
    (the exact string that appears in #include directives).
    """
    return header_rel.replace("include/", "", 1)


def main() -> int:
    header_files = sorted(
        h for h in INCLUDE_DIR.rglob("*.h")
        if h.name not in GENERATED_HEADERS
    )

    source_map = find_all_source_files()
    issues: list[str] = []
    ok_count = 0

    print(f"Checking {len(header_files)} headers in include/memdbg/ ...")
    print()

    for hdr_path in header_files:
        rel = str(hdr_path.relative_to(ROOT))
        include_ref = header_include_path(rel)
        basename = hdr_path.stem  # e.g. "flashscan" from "flashscan.h"
        subpath = hdr_path.relative_to(INCLUDE_DIR)  # e.g. "scanner/flashscan.h"

        # --- Exceptions ---
        if basename in NO_SOURCE_EXCEPTIONS:
            ok_count += 1
            continue
        if basename in DAEMON_HEADERS:
            # The daemon implementation is in core/daemon/memdbg.c
            daemon_c = SRC_DIR / "core" / "daemon" / "memdbg.c"
            if daemon_c.exists():
                ok_count += 1
                continue
            issues.append(f"{rel}: daemon header but {daemon_c.relative_to(ROOT)} not found")
            continue

        # --- Check 1: exact path match src/<subpath>/<name>.c ---
        expected_c = SRC_DIR / subpath.parent / (basename + ".c")
        if expected_c.exists():
            ok_count += 1
            continue

        # --- Check 2: resolve symlinks ---
        resolved = hdr_path
        try:
            resolved = hdr_path.resolve()
        except OSError:
            pass
        if resolved != hdr_path:  # symlink
            expected_resolved = resolved.with_suffix(".c")
            if expected_resolved.exists():
                ok_count += 1
                continue

        # --- Check 3: search for a .c with matching basename anywhere in src/ ---
        if basename in source_map:
            ok_count += 1
            continue

        # --- Check 4: grep all .c files for #include "memdbg/..." of this header ---
        found_include = False
        for src_stem, src_relpath in source_map.items():
            src_path = ROOT / src_relpath
            if find_header_includes_in_source(src_path, include_ref):
                found_include = True
                break

        if found_include:
            ok_count += 1
            continue

        # --- No source file includes this header ---
        issues.append(
            f"  {rel}\n"
            f"    → Expected source at: src/{subpath.parent}/{basename}.c (not found)\n"
            f"    → No .c in src/ has basename '{basename}.c'\n"
            f"    → No .c in src/ includes '{include_ref}'"
        )

    print(f"  {ok_count} header(s) OK")
    print()

    if issues:
        print(f"ERROR: {len(issues)} header(s) without corresponding source:")
        print()
        for issue in issues:
            print(issue)
            print()
        print("Fix: either add the missing .c file under src/, create a symlink in")
        print("include/memdbg/ pointing to the correct location, or add the header")
        print(f"basename to the NO_SOURCE_EXCEPTIONS or DAEMON_HEADERS sets in {__file__}")
        return 1

    print("All headers are accounted for.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
