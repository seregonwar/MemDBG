#!/usr/bin/env python3
"""
generate_locale_manifest.py — Build the remote locale manifest consumed by the
frontend language selector.

Usage:
  python3 tools/generate_locale_manifest.py [--locales-dir frontend/locales]
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


DEFAULT_RAW_BASE = "https://raw.githubusercontent.com/seregonwar/memDBG/main/frontend/locales"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate frontend/locales/manifest.json")
    parser.add_argument("--locales-dir", default=None)
    parser.add_argument("--raw-base", default=DEFAULT_RAW_BASE)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    locales_dir = Path(args.locales_dir) if args.locales_dir else repo_root / "frontend" / "locales"
    if not locales_dir.is_dir():
        print(f"ERROR: locales directory not found: {locales_dir}", file=sys.stderr)
        return 1

    languages = []
    for path in sorted(locales_dir.glob("*.json")):
        if path.name == "manifest.json":
            continue
        raw = path.read_bytes()
        try:
            doc = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            print(f"ERROR: {path.name}: {exc}", file=sys.stderr)
            return 1
        if not isinstance(doc, dict):
            print(f"ERROR: {path.name}: top-level value is not an object", file=sys.stderr)
            return 1

        code = path.stem
        meta = doc.get("_meta", {})
        if isinstance(meta, dict) and meta.get("code") and meta["code"] != code:
            print(f"ERROR: {path.name}: _meta.code does not match filename", file=sys.stderr)
            return 1

        name = meta.get("language") if isinstance(meta, dict) else None
        if not isinstance(name, str) or not name.strip():
            name = code

        languages.append(
            {
                "code": code,
                "name": name,
                "filename": path.name,
                "url": f"{args.raw_base.rstrip('/')}/{path.name}",
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "embedded": code == "en",
            }
        )

    manifest = {
        "version": 1,
        "repository": "https://github.com/seregonwar/memDBG",
        "raw_base": args.raw_base.rstrip("/"),
        "languages": languages,
    }

    output = locales_dir / "manifest.json"
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output} with {len(languages)} language(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
