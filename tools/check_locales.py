#!/usr/bin/env python3
"""
check_locales.py — Validate MemDBG locale JSON files for consistency.

Checks:
  1. All JSON files parse without errors.
  2. Every file has exactly the same keys as en.json (reference).
  3. No broken Unicode escape sequences (\\uXXXX).
  4. Format specifiers (%s, %d, %zu, etc.) are consistent across all languages.

Usage:
  python3 tools/check_locales.py [--locales-dir frontend/locales]

Exit code: 0 on success, 1 on validation errors.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

# ── helpers ──────────────────────────────────────────────────────────────────

def red(text: str) -> str:
    return f"\033[31m{text}\033[0m"

def green(text: str) -> str:
    return f"\033[32m{text}\033[0m"

def yellow(text: str) -> str:
    return f"\033[33m{text}\033[0m"

def dim(text: str) -> str:
    return f"\033[2m{text}\033[0m"

# ── format specifier extraction ──────────────────────────────────────────────

FORMAT_RE = re.compile(r"%(?:[0-9]*\.?[0-9]*)?[diouxXeEfFgGaAcspn%]|%zu|%ll[duixX]|%lu|%l[du]")
SOURCE_LOCALE_RE = re.compile(r'(?:locale::tr|\btr)\(\s*"([^"]+)"\s*\)')

def extract_specifiers(text: str) -> list[str]:
    """Return ordered list of printf-style format specifiers in *text*."""
    return FORMAT_RE.findall(text)


def check_format_consistency(
    ref_specs: dict[str, list[str]],
    lang_specs: dict[str, list[str]],
    lang_code: str,
) -> list[str]:
    """Return list of error messages for mismatched format specifiers."""
    errors = []
    for key, ref in ref_specs.items():
        other = lang_specs.get(key, [])
        if len(ref) != len(other):
            errors.append(
                f"{lang_code}: key '{key}' has {len(other)} format specifier(s) "
                f"(expected {len(ref)}): ref={ref}  got={other}"
            )
        elif ref != other:
            errors.append(
                f"{lang_code}: key '{key}' specifiers differ: "
                f"ref={ref}  got={other}"
            )
    return errors


# ── Unicode escape validation ────────────────────────────────────────────────

UNICODE_ESC_RE = re.compile(r"\\u[0-9a-fA-F]{4}")

def check_unicode_escapes(text: str, path: str) -> list[str]:
    """Verify every \\uXXXX in *text* encodes a valid Unicode scalar value."""
    errors = []
    for m in UNICODE_ESC_RE.finditer(text):
        cp = int(m.group()[2:], 16)
        # surrogate halves are invalid in JSON strings, as are out-of-range
        if 0xD800 <= cp <= 0xDFFF:
            errors.append(f"{path}: invalid surrogate \\u{m.group()[2:]} in value")
        elif cp > 0x10FFFF:
            errors.append(f"{path}: out-of-range code point \\u{m.group()[2:]}")
    return errors


def check_manifest(locales_dir: Path, locale_files: list[str]) -> list[str]:
    """Verify manifest.json tracks every locale file with current size/hash."""
    path = locales_dir / "manifest.json"
    if not path.exists():
        return ["manifest.json: missing remote locale manifest"]

    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"manifest.json: parse error: {exc}"]
    except OSError as exc:
        return [f"manifest.json: read error: {exc}"]

    if not isinstance(manifest, dict):
        return ["manifest.json: top-level value is not an object"]
    languages = manifest.get("languages")
    if not isinstance(languages, list):
        return ["manifest.json: languages is not an array"]

    expected = {Path(name).stem: name for name in locale_files}
    seen: set[str] = set()
    errors: list[str] = []
    for entry in languages:
        if not isinstance(entry, dict):
            errors.append("manifest.json: language entry is not an object")
            continue
        code = entry.get("code")
        filename = entry.get("filename")
        if not isinstance(code, str) or not isinstance(filename, str):
            errors.append("manifest.json: language entry missing code or filename")
            continue
        seen.add(code)
        if expected.get(code) != filename:
            errors.append(f"manifest.json: {code} filename mismatch")
            continue
        raw = (locales_dir / filename).read_bytes()
        if entry.get("size") != len(raw):
            errors.append(f"manifest.json: {filename} size is stale")
        if entry.get("sha256") != hashlib.sha256(raw).hexdigest():
            errors.append(f"manifest.json: {filename} sha256 is stale")
        if entry.get("embedded") != (code == "en"):
            errors.append(f"manifest.json: {code} embedded flag is wrong")

    for code in sorted(set(expected) - seen):
        errors.append(f"manifest.json: missing language '{code}'")
    for code in sorted(seen - set(expected)):
        errors.append(f"manifest.json: extra language '{code}'")
    return errors


def check_source_references(locales_dir: Path, reference: dict) -> list[str]:
    """Verify every literal locale lookup in frontend/src exists in en.json."""
    source_dir = locales_dir.parent / "src"
    if not source_dir.is_dir():
        return []

    referenced: dict[str, list[str]] = defaultdict(list)
    for path in source_dir.rglob("*"):
        if path.suffix not in {".c", ".cpp", ".h", ".hpp", ".mm"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            return [f"{path}: read error while checking locale references: {exc}"]
        for match in SOURCE_LOCALE_RE.finditer(text):
            referenced[match.group(1)].append(
                str(path.relative_to(source_dir.parent))
            )

    errors = []
    for key in sorted(set(referenced) - set(reference)):
        locations = ", ".join(sorted(set(referenced[key])))
        errors.append(
            f"en.json: missing source-referenced key '{key}' ({locations})"
        )
    return errors


# ── main validation ──────────────────────────────────────────────────────────

def validate(locales_dir: Path) -> int:
    """Run all checks.  Return 0 on success, 1 on failure."""
    json_files = sorted(
        fp for fp in locales_dir.glob("*.json")
        if fp.name != "manifest.json"
    )
    if not json_files:
        print(red("ERROR:"), f"No JSON files found in {locales_dir}")
        return 1

    # ── 1. Parse all files ───────────────────────────────────────────────
    parsed: dict[str, dict] = {}
    parse_errors: list[str] = []

    for fp in json_files:
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            parse_errors.append(f"{fp.name}: parse error: {exc}")
            continue
        except OSError as exc:
            parse_errors.append(f"{fp.name}: read error: {exc}")
            continue

        if not isinstance(data, dict):
            parse_errors.append(f"{fp.name}: top-level value is not an object")
            continue

        # strip _meta key — it is per‑language metadata, not translatable keys
        data.pop("_meta", None)
        parsed[fp.name] = data

    if parse_errors:
        for e in parse_errors:
            print(red("PARSE ERROR:"), e)
        print()
        print(red(f"  {len(parse_errors)} file(s) could not be parsed."))
        return 1

    langs = sorted(parsed.keys())
    print(f"  Loaded {len(langs)} locale(s): {', '.join(langs)}")

    ref_name = "en.json"
    if ref_name not in parsed:
        print(red("ERROR:"), f"Reference file '{ref_name}' not found.")
        return 1

    ref_keys = set(parsed[ref_name].keys())
    errors: list[str] = []

    # ── 2. Key coverage ──────────────────────────────────────────────────
    for lang_file in langs:
        lang_keys = set(parsed[lang_file].keys())

        missing = ref_keys - lang_keys
        extra = lang_keys - ref_keys

        for k in sorted(missing):
            errors.append(f"{lang_file}: missing key '{k}'")
        for k in sorted(extra):
            errors.append(f"{lang_file}: extra key '{k}' (not in en.json)")

    # ── 3. Unicode escape validation ─────────────────────────────────────
    for lang_file in langs:
        for key, value in parsed[lang_file].items():
            if isinstance(value, str):
                errors.extend(check_unicode_escapes(value, f"{lang_file}:{key}"))

    # ── 4. Format specifier consistency ──────────────────────────────────
    ref_specs = {k: extract_specifiers(v) for k, v in parsed[ref_name].items() if isinstance(v, str)}
    for lang_file in langs:
        if lang_file == ref_name:
            continue
        lang_specs = {
            k: extract_specifiers(v)
            for k, v in parsed[lang_file].items()
            if isinstance(v, str)
        }
        errors.extend(check_format_consistency(ref_specs, lang_specs, lang_file))

    # ── 5. Empty / whitespace-only values ────────────────────────────────
    for lang_file in langs:
        for key, value in parsed[lang_file].items():
            if isinstance(value, str) and not value.strip():
                errors.append(f"{lang_file}: key '{key}' is empty or whitespace-only")

    # ── 6. Remote manifest consistency ───────────────────────────────────
    errors.extend(check_manifest(locales_dir, langs))

    # Literal source references must exist in the English catalog.
    errors.extend(check_source_references(locales_dir, parsed[ref_name]))

    # ── 7. Report ────────────────────────────────────────────────────────
    print()

    if errors:
        for e in errors:
            print(yellow("ISSUE:"), e)
        print()
        print(red(f"  {len(errors)} validation issue(s) found across {len(langs)} locale(s)."))
        return 1

    print(green(f"  All {len(langs)} locale(s) passed validation ({len(ref_keys)} keys)."))
    return 0


# ── entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate MemDBG locale JSON files."
    )
    parser.add_argument(
        "--locales-dir",
        default=None,
        help="Path to the locales directory (default: frontend/locales relative to repo root).",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    locales_dir = Path(args.locales_dir) if args.locales_dir else (repo_root / "frontend" / "locales")

    if not locales_dir.is_dir():
        print(red("ERROR:"), f"Locales directory not found: {locales_dir}")
        return 1

    print(f"MemDBG Locale Validator")
    print(f"  Directory: {locales_dir}")
    return validate(locales_dir)


if __name__ == "__main__":
    sys.exit(main())
