#!/usr/bin/env python3
"""Resolve one canonical MemDBG version for release and nightly builds."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


VERSION_RE = re.compile(
    r"^[0-9]+(?:\.[0-9]+){1,3}(?:[.-][0-9A-Za-z][0-9A-Za-z.-]*)?$"
)


def normalize(value: str) -> str:
    return value.strip().removeprefix("v").removeprefix("V")


def resolve_version(
    *,
    version_file: Path,
    event: str,
    ref_type: str,
    ref_name: str,
    input_version: str,
    nightly: bool,
    run_number: str,
    sha: str,
) -> str:
    checked_in = normalize(version_file.read_text(encoding="utf-8").splitlines()[0])

    if nightly:
        core = checked_in.split("-", 1)[0].split("+", 1)[0]
        if not run_number.isdigit():
            raise ValueError(f"invalid nightly run number: {run_number!r}")
        if not re.fullmatch(r"[0-9a-fA-F]{7,40}", sha):
            raise ValueError(f"invalid nightly commit SHA: {sha!r}")
        version = f"{core}-nightly.{run_number}.g{sha[:7].lower()}"
    elif event == "workflow_dispatch":
        if not input_version.strip():
            raise ValueError("release version is required for a manual official build")
        version = normalize(input_version)
    elif ref_type == "tag":
        version = normalize(ref_name)
    else:
        version = checked_in

    if not VERSION_RE.fullmatch(version):
        raise ValueError(f"invalid MemDBG version: {version!r}")
    return version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version-file", type=Path, default=Path("VERSION"))
    parser.add_argument("--event", default="")
    parser.add_argument("--ref-type", default="")
    parser.add_argument("--ref-name", default="")
    parser.add_argument("--input-version", default="")
    parser.add_argument("--nightly", action="store_true")
    parser.add_argument("--run-number", default="")
    parser.add_argument("--sha", default="")
    args = parser.parse_args()

    try:
        version = resolve_version(
            version_file=args.version_file,
            event=args.event,
            ref_type=args.ref_type,
            ref_name=args.ref_name,
            input_version=args.input_version,
            nightly=args.nightly,
            run_number=args.run_number,
            sha=args.sha,
        )
    except (OSError, IndexError, ValueError) as exc:
        parser.error(str(exc))

    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
