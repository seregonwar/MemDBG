#!/usr/bin/env python3
"""Resolve immutable MemDBG release identities and publication actions."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
from zoneinfo import ZoneInfo

from resolve_build_version import resolve_version


ROME = ZoneInfo("Europe/Rome")
NIGHTLY_SCHEDULES = frozenset({"0 20 * * *", "0 21 * * *"})
SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


@dataclass(frozen=True)
class ReleaseIdentity:
    should_run: bool
    nightly: bool
    version: str
    tag: str
    title: str
    stable: bool


def parse_utc_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid UTC date/time: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"UTC date/time must include a timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def short_sha(sha: str) -> str:
    if not SHA_RE.fullmatch(sha):
        raise ValueError(f"invalid release commit SHA: {sha!r}")
    return sha[:7].lower()


def release_sha(sha: str, abbreviated_sha: str) -> str:
    full = sha.lower()
    short_sha(full)
    if not abbreviated_sha:
        return short_sha(full)
    abbreviated = abbreviated_sha.lower()
    if not SHA_RE.fullmatch(abbreviated) or not full.startswith(abbreviated):
        raise ValueError(
            f"invalid abbreviated commit SHA {abbreviated_sha!r} for {sha!r}"
        )
    return abbreviated


def scheduled_rome_datetime(now: datetime, schedule: str) -> datetime:
    if schedule not in NIGHTLY_SCHEDULES:
        raise ValueError(f"unsupported nightly schedule: {schedule!r}")
    minute, hour, _, _, _ = schedule.split()
    nominal_utc = datetime(
        now.year,
        now.month,
        now.day,
        int(hour),
        int(minute),
        tzinfo=timezone.utc,
    )
    if nominal_utc > now:
        nominal_utc -= timedelta(days=1)
    return nominal_utc.astimezone(ROME)


def resolve_identity(
    *,
    version_file: Path,
    event: str,
    ref_type: str,
    ref_name: str,
    input_version: str,
    nightly: bool,
    run_number: str,
    sha: str,
    abbreviated_sha: str,
    now: str,
    schedule: str,
) -> ReleaseIdentity:
    parsed_now = parse_utc_datetime(now)
    version = resolve_version(
        version_file=version_file,
        event=event,
        ref_type=ref_type,
        ref_name=ref_name,
        input_version=input_version,
        nightly=nightly,
        run_number=run_number,
        sha=sha,
    )

    if nightly:
        if event == "schedule":
            local = scheduled_rome_datetime(parsed_now, schedule)
            should_run = local.hour == 22 and local.minute == 0
        else:
            if event != "workflow_dispatch":
                raise ValueError("nightly builds must be scheduled or manually dispatched")
            if schedule:
                raise ValueError("manual nightly builds cannot specify a cron schedule")
            local = parsed_now.astimezone(ROME)
            should_run = True

        abbreviated_sha = release_sha(sha, abbreviated_sha)
        date_compact = local.strftime("%Y%m%d")
        date_display = local.strftime("%Y-%m-%d")
        return ReleaseIdentity(
            should_run=should_run,
            nightly=True,
            version=version,
            tag=f"nightly-{date_compact}-g{abbreviated_sha}",
            title=f"nightly [{date_display}-g{abbreviated_sha}]",
            stable=False,
        )

    if schedule:
        raise ValueError("official releases cannot specify a nightly cron schedule")
    if event == "workflow_dispatch":
        tag = f"v{version}"
    elif ref_type == "tag":
        tag = ref_name
        if tag != f"v{version}":
            raise ValueError(f"official release tag must be canonical: {tag!r}")
    else:
        raise ValueError("official releases must use a v* tag or manual dispatch")

    return ReleaseIdentity(
        should_run=True,
        nightly=False,
        version=version,
        tag=tag,
        title=f"MemDBG {tag}",
        stable="-" not in version.split("+", 1)[0],
    )


def resolve_publication_action(
    *, expected_sha: str, tag_sha: str, release_exists: bool
) -> str:
    expected = expected_sha.lower()
    short_sha(expected)
    if tag_sha:
        actual = tag_sha.lower()
        short_sha(actual)
        if actual != expected:
            raise ValueError(
                "nightly tag already points to a different commit: "
                f"expected {short_sha(expected)}, found {short_sha(actual)}"
            )
        return "verify" if release_exists else "create-release"
    if release_exists:
        raise ValueError("nightly release exists without its immutable git tag")
    return "create-tag-and-release"


def identity_command(args: argparse.Namespace) -> int:
    identity = resolve_identity(
        version_file=args.version_file,
        event=args.event,
        ref_type=args.ref_type,
        ref_name=args.ref_name,
        input_version=args.input_version,
        nightly=args.nightly,
        run_number=args.run_number,
        sha=args.sha,
        abbreviated_sha=args.short_sha,
        now=args.now,
        schedule=args.schedule,
    )
    print(f"should_run={str(identity.should_run).lower()}")
    print(f"nightly={str(identity.nightly).lower()}")
    print(f"version={identity.version}")
    print(f"tag={identity.tag}")
    print(f"title={identity.title}")
    print(f"stable={str(identity.stable).lower()}")
    return 0


def publication_command(args: argparse.Namespace) -> int:
    print(
        resolve_publication_action(
            expected_sha=args.expected_sha,
            tag_sha=args.tag_sha,
            release_exists=args.release_exists,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("identity")
    identity.add_argument("--version-file", type=Path, default=Path("VERSION"))
    identity.add_argument("--event", required=True)
    identity.add_argument("--ref-type", default="")
    identity.add_argument("--ref-name", default="")
    identity.add_argument("--input-version", default="")
    identity.add_argument("--nightly", action="store_true")
    identity.add_argument("--run-number", default="")
    identity.add_argument("--sha", required=True)
    identity.add_argument("--short-sha", default="")
    identity.add_argument("--now", required=True)
    identity.add_argument("--schedule", default="")
    identity.set_defaults(handler=identity_command)

    publication = subparsers.add_parser("publication")
    publication.add_argument("--expected-sha", required=True)
    publication.add_argument("--tag-sha", default="")
    publication.add_argument("--release-exists", action="store_true")
    publication.set_defaults(handler=publication_command)

    args = parser.parse_args()
    try:
        return args.handler(args)
    except (OSError, IndexError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
