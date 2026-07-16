#!/usr/bin/env python3

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from resolve_release_identity import (
    parse_utc_datetime,
    resolve_identity,
    resolve_publication_action,
    scheduled_rome_datetime,
)


class ResolveReleaseIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.version_file = Path(self.temp_dir.name) / "VERSION"
        self.version_file.write_text("0.2.0-beta.2\n", encoding="utf-8")

    def resolve(self, **overrides: object):
        values: dict[str, object] = {
            "version_file": self.version_file,
            "event": "workflow_dispatch",
            "ref_type": "branch",
            "ref_name": "main",
            "input_version": "",
            "nightly": True,
            "run_number": "321",
            "sha": "D791061A47298FEBE58F9E08678AB487F009044A",
            "abbreviated_sha": "",
            "now": "2026-07-16T20:00:00Z",
            "schedule": "",
        }
        values.update(overrides)
        return resolve_identity(**values)  # type: ignore[arg-type]

    def test_manual_nightly_uses_rome_date_tag_and_exact_title(self) -> None:
        identity = self.resolve()
        self.assertTrue(identity.should_run)
        self.assertEqual(identity.tag, "nightly-20260716-gd791061")
        self.assertEqual(identity.title, "nightly [2026-07-16-gd791061]")
        self.assertEqual(identity.version, "0.2.0-nightly.321.gd791061")

    def test_manual_nightly_date_crosses_utc_midnight_in_rome(self) -> None:
        identity = self.resolve(now="2026-07-16T22:30:00Z")
        self.assertEqual(identity.tag, "nightly-20260717-gd791061")
        self.assertEqual(identity.title, "nightly [2026-07-17-gd791061]")

    def test_git_can_supply_a_longer_collision_safe_sha(self) -> None:
        identity = self.resolve(abbreviated_sha="D791061A")
        self.assertEqual(identity.tag, "nightly-20260716-gd791061a")
        self.assertEqual(identity.title, "nightly [2026-07-16-gd791061a]")

    def test_abbreviated_sha_must_match_the_commit(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid abbreviated"):
            self.resolve(abbreviated_sha="abcdef0")

    def test_winter_uses_the_21_utc_schedule(self) -> None:
        active = self.resolve(
            event="schedule",
            now="2026-01-15T21:05:00Z",
            schedule="0 21 * * *",
        )
        duplicate = self.resolve(
            event="schedule",
            now="2026-01-15T20:05:00Z",
            schedule="0 20 * * *",
        )
        self.assertTrue(active.should_run)
        self.assertFalse(duplicate.should_run)
        self.assertEqual(active.tag, "nightly-20260115-gd791061")

    def test_summer_uses_the_20_utc_schedule(self) -> None:
        active = self.resolve(
            event="schedule",
            now="2026-07-16T20:05:00Z",
            schedule="0 20 * * *",
        )
        duplicate = self.resolve(
            event="schedule",
            now="2026-07-16T21:05:00Z",
            schedule="0 21 * * *",
        )
        self.assertTrue(active.should_run)
        self.assertFalse(duplicate.should_run)

    def test_delayed_schedule_after_midnight_uses_nominal_occurrence(self) -> None:
        identity = self.resolve(
            event="schedule",
            now="2026-01-16T00:15:00Z",
            schedule="0 21 * * *",
        )
        self.assertTrue(identity.should_run)
        self.assertEqual(identity.tag, "nightly-20260115-gd791061")
        self.assertEqual(identity.title, "nightly [2026-01-15-gd791061]")

    def test_dst_transition_days_still_select_exactly_one_schedule(self) -> None:
        spring = [
            scheduled_rome_datetime(
                datetime(2026, 3, 29, 23, tzinfo=timezone.utc), schedule
            ).hour
            == 22
            for schedule in ("0 20 * * *", "0 21 * * *")
        ]
        autumn = [
            scheduled_rome_datetime(
                datetime(2026, 10, 25, 23, tzinfo=timezone.utc), schedule
            ).hour
            == 22
            for schedule in ("0 20 * * *", "0 21 * * *")
        ]
        self.assertEqual(spring.count(True), 1)
        self.assertEqual(autumn.count(True), 1)

    def test_invalid_sha_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid"):
            self.resolve(sha="not-a-sha")

    def test_invalid_date_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid UTC date/time"):
            self.resolve(now="2026-02-30T20:00:00Z")

    def test_date_requires_timezone(self) -> None:
        with self.assertRaisesRegex(ValueError, "must include a timezone"):
            parse_utc_datetime("2026-07-16T20:00:00")

    def test_unknown_schedule_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported nightly schedule"):
            self.resolve(event="schedule", schedule="17 3 * * *")

    def test_official_tag_is_separate_from_nightly_identity(self) -> None:
        identity = self.resolve(
            event="push",
            ref_type="tag",
            ref_name="v0.2.0-beta.3",
            input_version="",
            nightly=False,
            schedule="",
        )
        self.assertEqual(identity.tag, "v0.2.0-beta.3")
        self.assertEqual(identity.title, "MemDBG v0.2.0-beta.3")
        self.assertFalse(identity.stable)

    def test_manual_stable_release_is_latest_eligible(self) -> None:
        identity = self.resolve(
            input_version="v0.3.0",
            nightly=False,
            schedule="",
        )
        self.assertEqual(identity.tag, "v0.3.0")
        self.assertTrue(identity.stable)

    def test_manual_nightly_ignores_official_version_input(self) -> None:
        identity = self.resolve(input_version="v9.9.9")
        self.assertTrue(identity.nightly)
        self.assertTrue(identity.version.startswith("0.2.0-nightly."))

    def test_first_publication_creates_tag_and_release(self) -> None:
        self.assertEqual(
            resolve_publication_action(
                expected_sha="d791061a47298febe58f9e08678ab487f009044a",
                tag_sha="",
                release_exists=False,
            ),
            "create-tag-and-release",
        )

    def test_interrupted_publication_can_create_release_for_matching_tag(self) -> None:
        self.assertEqual(
            resolve_publication_action(
                expected_sha="d791061a47298febe58f9e08678ab487f009044a",
                tag_sha="d791061a47298febe58f9e08678ab487f009044a",
                release_exists=False,
            ),
            "create-release",
        )

    def test_rerun_verifies_without_mutation(self) -> None:
        self.assertEqual(
            resolve_publication_action(
                expected_sha="d791061a47298febe58f9e08678ab487f009044a",
                tag_sha="D791061A47298FEBE58F9E08678AB487F009044A",
                release_exists=True,
            ),
            "verify",
        )

    def test_tag_collision_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "different commit"):
            resolve_publication_action(
                expected_sha="d791061a47298febe58f9e08678ab487f009044a",
                tag_sha="d791061fffffffffffffffffffffffffffffffff",
                release_exists=True,
            )


if __name__ == "__main__":
    unittest.main()
