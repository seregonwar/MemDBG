#!/usr/bin/env python3

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from resolve_build_version import resolve_version


class ResolveBuildVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.version_file = Path(self.temp_dir.name) / "VERSION"
        self.version_file.write_text("0.2.0-beta.2\n", encoding="utf-8")

    def resolve(self, **overrides: object) -> str:
        values: dict[str, object] = {
            "version_file": self.version_file,
            "event": "push",
            "ref_type": "branch",
            "ref_name": "main",
            "input_version": "",
            "nightly": False,
            "run_number": "321",
            "sha": "d791061a47298febe58f9e08678ab487f009044a",
        }
        values.update(overrides)
        return resolve_version(**values)  # type: ignore[arg-type]

    def test_checked_in_version_is_used_for_normal_builds(self) -> None:
        self.assertEqual(self.resolve(), "0.2.0-beta.2")

    def test_tag_is_canonical_for_official_release(self) -> None:
        self.assertEqual(
            self.resolve(ref_type="tag", ref_name="v0.2.0-beta.3"),
            "0.2.0-beta.3",
        )

    def test_manual_release_uses_input_version(self) -> None:
        self.assertEqual(
            self.resolve(event="workflow_dispatch", input_version="v0.3.0-rc.1"),
            "0.3.0-rc.1",
        )

    def test_nightly_has_independent_run_and_commit_identity(self) -> None:
        self.assertEqual(
            self.resolve(nightly=True),
            "0.2.0-nightly.321.gd791061",
        )

    def test_manual_official_release_requires_a_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "release version is required"):
            self.resolve(event="workflow_dispatch")


if __name__ == "__main__":
    unittest.main()
