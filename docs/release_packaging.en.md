# Release Packaging

MemDBG release artifacts are produced by `.github/workflows/release.yml`.

| Target | Build job | Artifact |
|---|---|---|
| Linux host daemon | `host-linux` | `MemDBG-host-linux.tar.gz` |
| Linux desktop frontend | `frontend-linux` | `MemDBG-frontend-linux.tar.gz` |
| macOS host daemon | `host-macos` | `MemDBG-host-macos.tar.gz` |
| macOS desktop frontend | `frontend-macos` | `MemDBG-frontend-macos.app.zip`, `MemDBG-frontend-macos.dmg` |
| Windows desktop frontend | `frontend-windows` | `MemDBG-frontend-windows.zip` containing `.exe` files |
| PS4 payload | `payload-ps4` | `MemDBG-ps4.elf`, `libmemdbg-ps4.a` |
| PS5 payload | `payload-ps5` | `MemDBG-ps5.elf`, `libmemdbg-ps5.a` |
| iOS / iPadOS mobile | `mobile-ios` | `MemDBG-mobile-ios.ipa` (unsigned, CMake + Xcode archive) |
| Android mobile | `mobile-android` | `MemDBG-mobile-android.apk` (debug-signed release, Gradle + NDK CMake) |

The desktop frontend bundles `assets/` and `plugin-repository/` so a downloaded
app has icons and a local plugin catalog even without a network refresh.

## Nightly candidates

The release workflow runs every day at 22:00 in the `Europe/Rome` timezone.
GitHub Actions schedules both 20:00 and 21:00 UTC; a preflight converts each
nominal schedule to Rome time and permits exactly one matrix build through, so
CET and CEST transitions do not duplicate or skip a nightly.

Each successful nightly is an immutable historical release tagged
`nightly-YYYYMMDD-gSHA` and titled `nightly [YYYY-MM-DD-gSHA]`. The date is the
Rome calendar date and `SHA` is the lowercase seven-character commit ID. The
SHA is automatically lengthened only if Git detects an abbreviation collision.
The artifact payload version remains independent in the form
`0.2.0-nightly.<run>.g<commit>`, and release notes link to the exact commit and
workflow run. Manual nightlies use the same identity format; official tag and
manual releases retain their `v<version>` identity.

The first publication creates the tag without force and uploads assets without
`--clobber`. A rerun for the same date and commit verifies the existing title,
tag target, asset names, and the checksums of the already-published assets, then
exits without mutation. It does not compare freshly rebuilt archives, whose
container metadata may differ. A tag collision or inconsistent release state
fails clearly.

A newly published nightly is marked Latest. A subsequently published stable
official release becomes Latest, while official prereleases do not; the next new
nightly becomes Latest again. Rerunning an older nightly never changes this
ordering. Historical nightlies and official releases remain accessible
snapshots.

Linux currently ships a `.tar.gz` bundle with a `.desktop` file and hicolor icon
data. AppImage can be added later once the runtime dependency bundle is stable
enough to avoid surprising users on older distributions.

### Mobile signing notes

- The iOS `.ipa` is produced with `CODE_SIGNING_ALLOWED=NO` so the CI build does
  not require Apple secrets. Pass `-DIOS_SIGNING_TEAM=<TeamID>` to the CMake
  configure step and supply a matching signing identity in Xcode for signed
  device or TestFlight builds.
- The Android `.apk` is signed with the debug keystore by default so it is
  installable out of the box (`adb install -r`). Replace the release
  `signingConfig` in `mobile/android/app/build.gradle.kts` with a real upload
  keystore (plus Play `*.aab` output) for distribution.
