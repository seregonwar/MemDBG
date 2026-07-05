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
