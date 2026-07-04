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
| iOS / iPadOS mobile | `mobile-ios` | `.ipa` when the Xcode project is present |
| Android mobile | `mobile-android` | `.apk` when the Gradle project is present |

The desktop frontend bundles `assets/` and `plugin-repository/` so a downloaded
app has icons and a local plugin catalog even without a network refresh.

Linux currently ships a `.tar.gz` bundle with a `.desktop` file and hicolor icon
data. AppImage can be added later once the runtime dependency bundle is stable
enough to avoid surprising users on older distributions.
