# iOS and iPadOS Shell

Native iOS/iPadOS shell built with **CMake + Xcode + Metal + Dear ImGui**. The
shell reuses the desktop frontend's UI code (`draw_app()`) and renders through
the ImGui Metal backend (`imgui_impl_metal`).

## Stack

- CMake 3.24+ with the `Xcode` generator (an unsigned `.xcodeproj` is generated).
- Metal via `MTKView` + `MTLDevice` + `MTLCommandQueue`.
- Dear ImGui v1.90.9 with `backends/imgui_impl_metal.mm`.
- Touch input is mapped to a single left-mouse-button ImGui pointer model.
- Shared C++ static library for MemDBG protocol, scanner, trainer, locale and
  plugin catalog logic (compiled from `frontend/src`).
- Texture uploads for the desktop OpenGL path are skipped on iOS (logo, plugin
  icons and GitHub avatars render as placeholders); the Metal shell may iterate
  on real texture uploads in a later milestone.

## Local build

```sh
# Generate the Xcode project for an iOS device target.
cmake -S mobile/ios -B build/ios -G Xcode \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
  -DMEMDBG_RELEASE_VERSION=0.0.0

# Archive an unsigned bundle.
xcodebuild \
  -project build/ios/memdbg_mobile.xcodeproj \
  -scheme MemDBGMobile \
  -configuration Release \
  -sdk iphoneos \
  -archivePath build/ios/MemDBG.xcarchive \
  -derivedDataPath build/ios/derived \
  CODE_SIGNING_ALLOWED=NO \
  archive

# Wrap the archived .app into an unsigned .ipa.
app_path=$(find build/ios/MemDBG.xcarchive/Products/Applications \
  -maxdepth 1 -type d -name '*.app' -print -quit)
mkdir -p build/ios/Payload dist
cp -R "$app_path" build/ios/Payload/MemDBG.app
(cd build/ios && zip -qry "../../dist/MemDBG-mobile-ios.ipa" Payload)
```

For a signed device build, pass an Apple Developer Team ID:

```sh
cmake -S mobile/ios -B build/ios -G Xcode -DIOS_SIGNING_TEAM=YOUR_TEAM_ID \
  -DCMAKE_SYSTEM_NAME=iOS ...
```

## Release workflow

The `mobile-ios` job in `.github/workflows/release.yml` runs the CMake +
xcodebuild steps above with `CODE_SIGNING_ALLOWED=NO` and uploads the resulting
unsigned `.ipa`. Signed distribution can be added later via repository secrets
and an Apple Developer certificate.

## Files

| File | Purpose |
|---|---|
| `CMakeLists.txt` | Fetches imgui/stb/nlohmann_json, builds the Metal imgui lib and the `MemDBGMobile` app target |
| `main.ios.mm` | `UIApplicationMain` entry point |
| `AppDelegate.h` / `AppDelegate.mm` | App lifecycle, window + root view controller |
| `ViewController.h` / `ViewController.mm` | `MTKView` render surface, Metal device/queue, ImGui Metal backend, touch handling |
| `Info.plist` | Bundle metadata, orientations, Bonjour/local-network usage description |
| `LaunchScreen.storyboard` | Splash screen shown before Metal surface is ready |