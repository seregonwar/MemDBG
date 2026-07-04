# iOS and iPadOS Shell

The iOS shell should be a native Xcode app target named `MemDBGMobile`.

Planned stack:

- Swift or Objective-C app lifecycle.
- `MTKView` for the render surface.
- Dear ImGui Metal backend for immediate-mode debugger panels.
- Shared C++ static library for MemDBG protocol/client modules.
- Keychain-backed target presets for console IPs and ports.

Release workflow expectation:

```sh
xcodebuild \
  -project mobile/ios/MemDBG.xcodeproj \
  -scheme MemDBGMobile \
  -configuration Release \
  -sdk iphoneos \
  -archivePath build/ios/MemDBG.xcarchive \
  CODE_SIGNING_ALLOWED=NO \
  archive
```

The CI job wraps the archived `.app` into an unsigned `.ipa` artifact. Signed
distribution can be added later through repository secrets and an Apple
Developer certificate.
