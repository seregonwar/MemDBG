# MemDBG Mobile

This directory contains the mobile product for iOS, iPadOS, and Android. The
intent is to share MemDBG's protocol, trainer, scanner, locale, and plugin
catalog logic while giving mobile users a native touch-first shell.

Current status:

- iOS / iPadOS shell is implemented with Metal + Dear ImGui (see `ios/`).
  The `mobile-ios` CI job generates the Xcode project via CMake and produces an
  unsigned `.ipa`.
- Android shell is implemented with OpenGL ES 3 + Dear ImGui through an NDK
  CMake library loaded by a Kotlin `GLSurfaceView` activity (see `android/`).
  The `mobile-android` CI job runs `./gradlew --no-daemon assembleRelease` and
  produces a debug-signed release `.apk`.
- Both shells reuse the same `draw_mobile_app()` touch layout, forward system
  safe areas via `set_mobile_safe_area()`, and run the same embedded Lua 5.4
  plugin runtime (`MEMDBG_ENABLE_EMBEDDED_LUA`) as the desktop build.
- Mobile UI is specified in `docs/mobile_architecture.md` and
  `mobile/shared/mobile_ui_contract.md`.

Directory layout:

```text
mobile/
├── android/
│   ├── settings.gradle.kts / build.gradle.kts / gradlew
│   ├── app/
│   │   ├── build.gradle.kts
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       ├── cpp/CMakeLists.txt + native_android.cpp
│   │       ├── java/.../ MainActivity.kt, MemDBGGLSurfaceView.kt,
│   │       │                 MemDBGRenderer.kt, MemDBGJNI.kt
│   │       └── res/values/{strings,themes}.xml
│   └── README.md
├── ios/
│   ├── CMakeLists.txt
│   ├── main.ios.mm
│   ├── AppDelegate.h / .mm
│   ├── ViewController.h / .mm
│   ├── Info.plist
│   ├── LaunchScreen.storyboard
│   └── README.md
└── shared/
    └── mobile_ui_contract.md
```

The mobile shells are feature-equivalent to the desktop frontend for the
session/process/map/scanner/trainer/plugin/log workflows. Debugger attach
flows are available through the same shared screens; detailed mobile debugger
drilldown (Patch Studio, Analysis Notebook) continues to be tracked under the
shared UI contract.
