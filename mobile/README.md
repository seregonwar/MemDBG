# MemDBG Mobile

This directory contains the mobile product scaffold for iOS, iPadOS, and
Android. The intent is to share MemDBG's protocol, trainer, scanner, locale, and
plugin catalog logic while giving mobile users a native touch-first shell.

Current status:

- iOS / iPadOS shell is implemented with Metal + Dear ImGui (see `ios/`).
  The `mobile-ios` CI job generates the Xcode project via CMake and produces an
  unsigned `.ipa`.
- Android renderer target: OpenGL ES 3 through the NDK first, Vulkan later.
  The `mobile-android` CI job stays disabled until the Gradle project is added.
- Mobile UI is specified in `docs/mobile_architecture.md`.

Directory layout:

```text
mobile/
├── android/
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

The first implementation milestone is a read-only session browser on both
platforms: connect, list processes, list maps, inspect memory, and open UDP
logs. The second milestone adds scanner/trainer flows. The third milestone adds
debugger attach, disassembly actions, Patch Studio, and Analysis Notebook.
