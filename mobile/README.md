# MemDBG Mobile

This directory contains the mobile product scaffold for iOS, iPadOS, and
Android. The intent is to share MemDBG's protocol, trainer, scanner, locale, and
plugin catalog logic while giving mobile users a native touch-first shell.

Current status:

- iOS / iPadOS renderer target: Metal.
- Android renderer target: OpenGL ES 3 through the NDK first, Vulkan later.
- Mobile CI jobs are wired in the release workflow and activate when native
  project files are added.
- Mobile UI is specified in `docs/mobile_architecture.md`.

Directory layout:

```text
mobile/
├── android/
│   └── README.md
├── ios/
│   └── README.md
└── shared/
    └── mobile_ui_contract.md
```

The first implementation milestone is a read-only session browser on both
platforms: connect, list processes, list maps, inspect memory, and open UDP
logs. The second milestone adds scanner/trainer flows. The third milestone adds
debugger attach, disassembly actions, Patch Studio, and Analysis Notebook.
