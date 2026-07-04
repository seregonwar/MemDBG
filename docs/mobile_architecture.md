# MemDBG Mobile Architecture

MemDBG mobile starts from the existing desktop product, but the interaction
model is different: touch first, fewer always-visible panes, and a debugger
layout that can be operated with one hand during live console sessions.

## Platform Strategy

| Platform | Renderer | Native Shell | Package | Status |
|---|---|---|---|---|
| iOS / iPadOS | Metal | Xcode app target with `MTKView` | `.ipa` | Scaffolded |
| Android | OpenGL ES 3 first, Vulkan later | Kotlin/Java activity plus NDK CMake library | `.apk`, later `.aab` | Scaffolded |
| Desktop | OpenGL 3 via GLFW | Existing CMake frontend | `.exe`, `.dmg`, `.tar.gz` | Implemented |

Metal is the right first-class path for iPhone and iPad because it gives
predictable frame pacing and crisp text on Apple displays. Android cannot use
Metal, so the first portable target should be an NDK renderer that reuses Dear
ImGui with OpenGL ES 3. Vulkan can follow once the app shell is stable.

## Shared Code

The mobile apps should reuse these desktop modules directly:

- `frontend/src/core/client`: MDBG protocol client and async-safe host calls.
- `frontend/src/trainer`: trainer import/export and batchcode parsing.
- `frontend/src/scanner`: auto-search heuristics and structure comparison.
- `frontend/src/locale`: translation repository and locale selection.
- `frontend/src/plugins/repository`: catalog parsing and install metadata.

Desktop-only UI code stays behind the current GLFW/OpenGL shell. Mobile shells
should add a new presentation layer rather than bending the desktop sidebar into
a phone layout.

## Mobile UX Model

Use a bottom navigation bar with five primary destinations:

| Tab | Purpose |
|---|---|
| Session | Connect, target presets, process picker, payload health, UDP log state. |
| Memory | Address read/write, map browser, compact hex inspector, quick patches. |
| Scanner | Exact/unknown scan, refinement, Smart Auto-Search, hit pinning. |
| Debugger | Attach, threads, registers, disassembly, breakpoints, Patch Studio, Notebook. |
| Trainer | Cheats, locks, OFF capture, import/export, live enable/disable. |

Secondary tools such as Plugins, Logs, Telemetry, Settings, and Credits belong
in a command sheet opened from the top-right action button. This keeps the phone
layout dense without hiding core workflows.

## Debugger Mobile Layout

Debugger should be a three-level drilldown instead of desktop-style dense tabs:

1. Process attach header: PID, stopped/running state, active LWP, stop/continue.
2. Segment switcher: Threads, Registers, Code, Breakpoints, Stack, Patch, Notes.
3. Detail sheet: register editor, disassembly row actions, stack frame actions,
   or patch/notebook editor.

Patch Studio and Analysis Notebook are always available. They should not be a
separate mode on mobile; they are part of the debugger workflow.

## Rendering Quality

Both mobile shells should use one font atlas per DPI bucket, high oversampling
for Latin/Cyrillic text, merged icon glyphs, and platform text scale only at the
layout layer. Text should not be scaled directly with viewport width.

Target frame budget:

- Phone: 60 FPS while idle, 30 FPS minimum during scan progress updates.
- Tablet: 60 FPS with split debugger panes.
- All platforms: avoid blocking socket calls on the UI thread.

## CI Contract

The release workflow already packages desktop builds. Mobile jobs are wired to
look for native projects under:

- `mobile/ios/MemDBG.xcodeproj` or `mobile/ios/MemDBG.xcworkspace`
- `mobile/android/gradlew`

Until those projects exist, the mobile jobs report a clear skip message and do
not fail the release. Once the native projects land, the same workflow emits
`.ipa` and `.apk` artifacts.
