# MemDBG Mobile Architecture

MemDBG mobile starts from the existing desktop product, but the interaction
model is different: touch first, fewer always-visible panes, and a debugger
layout that can be operated with one hand during live console sessions.

## Platform Strategy

| Platform | Renderer | Native Shell | Package | Status |
|---|---|---|---|---|
| iOS / iPadOS | Metal | CMake → Xcode app target with `MTKView` (`UIViewController`) | `.ipa` | Implemented |
| Android | OpenGL ES 3 (Vulkan later) | Gradle + NDK CMake + Kotlin activity + `GLSurfaceView` (`libmemdbg.so`) | `.apk` (later `.aab`) | Implemented |
| Desktop | OpenGL 3 via GLFW | Existing CMake frontend | `.exe`, `.dmg`, `.tar.gz` | Implemented |

Metal is the right first-class path for iPhone and iPad because it gives
predictable frame pacing and crisp text on Apple displays. Android cannot use
Metal, so the first portable target should be an NDK renderer that reuses Dear
ImGui with OpenGL ES 3. Vulkan can follow once the app shell is stable.

## Shared Code

The mobile apps reuse these desktop modules directly via the same CMake source
list used by the iOS shell:

- `frontend/src/core/client`: MDBG protocol client and async-safe host calls.
- `frontend/src/trainer`: trainer import/export and batchcode parsing.
- `frontend/src/scanner`: auto-search heuristics and structure comparison.
- `frontend/src/locale`: translation repository and locale selection.
- `frontend/src/plugins/repository`: catalog parsing, install metadata, and
  the **embedded Lua 5.4 runtime** (`MEMDBG_ENABLE_EMBEDDED_LUA`) so plugins
  run on-device without an external interpreter.
- `frontend/src/app/shell/memdbg_app.cpp`: `draw_mobile_app()` and
  `set_mobile_safe_area()` drive the touch layout on both platforms.

Desktop-only UI paths (GLFW window, `imgui_impl_glfw`, `std::system`/`popen`
plugin hosting) are gated out by the `MEMDBG_PLATFORM_IOS` guard, which both
the iOS CMake and the Android NDK CMake define on the shared frontend sources.
A follow-up refactor can promote that to a `MEMDBG_PLATFORM_MOBILE` umbrella.

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

The release workflow (`.github/workflows/release.yml`) packages desktop, iOS,
and Android builds on every tag (`v*`) or manual `workflow_dispatch`:

- `mobile-ios` — CMake (Xcode generator) + `xcodebuild archive`, emits an
  unsigned `.ipa` at `dist/MemDBG-mobile-ios.ipa`.
- `mobile-android` — Gradle wrapper (`mobile/android/gradlew`) + NDK CMake,
  emits a release `.apk` at `dist/` (debug-signed so it installs out of the
  box). The job installs `ndk;26.1.10909125` and `cmake;3.22.1` via
  `sdkmanager` before building.

Both mobile jobs were previously guarded by a `gradlew` / Xcode project probe
and skipped with a clear message; the probes now resolve to the real projects
and the jobs build unconditionally on tag/manual dispatch.
