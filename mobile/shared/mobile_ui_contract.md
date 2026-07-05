# Mobile UI Contract

Mobile screens must keep the same product vocabulary as the desktop app while
avoiding desktop-only layout assumptions.

## Global Rules

- Primary navigation is a bottom tab bar.
- Secondary actions open as sheets.
- Long-running operations show progress and remain cancellable.
- Network operations never block the UI thread.
- Text uses stable sizes per density bucket; do not scale fonts with viewport
  width.
- Debugger editing actions require a confirmation sheet when they write memory,
  change protection, or alter thread execution.
- The frontend owns the layout in dp; the native shell forwards the device safe
  area every frame via `set_mobile_safe_area(left, top, right, bottom)` (iOS
  uses `safeAreaInsets`, Android uses `WindowInsets` systemBars + displayCutout).
- Touch input is mapped to a single ImGui pointer with the left mouse button
  held while the user is touching; both iOS and Android forward raw dp
  coordinates (no framebuffer-scale doubling).

## Required Screens

| Screen | Required controls |
|---|---|
| Session | Target selector, connect/disconnect, ping, payload version, UDP log toggle. |
| Processes | Search, process list, process details, maps, dump selected map. |
| Memory | Address input, size stepper, read/write, hex inspector, protection badge. |
| Scanner | Scan type picker, value input, refinement controls, hit list, pin to trainer. |
| Debugger | Attach/detach, stop/continue/step, thread picker, registers, disassembly. |
| Trainer | Cheat list, enable/disable, lock interval, import/export. |
| Plugins | Installed plugin apps, run status, plugin settings. |

## Debugger Actions

Disassembly rows must expose:

- Copy address.
- Disassemble here.
- Set or clear software breakpoint.
- Set or clear hardware breakpoint/watchpoint.
- Stage in Patch Studio.
- Bookmark in Analysis Notebook.

Stack return rows must expose:

- Disassemble return address.
- Bookmark return address.
- Stage return address as a patch.
