// MemDBG - iOS software keyboard bridge for ImGui text input.
// Copyright (C) 2026 SeregonWar
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from Ghostpad (https://github.com/AssPayload/Ghostpad)
// which demonstrated the UIKeyInput approach for Dear ImGui on iOS.

#import <TargetConditionals.h>

#if TARGET_OS_IOS
#import <UIKit/UIKit.h>
#ifdef __cplusplus
extern "C" {
#endif

/// Install an invisible UIKeyInput view into the host view hierarchy.
/// Must be called once after the root view is available (e.g. in viewDidLoad).
void ImGuiInstallIOSKeyboardBridge(UIView *hostView);

/// Synchronize the native iOS keyboard visibility with ImGui's
/// io.WantTextInput flag.  Call once per frame from the render loop.
void ImGuiUpdateIOSKeyboardBridge(void);

#ifdef __cplusplus
}
#endif

#else // !TARGET_OS_IOS — no-op stubs for non-iOS builds

#ifdef __cplusplus
extern "C" {
#endif
static inline void ImGuiInstallIOSKeyboardBridge(void* /*hostView*/) {}
static inline void ImGuiUpdateIOSKeyboardBridge(void) {}
#ifdef __cplusplus
}
#endif

#endif // TARGET_OS_IOS
