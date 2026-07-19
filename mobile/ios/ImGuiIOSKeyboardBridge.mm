// MemDBG - iOS software keyboard bridge for ImGui text input.
// Copyright (C) 2026 SeregonWar
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from Ghostpad (https://github.com/AssPayload/Ghostpad)
// which demonstrated the UIKeyInput approach for Dear ImGui on iOS.
//
// This creates an invisible UIView that conforms to UIKeyInput and
// becomes/resigns first responder in sync with io.WantTextInput,
// summoning and dismissing the native iOS software keyboard.

#import "ImGuiIOSKeyboardBridge.h"

#if TARGET_OS_IOS

#import <UIKit/UIKit.h>
#include "imgui.h"

// ---- Private UIKeyInput view ------------------------------------------------

@interface MemDBGTextInputView : UIView <UIKeyInput>
@end

static MemDBGTextInputView *gInputView = nil;
static BOOL gKeyboardVisible = NO;

@implementation MemDBGTextInputView

- (BOOL)canBecomeFirstResponder { return YES; }

// UIKeyInput protocol
- (BOOL)hasText { return NO; }

- (void)insertText:(NSString *)text {
    ImGuiIO &io = ImGui::GetIO();
    const char *utf8 = [text UTF8String];
    if (utf8) {
        io.AddInputCharactersUTF8(utf8);
    }

    // Special-case Return → Enter key
    if ([text isEqualToString:@"\n"]) {
        io.AddKeyEvent(ImGuiKey_Enter, true);
        io.AddKeyEvent(ImGuiKey_Enter, false);
    }
}

- (void)deleteBackward {
    ImGuiIO &io = ImGui::GetIO();
    io.AddKeyEvent(ImGuiKey_Backspace, true);
    io.AddKeyEvent(ImGuiKey_Backspace, false);
}

// Paste support
- (BOOL)canPerformAction:(SEL)action withSender:(id)sender {
    return action == @selector(paste:);
}

- (void)paste:(id)sender {
    NSString *s = UIPasteboard.generalPasteboard.string;
    if (s.length > 0) {
        ImGui::GetIO().AddInputCharactersUTF8(s.UTF8String);
    }
}

@end

// ---- Public bridge API -------------------------------------------------------

void ImGuiInstallIOSKeyboardBridge(UIView *hostView) {
    if (!hostView) return;
    if (!gInputView) {
        gInputView = [[MemDBGTextInputView alloc] initWithFrame:CGRectMake(0, 0, 0, 0)];
        gInputView.userInteractionEnabled = NO;  // invisible, not intercepting touches
        gInputView.backgroundColor = UIColor.clearColor;
        [hostView addSubview:gInputView];
    }
}

void ImGuiUpdateIOSKeyboardBridge(void) {
    if (!gInputView) return;
    ImGuiIO &io = ImGui::GetIO();
    BOOL want = io.WantTextInput ? YES : NO;

    if (want && !gKeyboardVisible) {
        gKeyboardVisible = YES;
        dispatch_async(dispatch_get_main_queue(), ^{
            [gInputView becomeFirstResponder];
        });
    } else if (!want && gKeyboardVisible) {
        gKeyboardVisible = NO;
        dispatch_async(dispatch_get_main_queue(), ^{
            [gInputView resignFirstResponder];
        });
    }
}

#endif // TARGET_OS_IOS
