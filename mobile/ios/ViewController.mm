// MemDBG - iOS shell with Metal + Dear ImGui.
// Copyright (C) 2026 SeregonWar
// SPDX-License-Identifier: GPL-3.0-or-later

#import "ViewController.h"
#import "ImGuiIOSKeyboardBridge.h"

#include "imgui.h"
#include "imgui_impl_metal.h"

#include "app/app_state.hpp"
#include "app/shell/memdbg_app.hpp"

#include <memory>

@interface ViewController ()
- (void)_applyTouchStateToImGui;
@end

@implementation ViewController {
  std::unique_ptr<memdbg::frontend::AppState> _state;
  BOOL _imguiInitialized;
  float _dpiScale;
  __strong id _primaryTouch;
}

- (void)viewDidLoad {
  [super viewDidLoad];
  _imguiInitialized = NO;
  _primaryTouch = nil;
  _dpiScale = [UIDevice currentDevice].userInterfaceIdiom == UIUserInterfaceIdiomPad
                  ? 1.08f
                  : 1.0f;

  self.device = MTLCreateSystemDefaultDevice();
  if (!self.device) {
    NSLog(@"Metal is not supported on this device");
    return;
  }
  self.commandQueue = [self.device newCommandQueue];

  CGRect bounds = self.view.bounds;
  self.mtkView = [[MTKView alloc] initWithFrame:bounds device:self.device];
  self.mtkView.delegate = self;
  self.mtkView.colorPixelFormat = MTLPixelFormatBGRA8Unorm;
  self.mtkView.sampleCount = 1;
  self.mtkView.preferredFramesPerSecond = 60;
  self.mtkView.contentScaleFactor = [[UIScreen mainScreen] scale];
  self.mtkView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
  self.mtkView.backgroundColor = [UIColor colorWithRed:11.0f/255.0f green:11.0f/255.0f blue:14.0f/255.0f alpha:1.0f];
  self.mtkView.multipleTouchEnabled = YES;
  [self.view addSubview:self.mtkView];

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  io.IniFilename = nil;
  io.ConfigFlags |= ImGuiConfigFlags_IsTouchScreen;
  io.DisplayFramebufferScale = ImVec2(1.0f, 1.0f);
  ImGui_ImplMetal_Init(self.device);

  _state = std::make_unique<memdbg::frontend::AppState>();
  memdbg::frontend::init_app_shared(*_state, _dpiScale);

  // Install iOS keyboard bridge so InputText fields can summon the software keyboard
  ImGuiInstallIOSKeyboardBridge(self.view);

  _imguiInitialized = YES;
}

- (void)dealloc {
  if (_imguiInitialized) {
    memdbg::frontend::shutdown_app_shared(*_state);
    ImGui_ImplMetal_Shutdown();
    ImGui::DestroyContext();
  }
  [super dealloc];
}

#pragma mark - MTKViewDelegate

- (void)drawInMTKView:(MTKView *)view {
  if (!_imguiInitialized) return;

  // Sync iOS software keyboard with ImGui's WantTextInput flag
  ImGuiUpdateIOSKeyboardBridge();

  ImGuiIO &io = ImGui::GetIO();
  io.DisplaySize = ImVec2(view.bounds.size.width, view.bounds.size.height);
  CGFloat scale = view.window.screen.scale;
  if (scale <= 0.0) scale = view.contentScaleFactor;
  io.DisplayFramebufferScale = ImVec2(scale, scale);
  io.DeltaTime = 1.0f / 60.0f;

  UIEdgeInsets safe = view.safeAreaInsets;
  memdbg::frontend::set_mobile_safe_area(
      static_cast<float>(safe.left),
      static_cast<float>(safe.top),
      static_cast<float>(safe.right),
      static_cast<float>(safe.bottom));

  [self _applyTouchStateToImGui];

  id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
  MTLRenderPassDescriptor *renderPass = view.currentRenderPassDescriptor;
  if (renderPass == nil) {
    [commandBuffer commit];
    return;
  }

  ImGui_ImplMetal_NewFrame(renderPass);
  ImGui::NewFrame();
  CGSize bounds = view.bounds.size;
  if (bounds.width < 768.0) {
    memdbg::frontend::draw_mobile_app(*_state);
  } else {
    memdbg::frontend::draw_app(*_state);
  }
  ImGui::Render();

  id<MTLRenderCommandEncoder> encoder = [commandBuffer renderCommandEncoderWithDescriptor:renderPass];
  ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), commandBuffer, encoder);
  [encoder endEncoding];
  [commandBuffer presentDrawable:view.currentDrawable];
  [commandBuffer commit];
}

- (void)mtkView:(MTKView *)view drawableSizeWillChange:(CGSize)size {
  (void)view;
  (void)size;
}

#pragma mark - Touch input -> ImGui mouse

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
  (void)event;
  UITouch *t = touches.anyObject;
  if (!t) return;
  CGPoint p = [t locationInView:self.mtkView];
  ImGuiIO &io = ImGui::GetIO();
  io.AddMousePosEvent(p.x, p.y);
  io.AddMouseButtonEvent(0, true);
  _primaryTouch = t;
}

- (void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
  (void)event;
  UITouch *t = [_primaryTouch isKindOfClass:[UITouch class]] ? (UITouch *)_primaryTouch : touches.anyObject;
  if (!t) return;
  CGPoint p = [t locationInView:self.mtkView];
  ImGuiIO &io = ImGui::GetIO();
  io.AddMousePosEvent(p.x, p.y);
}

- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
  (void)event;
  (void)touches;
  ImGuiIO &io = ImGui::GetIO();
  io.AddMouseButtonEvent(0, false);
  _primaryTouch = nil;
}

- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
  [self touchesEnded:touches withEvent:event];
}

- (void)_applyTouchStateToImGui {
  UITouch *t = [_primaryTouch isKindOfClass:[UITouch class]] ? (UITouch *)_primaryTouch : nil;
  if (!t) return;
  CGPoint p = [t locationInView:self.mtkView];
  ImGuiIO &io = ImGui::GetIO();
  io.AddMousePosEvent(p.x, p.y);
}

@end
