// MemDBG - Android native shell (JNI bridge + OpenGL ES 3 renderer).
// Copyright (C) 2026 SeregonWar
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Mirrors the iOS ViewController. The shared frontend is compiled in mobile mode
// (MEMDBG_PLATFORM_IOS guard) so draw_mobile_app / set_mobile_safe_area drive
// the identical touch layout used on iPhone and iPad. The JVM side owns the
// EGL surface via GLSurfaceView; this module only feeds ImGui and renders each
// frame through the ImGui OpenGL ES 3 backend.

#include <jni.h>
#include <android/log.h>
#include <cmath>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <imgui.h>
#include <imgui_impl_opengl3.h>

#include "app_state.hpp"
#include "app/shell/memdbg_app.hpp"

#define MEMDBG_LOG_TAG "MemDBG"
#define MEMDBG_LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, MEMDBG_LOG_TAG, __VA_ARGS__))
#define MEMDBG_LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, MEMDBG_LOG_TAG, __VA_ARGS__))

namespace {

struct TouchEvent {
  int action;     // 0 down, 1 up, 2 move, 3 cancel
  float x_dp;
  float y_dp;
};

std::unique_ptr<memdbg::frontend::AppState> g_state;
bool g_imgui_ready = false;
float g_density = 1.0f;
float g_design_dpi_scale = 1.0f;
int g_width_dp = 0;
int g_height_dp = 0;
bool g_use_mobile_layout = true;

std::mutex g_touch_mutex;
std::deque<TouchEvent> g_touch_queue;

// MotionEvent action codes (mirror android.view.MotionEvent).
constexpr int ACTION_DOWN = 0;
constexpr int ACTION_UP = 1;
constexpr int ACTION_MOVE = 2;
constexpr int ACTION_CANCEL = 3;

void flush_touch_events() {
  std::deque<TouchEvent> local;
  {
    std::lock_guard<std::mutex> lock(g_touch_mutex);
    local.swap(g_touch_queue);
  }
  if (local.empty()) return;
  ImGuiIO &io = ImGui::GetIO();
  for (const TouchEvent &ev : local) {
    io.AddMousePosEvent(ev.x_dp, ev.y_dp);
    if (ev.action == ACTION_DOWN) {
      io.AddMouseButtonEvent(0, true);
    } else if (ev.action == ACTION_UP || ev.action == ACTION_CANCEL) {
      io.AddMouseButtonEvent(0, false);
    }
  }
}

} // namespace

extern "C" {

JNIEXPORT void JNICALL
Java_io_github_seregonwar_memdbg_mobile_MemDBGJNI_nativeInit(
    JNIEnv *env, jclass clazz, jfloat density, jboolean is_tablet) {
  (void)env;
  (void)clazz;

  if (g_imgui_ready) return;

  g_density = density > 0.0f ? density : 1.0f;
  g_design_dpi_scale = is_tablet ? 1.08f : 1.0f;

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  io.IniFilename = nullptr;
  io.ConfigFlags |= ImGuiConfigFlags_IsTouchScreen;
  io.BackendPlatformName = "MemDBG-Android";

  // GL ES 3 backend. The current EGL context is owned by GLSurfaceView.
  ImGui_ImplOpenGL3_Init("#version 300 es");

  g_state = std::make_unique<memdbg::frontend::AppState>();
  memdbg::frontend::init_app_shared(*g_state, g_design_dpi_scale);
  g_imgui_ready = true;
  MEMDBG_LOGI("ImGui + MemDBG frontend initialized (density=%.2f tablet=%d)",
              g_density, is_tablet ? 1 : 0);
}

JNIEXPORT void JNICALL
Java_io_github_seregonwar_memdbg_mobile_MemDBGJNI_nativeOnSurfaceChanged(
    JNIEnv *env, jclass clazz, jint width_px, jint height_px) {
  (void)env;
  (void)clazz;
  if (!g_imgui_ready || g_density <= 0.0f) return;

  g_width_dp = static_cast<int>(std::round(static_cast<float>(width_px) / g_density));
  g_height_dp = static_cast<int>(std::round(static_cast<float>(height_px) / g_density));
  g_use_mobile_layout = (g_width_dp < 768);

  ImGuiIO &io = ImGui::GetIO();
  io.DisplaySize = ImVec2(static_cast<float>(g_width_dp),
                          static_cast<float>(g_height_dp));
  io.DisplayFramebufferScale = ImVec2(g_density, g_density);
}

JNIEXPORT void JNICALL
Java_io_github_seregonwar_memdbg_mobile_MemDBGJNI_nativeSetSafeArea(
    JNIEnv *env, jclass clazz, jfloat left, jfloat top, jfloat right, jfloat bottom) {
  (void)env;
  (void)clazz;
  if (g_density <= 0.0f) return;
  // Convert pixel insets to dp so they match ImGui's dp coordinate system.
  memdbg::frontend::set_mobile_safe_area(left / g_density, top / g_density,
                                         right / g_density, bottom / g_density);
}

JNIEXPORT void JNICALL
Java_io_github_seregonwar_memdbg_mobile_MemDBGJNI_nativeDrawFrame(
    JNIEnv *env, jclass clazz) {
  (void)env;
  (void)clazz;
  if (!g_imgui_ready) return;

  ImGuiIO &io = ImGui::GetIO();
  if (io.DisplaySize.x <= 0.0f || io.DisplaySize.y <= 0.0f) return;
  io.DeltaTime = 1.0f / 60.0f;

  flush_touch_events();

  ImGui_ImplOpenGL3_NewFrame();
  ImGui::NewFrame();
  if (g_use_mobile_layout) {
    memdbg::frontend::draw_mobile_app(*g_state);
  } else {
    memdbg::frontend::draw_app(*g_state);
  }
  ImGui::Render();
  ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
}

JNIEXPORT void JNICALL
Java_io_github_seregonwar_memdbg_mobile_MemDBGJNI_nativeOnTouch(
    JNIEnv *env, jclass clazz, jint action, jfloat x_px, jfloat y_px) {
  (void)env;
  (void)clazz;
  if (!g_imgui_ready) return;

  TouchEvent ev;
  ev.action = action;
  ev.x_dp = (g_density > 0.0f) ? (x_px / g_density) : x_px;
  ev.y_dp = (g_density > 0.0f) ? (y_px / g_density) : y_px;
  {
    std::lock_guard<std::mutex> lock(g_touch_mutex);
    g_touch_queue.push_back(ev);
    if (g_touch_queue.size() > 256) g_touch_queue.pop_front();
  }
}

JNIEXPORT void JNICALL
Java_io_github_seregonwar_memdbg_mobile_MemDBGJNI_nativeOnDestroy(
    JNIEnv *env, jclass clazz) {
  (void)env;
  (void)clazz;
  if (!g_imgui_ready) return;

  if (g_state) {
    memdbg::frontend::shutdown_app_shared(*g_state);
    g_state.reset();
  }
  ImGui_ImplOpenGL3_Shutdown();
  ImGui::DestroyContext();
  g_imgui_ready = false;
  {
    std::lock_guard<std::mutex> lock(g_touch_mutex);
    g_touch_queue.clear();
  }
  MEMDBG_LOGI("ImGui + MemDBG frontend destroyed");
}

} // extern "C"