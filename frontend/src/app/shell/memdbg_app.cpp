/*
 * MemDBG - ImGui console frontend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "internal.hpp"
#include "icon_font.hpp"
#include "embedded_logo.hpp"
#include "embedded_assets.inc"
#include "github_profile.hpp"
#include "payload_fetcher.hpp"
#include "release_check.hpp"

#include "imgui.h"

#if !defined(MEMDBG_PLATFORM_IOS)
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#endif

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <csignal>
#include <filesystem>
#include <limits>
#include <string>
#include <vector>

#include "stb_image.h"

#if !defined(MEMDBG_PLATFORM_IOS)
#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE 0x812F
#endif
#endif

namespace memdbg::frontend {

namespace {

#if defined(MEMDBG_PLATFORM_IOS)
/* Metal texture handle (id<MTLTexture>) stored as void*; the iOS shell owns
 * the real upload via ImGui_ImplMetal, so the desktop OpenGL path is skipped. */
using TextureHandle = void *;
#else
using TextureHandle = GLuint;
#endif

struct TextureAsset {
  TextureHandle texture{};
  int width = 0;
  int height = 0;
  int content_width = 0;
  int content_height = 0;
  ImVec2 uv0 = ImVec2(0.0f, 0.0f);
  ImVec2 uv1 = ImVec2(1.0f, 1.0f);
  bool attempted = false;
};

static TextureAsset s_logo_texture;
static std::filesystem::path s_executable_dir;

static ImTextureID texture_id(TextureHandle texture) {
#if defined(MEMDBG_PLATFORM_IOS)
  return reinterpret_cast<ImTextureID>(texture);
#else
  return reinterpret_cast<ImTextureID>(static_cast<intptr_t>(texture));
#endif
}

[[maybe_unused]] static void init_executable_dir(const char *argv0) {
  if (argv0 == nullptr || argv0[0] == '\0') return;

  try {
    std::error_code ec;
    std::filesystem::path path(argv0);
    if (path.is_relative()) {
      path = std::filesystem::current_path(ec) / path;
      if (ec) { path = std::filesystem::path(argv0); ec.clear(); }
    }
    const std::filesystem::path canonical = std::filesystem::weakly_canonical(path, ec);
    if (!ec && !canonical.empty()) path = canonical;
    if (path.has_parent_path()) s_executable_dir = path.parent_path();
  } catch (...) { /* argv0 parsing is best-effort */ }
}

#if !defined(__APPLE__)
static void add_asset_candidates(std::vector<std::filesystem::path> &out,
                                 const std::filesystem::path &root,
                                 const std::filesystem::path &relative_path) {
  if (root.empty()) return;
  std::filesystem::path current = root;
  for (int depth = 0; depth < 6; ++depth) {
    out.push_back(current / relative_path);
    if (!current.has_parent_path() || current.parent_path() == current) break;
    current = current.parent_path();
  }
}

static std::filesystem::path find_asset_path(const char *relative_path) {
  const std::filesystem::path rel(relative_path);
  std::vector<std::filesystem::path> candidates;
  candidates.reserve(16);
  candidates.push_back(rel);
  add_asset_candidates(candidates, s_executable_dir, rel);

  std::error_code ec;
  add_asset_candidates(candidates, std::filesystem::current_path(ec), rel);

  for (const auto &candidate : candidates) {
    ec.clear();
    if (std::filesystem::exists(candidate, ec) && !ec) {
      const std::filesystem::path canonical = std::filesystem::weakly_canonical(candidate, ec);
      return !ec && !canonical.empty() ? canonical : candidate;
    }
  }
  return rel;
}
#endif

static void compute_content_uv(TextureAsset &asset, const unsigned char *pixels) {
  int min_x = asset.width;
  int min_y = asset.height;
  int max_x = -1;
  int max_y = -1;

  for (int y = 0; y < asset.height; ++y) {
    for (int x = 0; x < asset.width; ++x) {
      const unsigned char alpha = pixels[(static_cast<size_t>(y) * asset.width + x) * 4U + 3U];
      if (alpha < 8U) continue;
      min_x = std::min(min_x, x);
      min_y = std::min(min_y, y);
      max_x = std::max(max_x, x);
      max_y = std::max(max_y, y);
    }
  }

  if (max_x < min_x || max_y < min_y) {
    asset.content_width = asset.width;
    asset.content_height = asset.height;
    return;
  }

  asset.content_width = max_x - min_x + 1;
  asset.content_height = max_y - min_y + 1;
  asset.uv0 = ImVec2(static_cast<float>(min_x) / static_cast<float>(asset.width),
                     static_cast<float>(min_y) / static_cast<float>(asset.height));
  asset.uv1 = ImVec2(static_cast<float>(max_x + 1) / static_cast<float>(asset.width),
                     static_cast<float>(max_y + 1) / static_cast<float>(asset.height));
}

static bool load_texture_png_from_memory(TextureAsset &asset,
                                         const std::uint8_t *data,
                                         std::size_t data_size) {
  if (static_cast<bool>(asset.texture)) return true;
  if (asset.attempted) return false;
  asset.attempted = true;

  if (data == nullptr || data_size == 0U ||
      data_size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return false;
  }

  int width = 0, height = 0, channels = 0;
  const auto *bytes = reinterpret_cast<const unsigned char *>(data);
  unsigned char *pixels = stbi_load_from_memory(bytes, static_cast<int>(data_size),
                                                &width, &height, &channels, 4);
  if (pixels == nullptr || width <= 0 || height <= 0) {
    stbi_image_free(pixels);
    return false;
  }

  asset.width = width;
  asset.height = height;
  compute_content_uv(asset, pixels);

#if !defined(MEMDBG_PLATFORM_IOS)
  GLuint texture = 0;
  glGenTextures(1, &texture);
  glBindTexture(GL_TEXTURE_2D, texture);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA,
               GL_UNSIGNED_BYTE, pixels);
  glBindTexture(GL_TEXTURE_2D, 0);
  asset.texture = texture;
#endif

  stbi_image_free(pixels);
  return true;
}

static void shutdown_texture(TextureAsset &asset) {
#if !defined(MEMDBG_PLATFORM_IOS)
  if (static_cast<bool>(asset.texture)) {
    GLuint texture = static_cast<GLuint>(asset.texture);
    glDeleteTextures(1, &texture);
  }
#endif
  asset = TextureAsset{};
}

#if !defined(MEMDBG_PLATFORM_IOS)
static void set_window_icon(GLFWwindow *window) {
#if defined(__APPLE__)
  (void)window;
#else
  if (window == nullptr) return;

  try {
    const std::filesystem::path path = find_asset_path("assets/app-icon.png");
    if (path.empty()) return;
    int width = 0, height = 0, channels = 0;
    unsigned char *pixels = stbi_load(path.string().c_str(), &width, &height, &channels, 4);
    if (pixels == nullptr || width <= 0 || height <= 0) {
      stbi_image_free(pixels);
      return;
    }

    GLFWimage image{};
    image.width = width;
    image.height = height;
    image.pixels = pixels;
    glfwSetWindowIcon(window, 1, &image);
    stbi_image_free(pixels);
  } catch (...) { /* icon load is non-fatal */ }
#endif
}
#endif

} // namespace

float topbar_logo_w(float logo_h) {
  const float scl = ui::dpi_scale();
  const int logo_content_w = s_logo_texture.content_width > 0 ? s_logo_texture.content_width : s_logo_texture.width;
  const int logo_content_h = s_logo_texture.content_height > 0 ? s_logo_texture.content_height : s_logo_texture.height;
  if (logo_content_h > 0)
    return logo_h * (static_cast<float>(logo_content_w) / static_cast<float>(logo_content_h));
  return 136.0f * scl;
}

void draw_topbar_logo(float logo_h) {
  load_texture_png_from_memory(s_logo_texture,
                               assets::kLogoNobgPng,
                               assets::kLogoNobgPngLen);
  const float logo_w = topbar_logo_w(logo_h);

  if (static_cast<bool>(s_logo_texture.texture)) {
    ImGui::Image(texture_id(s_logo_texture.texture), ImVec2(logo_w, logo_h),
                 s_logo_texture.uv0, s_logo_texture.uv1);
  } else {
    ImGui::Dummy(ImVec2(logo_w, logo_h));
  }
}

void draw_app(AppState &state) {
  poll_locale_repository(state);
  poll_connect(state);
  poll_payload_lifecycle(state);
  poll_taskmgr_prefetch(state);
  poll_telemetry(state);
  poll_map_refresh(state);
  poll_tracer(state);
  poll_plugin_tasks(state);
  poll_cheat_tasks(state);
  poll_session_health(state);
  handle_global_shortcuts(state);

  /* PayloadFetcher toast: fire once when a new payload release is detected. */
  {
    std::string notify_tag = state.payload_fetcher.take_notify();
    if (!notify_tag.empty()) {
      char buf[256];
      std::snprintf(buf, sizeof(buf),
                    locale::tr("payload.new_version"), notify_tag.c_str());
      push_notification(state, buf, 10.0);
    }

    /* Re-check payload version comparison when the fetcher has fresh data
     * (catches the case where the user connects before the first check completes). */
    if (state.has_hello && state.payload_fetcher.checked())
      update_payload_version_check(state);
  }

  ImGuiViewport *viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(viewport->WorkSize);

  ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoMove|
                           ImGuiWindowFlags_NoSavedSettings|ImGuiWindowFlags_NoBringToFrontOnFocus;
  ImGui::Begin("MemDBG Shell", nullptr, flags);

  ImVec2 win_pos = ImGui::GetWindowPos(), win_size = ImGui::GetWindowSize();
  ui::draw_background(ImGui::GetWindowDrawList(), win_pos, win_size);

  const float scl = ui::dpi_scale();
  const float sidebar_min = 160.0f * scl;
  const float sidebar_max = std::min(400.0f * scl, win_size.x * 0.35f);
  float sidebar_w = state.sidebar_width > 0.0f
      ? std::clamp(state.sidebar_width, sidebar_min, sidebar_max)
      : std::clamp(win_size.x * 0.15f, sidebar_min, 224.0f * scl);
  const float top_h = 46.0f * scl;
  const float status_h = 26.0f * scl;
  const float content_h = win_size.y - top_h - status_h;

  ImGui::SetCursorPos(ImVec2(0,0));
  draw_top_bar(state, ImVec2(win_size.x, top_h));
  ImGui::SetCursorPos(ImVec2(0, top_h));
  draw_sidebar(state, ImVec2(sidebar_w, content_h));

  /* â”€â”€ Resize handle â”€â”€ */
  const float handle_w = 5.0f * scl;
  ImGui::SetCursorPos(ImVec2(sidebar_w, top_h));
  ImGui::InvisibleButton("##SidebarResize", ImVec2(handle_w, content_h));
  if (ImGui::IsItemHovered() || ImGui::IsItemActive())
    ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
  if (ImGui::IsItemActive()) {
    sidebar_w = std::clamp(sidebar_w + ImGui::GetIO().MouseDelta.x, sidebar_min, sidebar_max);
    state.sidebar_width = sidebar_w;
  }
  /* Draw a subtle grip line in the handle area */
  {
    ImDrawList *dl = ImGui::GetWindowDrawList();
    const float cx = sidebar_w + handle_w * 0.5f;
    const float mid_y = top_h + content_h * 0.5f;
    const float grip_h = 24.0f * scl;
    ImVec4 grip_c = ui::colors().border;
    grip_c.w *= ImGui::IsItemHovered() ? 0.9f : 0.4f;
    const ImU32 grip_col = ui::color_u32(grip_c);
    dl->AddLine(ImVec2(cx - 1.0f * scl, mid_y - grip_h), ImVec2(cx - 1.0f * scl, mid_y + grip_h), grip_col, 1.5f);
    dl->AddLine(ImVec2(cx + 1.0f * scl, mid_y - grip_h), ImVec2(cx + 1.0f * scl, mid_y + grip_h), grip_col, 1.5f);
  }

  const float content_w = win_size.x - sidebar_w - handle_w;

  /* Wrap the content area in a child window so a misbehaved screen cannot
   * draw over the sidebar/topbar even if it resets the cursor position. */
  ImGui::SetCursorPos(ImVec2(sidebar_w + handle_w, top_h));
  ImGui::BeginChild("AppContent", ImVec2(content_w, content_h), false,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
  draw_screen(state, ImVec2(content_w, content_h));
  ImGui::EndChild();

  ImGui::SetCursorPos(ImVec2(0, win_size.y-status_h));
  draw_status_bar(state, ImVec2(win_size.x, status_h));

  set_notification_bottom_reserved(0.0f);
  draw_notifications(state);
  draw_connect_spinner(state);

  // Crash recovery dialog (like Unreal Engine crash reporter)
  if (state.crash_detected_on_startup) {
    ImGui::OpenPopup("##CrashRecovery");
    state.crash_detected_on_startup = false;
    state.crash_report_dialog_open = true;
  }
  static std::vector<ActionJournalEntry> s_crash_actions;
  static bool s_crash_actions_loaded = false;

  if (state.crash_report_dialog_open) {
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    bool open = true;
    if (ImGui::BeginPopupModal("##CrashRecovery", &open,
          ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove)) {
      ImGui::TextUnformatted(locale::tr("crash.detected_title"));
      ImGui::Spacing();
      ImGui::TextWrapped("%s", locale::tr("crash.detected_desc"));
      ImGui::Spacing();
      ImGui::TextWrapped("%s", locale::tr("crash.report_prompt"));
      ImGui::Spacing();
      ImGui::Separator();
      ImGui::Spacing();

      // Load previous actions for display
      // (moved to outer scope so the !open cleanup below can reach them)
      if (!s_crash_actions_loaded) {
        ActionJournal::load_recent(ActionJournal::default_path(), s_crash_actions, 50);
        s_crash_actions_loaded = true;
      }

      if (!s_crash_actions.empty()) {
        ImGui::TextWrapped("%s", locale::tr("crash.last_actions"));
        ImGui::Spacing();
        ImGui::BeginChild("CrashActions", ImVec2(500, 150), true);
        for (const auto &entry : s_crash_actions) {
          char time_buf[16];
          std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S",
                        std::localtime(&entry.timestamp));
          ImGui::TextColored(ui::colors().dim, "[%s]", time_buf);
          ImGui::SameLine();
          ImGui::TextUnformatted(entry.action.c_str());
        }
        ImGui::EndChild();
        ImGui::Spacing();
      }

      bool report_clicked = ui::soft_button(
          (std::string(icons::kExternalLink) + "  " + locale::tr("crash.report_github")).c_str(),
          ImVec2(280, 40));
      ImGui::SameLine();
      bool dismiss_clicked = ui::soft_button(
          (std::string(icons::kClose) + "  " + locale::tr("crash.dismiss")).c_str(),
          ImVec2(140, 40));

      if (report_clicked) {
        std::string url = ActionJournal::build_crash_report_url(
            s_crash_actions, MEMDBG_VERSION_STRING,
#if defined(__APPLE__)
            "macOS"
#elif defined(_WIN32)
            "Windows"
#else
            "Linux"
#endif
            ,
            state.report_anonymize,
            state.report_telemetry_enabled);
        platform::open_url(url);
        state.crash_report_dialog_open = false;
        ImGui::CloseCurrentPopup();
      }
      if (dismiss_clicked) {
        s_crash_actions.clear();
        s_crash_actions_loaded = false;
        state.crash_report_dialog_open = false;
        ImGui::CloseCurrentPopup();
      }
      ImGui::EndPopup();
    }
    if (!open) {
      s_crash_actions.clear();
      s_crash_actions_loaded = false;
      state.crash_report_dialog_open = false;
    }
  }

  // Capture console-side UDP logs into the crash logger
  if (state.crash_logging_enabled && state.udp_listener.running()) {
    state.crash_logger.capture_console_lines(
        state.udp_listener.snapshot(),
        state.crash_udp_last_received,
        state.udp_listener.stats().received);
  }

  ImGui::End();
}

/* ---- Entry point ---- */

static bool readable_file(const char *path) {
  FILE *file = std::fopen(path, "rb");
  if (!file) return false;
  std::fclose(file);
  return true;
}

static void setup_fonts(ImGuiIO &io, float dpi_scale) {
  const float base_text_size = 16.0f;
  const float text_size = std::roundf(base_text_size * dpi_scale);

  // Default and Cyrillic ranges omit punctuation such as U+2014 (em dash),
  // which is used by several translated strings.
  ImFontGlyphRangesBuilder ranges_builder;
  ranges_builder.AddRanges(io.Fonts->GetGlyphRangesDefault());
  ranges_builder.AddRanges(io.Fonts->GetGlyphRangesCyrillic());
  static const ImWchar punctuation_ranges[] = {0x2000, 0x206F, 0};
  ranges_builder.AddRanges(punctuation_ranges);
  ImVector<ImWchar> glyph_ranges;
  ranges_builder.BuildRanges(&glyph_ranges);

  ImFontConfig base_cfg;
  base_cfg.OversampleH = 4;
  base_cfg.OversampleV = 3;
  base_cfg.PixelSnapH = true;
  base_cfg.RasterizerMultiply = 1.12f;
  base_cfg.GlyphRanges = glyph_ranges.Data;
  base_cfg.FontBuilderFlags = 0;

  bool loaded_base = false;
  static const char *font_candidates[] = {
#if defined(__APPLE__)
    "/System/Library/Fonts/SFNS.ttf",
    "/System/Library/Fonts/HelveticaNeue.ttc",
    "/System/Library/Fonts/Avenir Next.ttc",
#elif defined(_WIN32)
    "C:\\Windows\\Fonts\\segoeui.ttf",
    "C:\\Windows\\Fonts\\arial.ttf",
#else
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
#endif
  };

  for (const char *path : font_candidates) {
    if (!readable_file(path)) continue;
    if (io.Fonts->AddFontFromFileTTF(path, text_size, &base_cfg)) {
      loaded_base = true;
      break;
    }
  }

  if (!loaded_base) {
    ImFontConfig fallback_cfg;
    fallback_cfg.SizePixels = text_size;
    fallback_cfg.OversampleH = 4;
    fallback_cfg.OversampleV = 3;
    fallback_cfg.PixelSnapH = true;
    fallback_cfg.RasterizerMultiply = 1.12f;
    fallback_cfg.GlyphRanges = glyph_ranges.Data;
    fallback_cfg.FontBuilderFlags = 0;
    io.Fonts->AddFontDefault(&fallback_cfg);
  }

  // CJK fallback font for Japanese (Hiragana, Katakana, common Kanji)
  {
    ImFontConfig cjk_cfg;
    cjk_cfg.MergeMode = true;
    cjk_cfg.OversampleH = 3;
    cjk_cfg.OversampleV = 2;
    cjk_cfg.PixelSnapH = true;
    cjk_cfg.GlyphRanges = io.Fonts->GetGlyphRangesJapanese();
    cjk_cfg.FontBuilderFlags = 0;

    static const char *cjk_candidates[] = {
#if defined(__APPLE__)
      "/System/Library/Fonts/AppleSDGothicNeo.ttc",
      "/System/Library/Fonts/Hiragino Sans GB.ttc",
      "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
#elif defined(_WIN32)
      "C:\\Windows\\Fonts\\YuGothR.ttc",
      "C:\\Windows\\Fonts\\YuGothM.ttc",
      "C:\\Windows\\Fonts\\YuGothB.ttc",
      "C:\\Windows\\Fonts\\meiryo.ttc",
      "C:\\Windows\\Fonts\\meiryob.ttc",
      "C:\\Windows\\Fonts\\msgothic.ttc",
      "C:\\Windows\\Fonts\\msmincho.ttc",
      "C:\\Windows\\Fonts\\malgun.ttf",
      "C:\\Windows\\Fonts\\msyh.ttc",
      "C:\\Windows\\Fonts\\simsun.ttc",
      "C:\\Windows\\Fonts\\arialuni.ttf",
#else
      "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
      "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
      "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
#endif
    };

    bool loaded_cjk = false;
    for (const char *path : cjk_candidates) {
      if (!readable_file(path)) continue;
      if (io.Fonts->AddFontFromFileTTF(path, text_size, &cjk_cfg)) {
        loaded_cjk = true;
        break;
      }
    }
    (void)loaded_cjk;  // best-effort; UI degrades gracefully without CJK font
  }

  const float icon_size = std::roundf(16.0f * dpi_scale);
  ImFontConfig icon_cfg;
  icon_cfg.MergeMode = true;
  icon_cfg.FontDataOwnedByAtlas = false;
  icon_cfg.PixelSnapH = true;
  icon_cfg.OversampleH = 3;
  icon_cfg.OversampleV = 2;
  icon_cfg.GlyphMinAdvanceX = std::roundf(17.0f * dpi_scale);
  icon_cfg.GlyphOffset = ImVec2(0.0f, 0.0f);
  icon_cfg.FontBuilderFlags = 0;
  static const ImWchar icon_ranges[] = { 0xF000, 0xF8FF, 0 };
  io.Fonts->AddFontFromMemoryTTF(
      fa_solid_900, (int)fa_solid_900_len,
      icon_size, &icon_cfg, icon_ranges);

  ImFontConfig brand_cfg;
  brand_cfg.MergeMode = true;
  brand_cfg.FontDataOwnedByAtlas = false;
  brand_cfg.PixelSnapH = true;
  brand_cfg.OversampleH = 3;
  brand_cfg.OversampleV = 2;
  brand_cfg.GlyphMinAdvanceX = std::roundf(17.0f * dpi_scale);
  brand_cfg.GlyphOffset = ImVec2(0.0f, 0.0f);
  brand_cfg.FontBuilderFlags = 0;
  static const ImWchar brand_ranges[] = { 0xE000, 0xF8FF, 0 };
  io.Fonts->AddFontFromMemoryTTF(
      fa_brands_400, (int)fa_brands_400_len,
      icon_size, &brand_cfg, brand_ranges);
  io.Fonts->Build();
}

void init_app_shared(AppState &state, float dpi_scale) {
#if !defined(_WIN32)
  signal(SIGPIPE, SIG_IGN);
#endif
  ImGuiIO &io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  io.FontGlobalScale = 1.0f;
  io.FontAllowUserScaling = false;
  io.ConfigWindowsMoveFromTitleBarOnly = true;
  ui::set_dpi_scale(dpi_scale);
  ui::apply_theme();

  setup_fonts(io, dpi_scale);
  ImGui::GetStyle().ScaleAllSizes(dpi_scale);

  state.plugin_manager.set_bundle_root(s_executable_dir);
  std::snprintf(state.plugin_bundle_root, sizeof(state.plugin_bundle_root),
                "%s", s_executable_dir.string().c_str());
  {
    std::string plugin_error;
    if (!state.plugin_manager.load(&plugin_error) && !plugin_error.empty()) {
      set_status(state, plugin_error);
    }
  }

  state.cheat_repository.set_bundle_root(s_executable_dir);
  {
    std::string cheat_error;
    if (!state.cheat_repository.load(&cheat_error) && !cheat_error.empty()) {
      set_status(state, cheat_error);
    }
  }

  state.theme_manager.set_bundle_root(s_executable_dir);
  {
    std::string theme_error;
    if (!state.theme_manager.load(&theme_error) && !theme_error.empty()) {
      set_status(state, theme_error);
    }
  }
  state.theme_manager.apply_active_theme();

  // Open crash logger and action journal in app data dir (writable on all platforms)
  try {
    const auto logs_dir = platform::app_data_dir() / "logs";
    std::filesystem::create_directories(logs_dir);
    state.crash_logger.open((logs_dir / "memdbg_crash.log").string().c_str());
  } catch (...) {
    // crash logger failure is non-fatal
  }

  // Detect previous crash: if the action journal exists but lacks clean_shutdown
  {
    const auto journal_path = ActionJournal::default_path();
    std::error_code ec;
    if (std::filesystem::exists(journal_path, ec) && !ec) {
      bool had_clean_shutdown = false;
      std::vector<ActionJournalEntry> prev_actions;
      ActionJournal::load_recent(journal_path, prev_actions, 200, &had_clean_shutdown);
      if (!had_clean_shutdown && !prev_actions.empty()) {
        state.crash_detected_on_startup = true;
        state.crash_logger.log("crash", "Previous session did not shut down cleanly");
      }
    }
  }

  // Open action journal for this session
  try {
    state.action_journal.open(ActionJournal::default_path().string().c_str());
  } catch (...) {
    // action journal failure is non-fatal
  }

  bool settings_loaded = false;
  {
    std::string config_error;
    settings_loaded = load_frontend_settings(state, &config_error);
    if (settings_loaded && config_error.empty()) {
      set_status(state, "Settings loaded");
    } else if (!config_error.empty()) {
      if (state.crash_logging_enabled)
        state.crash_logger.log("error", ("Config load error: " + config_error).c_str());
      set_status(state, config_error);
    }
  }

  /* ---- ImGui ini from embedded data ---- */
  {
    using namespace memdbg::frontend::assets;
    if (kImGuiIniSize > 0) {
      io.IniFilename = nullptr;
      ImGui::LoadIniSettingsFromMemory(
          reinterpret_cast<const char *>(kImGuiIni),
          kImGuiIniSize);
    }
  }

  /* ---- Locale init ---- */
  locale::Manager &loc = locale::Manager::instance();
  locale::Repository &locale_repo = locale::Repository::instance();
  {
    using namespace memdbg::frontend::assets;
    for (size_t i = 0; i < kEmbeddedLocaleCount; ++i) {
      const auto &el = kEmbeddedLocales[i];
      (void)loc.load_mem(el.filename, el.data, el.size);
    }
  }
  locale_repo.preload_installed(loc);

  // Set language from saved preference, or auto-detect from OS.
  locale::Lang requested_lang = locale::Lang::EN;
  if (settings_loaded &&
      state.language >= 0 &&
      state.language < static_cast<int>(locale::Lang::COUNT)) {
    requested_lang = static_cast<locale::Lang>(state.language);
  } else {
    requested_lang = locale::detect_system_lang();
  }
  if (loc.set_active(requested_lang)) {
    state.language = static_cast<int>(requested_lang);
  } else {
    state.pending_language = static_cast<int>(requested_lang);
    state.language = static_cast<int>(locale::Lang::EN);
    (void)loc.set_active(locale::Lang::EN);
  }
  (void)locale_repo.start_startup_sync(requested_lang);
  github_profile_start(state.github_profile);
  release_check_start(state.release_check, MEMDBG_VERSION_STRING);
  state.payload_fetcher.set_auto_fetch(state.payload_auto_fetch);
  state.payload_fetcher.set_platform(payload_platform_filter(state.payload_platform));
  state.payload_fetcher.start("MemDBG-");
  {
    std::string udp_error;
    if (!ensure_udp_listener(state, udp_error))
      set_status(state, "UDP: " + udp_error);
  }

  if (state.crash_logging_enabled) {
    state.crash_logger.log("startup", "MemDBG frontend started");
    state.action_journal.record("app_start", "{\"version\":\"" MEMDBG_VERSION_STRING "\"}");
  }

  if (state.payload_auto_inject) {
    state.payload_auto_inject_probe = true;
    connect_console(state);
  }

}

void shutdown_app_shared(AppState &state) {
  if (state.shutdown_started) return;
  state.shutdown_started = true;
  save_frontend_settings(state);

  if (state.scan_async_future.valid()) {
    state.scan_async_cancel_requested.store(true);
    state.client.cancel_pending_io();
    state.scan_async_future.wait();
    state.scan_async_pending = false;
  }
  if (state.map_dump_future.valid()) {
    state.map_dump_cancel_requested.store(true);
    state.pool.cancel_all_pending_io();
    state.map_dump_future.wait();
    state.map_dump_pending = false;
  }
  if (state.taskmgr.resource_future.valid()) state.taskmgr.resource_future.wait();
  state.taskmgr.resource_pending = false;
  if (state.taskmgr.prefetch_future.valid()) state.taskmgr.prefetch_future.wait();
  state.taskmgr.prefetch_pending = false;
  if (state.plugin.refresh_future.valid()) state.plugin.refresh_future.wait();
  state.plugin.refresh_pending = false;
  if (state.plugin.run_future.valid()) state.plugin.run_future.wait();
  state.plugin.run_pending = false;
  if (state.plugin_gui_bridge && state.plugin_gui_bridge->running())
    state.plugin_gui_bridge->stop();
  if (state.payload_auto_shutdown && state.client.connected()) {
    const bool shutdown_sent = state.client.shutdown_payload();
    if (state.crash_logging_enabled) {
      state.crash_logger.log(shutdown_sent ? "shutdown" : "error",
          shutdown_sent ? "Automatic payload shutdown sent"
                        : state.client.last_error().c_str());
    }
  }
  disconnect_console(state, "Application shutdown");
  state.udp_listener.stop();
  state.payload_fetcher.stop();
  release_check_shutdown(state.release_check);
  github_profile_shutdown(state.github_profile);
  locale::Repository::instance().shutdown();
  state.action_journal.close();
  state.crash_logger.close();
  shutdown_texture(s_logo_texture);
}

#if !defined(MEMDBG_PLATFORM_IOS)
int run_frontend(int, char **argv) {
  init_executable_dir(argv != nullptr ? argv[0] : nullptr);
#if !defined(_WIN32)
  signal(SIGPIPE, SIG_IGN);
#endif
  if (!glfwInit()) return 1;

  glfwWindowHintString(GLFW_COCOA_FRAME_NAME, "MemDBG");

  float xscale = 1.0f, yscale = 1.0f;
  GLFWmonitor *monitor = glfwGetPrimaryMonitor();
  if (monitor) glfwGetMonitorContentScale(monitor, &xscale, &yscale);
  float raw_scale = std::max(xscale, yscale);
  if (raw_scale < 1.0f) raw_scale = 1.0f;

  // Keep the compact reference look by default (1.0x) and only nudge the
  // scale up gently for HiDPI monitors. Large high-res screens get a small
  // extra boost so the UI remains usable without becoming oversized.
  float dpi_scale = 1.0f + (raw_scale - 1.0f) * 0.15f;
  const GLFWvidmode *mode = monitor ? glfwGetVideoMode(monitor) : nullptr;
  if (mode) {
    float diag = std::sqrt(static_cast<float>(mode->width * mode->width +
                                              mode->height * mode->height));
    if (diag > 2200.0f) {
      dpi_scale *= 1.0f + (diag - 2200.0f) * 0.0001f;
    }
  }
  if (dpi_scale > 1.5f) dpi_scale = 1.5f;
#if defined(__APPLE__)
  const char *glsl_version = "#version 150";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3); glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#else
  const char *glsl_version = "#version 130";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3); glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif
  GLFWwindow *window = glfwCreateWindow(1400, 900, "MemDBG", nullptr, nullptr);
  if (!window) { glfwTerminate(); return 1; }
  set_window_icon(window);
  glfwMakeContextCurrent(window); glfwSwapInterval(1);

  auto state = std::make_unique<AppState>();
  IMGUI_CHECKVERSION(); ImGui::CreateContext();
  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init(glsl_version);
  init_app_shared(*state, dpi_scale);

  push_notification(*state, "MemDBG by seregonwar started", 6.0);

  /* Store pointers for the refresh callback (window-refresh fires during live resize on macOS).
   * Must be static so the non-capturing lambda below can access them. */
  static AppState *s_render_state = nullptr;
  static GLFWwindow *s_render_window = nullptr;
  s_render_state = state.get();
  s_render_window = window;

  /* Render a single frame. Callable from the main loop and from the window-refresh
   * callback (which fires during live resize on macOS).  The re-entrancy guard
   * wraps only glfwPollEvents() so the callback CAN produce a real frame â€” if the
   * callback fires while the main loop is inside PollEvents, it skips PollEvents
   * but still draws, matching the reference pattern for smooth live resize. */
  static const auto render_frame = []() {
    static bool in_poll = false;
    if (!in_poll) {
      in_poll = true;
      glfwPollEvents();
      in_poll = false;
    }
    poll_release_check(*s_render_state);

    if (glfwWindowShouldClose(s_render_window)) return;

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
    draw_app(*s_render_state);
    ImGui::Render();

    int dw, dh;
    glfwGetFramebufferSize(s_render_window, &dw, &dh);
    glViewport(0, 0, dw, dh);
    glClearColor(11.0f / 255.0f, 11.0f / 255.0f, 14.0f / 255.0f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(s_render_window);
  };

  glfwSetWindowRefreshCallback(window, [](GLFWwindow *) { render_frame(); });

  while (!glfwWindowShouldClose(window))
    render_frame();

  shutdown_app_shared(*state);
  ImGui_ImplOpenGL3_Shutdown(); ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext(); glfwDestroyWindow(window); glfwTerminate();
  s_render_state = nullptr;
  s_render_window = nullptr;
  return 0;
}
#endif // !MEMDBG_PLATFORM_IOS

} // namespace memdbg::frontend
