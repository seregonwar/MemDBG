/*
 * MemDBG - Frontend theme manager.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_THEME_MANAGER_HPP
#define MEMDBG_FRONTEND_THEME_MANAGER_HPP

#include "imgui.h"
#include "ui_widgets.hpp"

#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace memdbg::frontend::themes {

struct ThemeColor {
  float r = 0.0f;
  float g = 0.0f;
  float b = 0.0f;
  float a = 1.0f;

  ImVec4 to_imvec4() const { return ImVec4(r, g, b, a); }
  static ThemeColor from_imvec4(const ImVec4 &c) {
    return {c.x, c.y, c.z, c.w};
  }
};

struct ThemePalette {
  ThemeColor bg0;
  ThemeColor bg1;
  ThemeColor bg2;
  ThemeColor bg3;
  ThemeColor panel;
  ThemeColor panel2;
  ThemeColor border;
  ThemeColor border_hot;
  ThemeColor text;
  ThemeColor muted;
  ThemeColor dim;
  ThemeColor primary;
  ThemeColor primary2;
  ThemeColor link;
  ThemeColor success;
  ThemeColor warning;
  ThemeColor danger;
};

struct ThemeDefinition {
  std::string id;
  std::string name;
  std::string version;
  std::string author;
  std::string description;
  std::string license;
  ThemePalette palette;
};

class ThemeManager {
public:
  void set_bundle_root(std::filesystem::path root);

  bool load(std::string *error = nullptr);
  bool save(std::string *error = nullptr) const;
  bool reload(std::string *error = nullptr);

  std::vector<ThemeDefinition> themes() const;
  const ThemeDefinition *find_theme(const std::string &id) const;

  bool set_active_theme(const std::string &id, std::string *error = nullptr);
  std::string active_theme_id() const;
  const ThemeDefinition *active_theme() const;

  std::filesystem::path config_path() const;
  std::filesystem::path bundled_manifest_path() const;

  static ui::Palette to_ui_palette(const ThemePalette &palette);
  void apply_active_theme() const;

private:
  bool load_unlocked(std::string *error);
  bool save_unlocked(std::string *error) const;
  void ensure_defaults_unlocked();
  void load_bundled_themes_unlocked();

  mutable std::mutex mutex_;
  std::filesystem::path bundle_root_;
  std::filesystem::path bundled_manifest_path_;
  std::vector<ThemeDefinition> themes_;
  std::string active_theme_id_ = "default";
};

} // namespace memdbg::frontend::themes

#endif /* MEMDBG_FRONTEND_THEME_MANAGER_HPP */
