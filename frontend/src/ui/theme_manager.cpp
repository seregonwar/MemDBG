/*
 * MemDBG - Frontend theme manager.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "theme_manager.hpp"

#include "core/platform.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace memdbg::frontend::themes {

namespace {

std::string trim_copy(std::string value) {
  auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(),
      [&](char c) { return !is_space(static_cast<unsigned char>(c)); }));
  value.erase(std::find_if(value.rbegin(), value.rend(),
      [&](char c) { return !is_space(static_cast<unsigned char>(c)); }).base(),
      value.end());
  return value;
}

std::filesystem::path find_bundled_manifest(const std::filesystem::path &bundle_root) {
  std::vector<std::filesystem::path> roots;
  if (!bundle_root.empty()) roots.push_back(bundle_root);
  std::error_code ec;
  roots.push_back(std::filesystem::current_path(ec));

  for (const auto &root : roots) {
    if (root.empty()) continue;
    std::filesystem::path current = root;
    for (int depth = 0; depth < 8; ++depth) {
      const auto candidate = current / "theme-repository" / "manifest.json";
      ec.clear();
      if (std::filesystem::exists(candidate, ec) && !ec)
        return std::filesystem::weakly_canonical(candidate, ec);
      if (!current.has_parent_path() || current.parent_path() == current) break;
      current = current.parent_path();
    }
  }
  return {};
}

bool parse_hex_color(const std::string &text, ThemeColor &out) {
  std::string value = trim_copy(text);
  if (value.empty()) return false;
  if (value[0] == '#') value = value.substr(1);
  if (value.size() < 6) return false;

  auto parse_byte = [](const std::string &s, size_t pos) -> float {
    unsigned long v = std::strtoul(s.substr(pos, 2).c_str(), nullptr, 16);
    return static_cast<float>(v) / 255.0f;
  };

  out.r = parse_byte(value, 0);
  out.g = parse_byte(value, 2);
  out.b = parse_byte(value, 4);
  out.a = value.size() >= 8 ? parse_byte(value, 6) : 1.0f;
  return true;
}

ThemeColor json_color(const nlohmann::json &doc, const char *key,
                      const ThemeColor &fallback) {
  auto it = doc.find(key);
  if (it == doc.end()) return fallback;
  if (it->is_string()) {
    ThemeColor c;
    if (parse_hex_color(it->get<std::string>(), c)) return c;
  } else if (it->is_array() && it->size() >= 3) {
    ThemeColor c = fallback;
    c.r = (*it)[0].is_number() ? static_cast<float>((*it)[0].get<double>()) : 0.0f;
    c.g = (*it)[1].is_number() ? static_cast<float>((*it)[1].get<double>()) : 0.0f;
    c.b = (*it)[2].is_number() ? static_cast<float>((*it)[2].get<double>()) : 0.0f;
    c.a = it->size() >= 4 && (*it)[3].is_number()
              ? static_cast<float>((*it)[3].get<double>())
              : 1.0f;
    return c;
  }
  return fallback;
}

ThemePalette parse_palette(const nlohmann::json &doc) {
  ThemePalette p;
  p.bg0 = json_color(doc, "bg0", {16.0f/255.0f, 17.0f/255.0f, 18.0f/255.0f, 1.0f});
  p.bg1 = json_color(doc, "bg1", {24.0f/255.0f, 26.0f/255.0f, 27.0f/255.0f, 1.0f});
  p.bg2 = json_color(doc, "bg2", {32.0f/255.0f, 35.0f/255.0f, 36.0f/255.0f, 1.0f});
  p.bg3 = json_color(doc, "bg3", {45.0f/255.0f, 50.0f/255.0f, 50.0f/255.0f, 1.0f});
  p.panel = json_color(doc, "panel", {22.0f/255.0f, 24.0f/255.0f, 25.0f/255.0f, 1.0f});
  p.panel2 = json_color(doc, "panel2", {28.0f/255.0f, 31.0f/255.0f, 32.0f/255.0f, 1.0f});
  p.border = json_color(doc, "border", {73.0f/255.0f, 80.0f/255.0f, 81.0f/255.0f, 0.95f});
  p.border_hot = json_color(doc, "border_hot", {79.0f/255.0f, 220.0f/255.0f, 145.0f/255.0f, 0.95f});
  p.text = json_color(doc, "text", {252.0f/255.0f, 254.0f/255.0f, 253.0f/255.0f, 1.0f});
  p.muted = json_color(doc, "muted", {214.0f/255.0f, 222.0f/255.0f, 220.0f/255.0f, 1.0f});
  p.dim = json_color(doc, "dim", {156.0f/255.0f, 168.0f/255.0f, 166.0f/255.0f, 1.0f});
  p.primary = json_color(doc, "primary", {39.0f/255.0f, 164.0f/255.0f, 103.0f/255.0f, 1.0f});
  p.primary2 = json_color(doc, "primary2", {119.0f/255.0f, 244.0f/255.0f, 166.0f/255.0f, 1.0f});
  p.link = json_color(doc, "link", {154.0f/255.0f, 202.0f/255.0f, 255.0f/255.0f, 1.0f});
  p.success = json_color(doc, "success", {104.0f/255.0f, 238.0f/255.0f, 148.0f/255.0f, 1.0f});
  p.warning = json_color(doc, "warning", {239.0f/255.0f, 192.0f/255.0f, 86.0f/255.0f, 1.0f});
  p.danger = json_color(doc, "danger", {241.0f/255.0f, 95.0f/255.0f, 100.0f/255.0f, 1.0f});
  return p;
}

std::string json_string(const nlohmann::json &doc,
                        std::initializer_list<const char *> keys,
                        const std::string &fallback = {}) {
  for (const char *key : keys) {
    auto it = doc.find(key);
    if (it != doc.end() && it->is_string())
      return trim_copy(it->get<std::string>());
  }
  return fallback;
}

bool parse_manifest_themes([[maybe_unused]] const std::filesystem::path &manifest_path,
                           const nlohmann::json &doc,
                           std::vector<ThemeDefinition> &out_themes,
                           std::string *error) {
  auto themes_it = doc.find("themes");
  if (themes_it == doc.end() || !themes_it->is_array()) {
    if (error != nullptr) *error = "Manifest needs a themes array";
    return false;
  }

  std::vector<ThemeDefinition> parsed;
  for (const auto &item : *themes_it) {
    if (!item.is_object()) continue;

    ThemeDefinition theme;
    theme.id = json_string(item, {"id", "identifier"});
    theme.name = json_string(item, {"name", "title"}, theme.id);
    theme.version = json_string(item, {"version"}, "1.0.0");
    theme.author = json_string(item, {"author"});
    theme.description = json_string(item, {"description", "summary"});
    theme.license = json_string(item, {"license"});

    auto palette_it = item.find("palette");
    if (palette_it != item.end() && palette_it->is_object()) {
      theme.palette = parse_palette(*palette_it);
    } else {
      theme.palette = parse_palette(item);
    }

    if (theme.id.empty() || theme.name.empty()) continue;
    parsed.push_back(std::move(theme));
  }

  out_themes = std::move(parsed);
  return true;
}

bool parse_json_file(const std::filesystem::path &path,
                     nlohmann::json &out,
                     std::string *error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    if (error != nullptr) *error = "Cannot open " + path.string();
    return false;
  }
  try {
    in >> out;
  } catch (const std::exception &ex) {
    if (error != nullptr) *error = "JSON parse failed: " + std::string(ex.what());
    return false;
  }
  if (!out.is_object()) {
    if (error != nullptr) *error = "Manifest root must be an object";
    return false;
  }
  return true;
}

} // namespace

void ThemeManager::set_bundle_root(std::filesystem::path root) {
  std::lock_guard<std::mutex> lock(mutex_);
  bundle_root_ = std::move(root);
  bundled_manifest_path_ = find_bundled_manifest(bundle_root_);
}

std::filesystem::path ThemeManager::bundled_manifest_path() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return bundled_manifest_path_;
}

std::filesystem::path ThemeManager::config_path() const {
  return platform::app_config_dir() / "themes.json";
}

bool ThemeManager::load(std::string *error) {
  std::lock_guard<std::mutex> lock(mutex_);
  return load_unlocked(error);
}

bool ThemeManager::load_unlocked(std::string *error) {
  themes_.clear();
  active_theme_id_ = "default";

  if (bundled_manifest_path_.empty())
    bundled_manifest_path_ = find_bundled_manifest(bundle_root_);

  nlohmann::json doc;
  const auto path = config_path();
  std::ifstream in(path, std::ios::binary);
  if (in) {
    try {
      in >> doc;
    } catch (const std::exception &ex) {
      if (error != nullptr) *error = "Theme settings parse failed: " + std::string(ex.what());
      ensure_defaults_unlocked();
      load_bundled_themes_unlocked();
      return false;
    }

    if (doc.contains("active_theme") && doc["active_theme"].is_string()) {
      active_theme_id_ = trim_copy(doc["active_theme"].get<std::string>());
    }
  }

  ensure_defaults_unlocked();
  load_bundled_themes_unlocked();
  return true;
}

bool ThemeManager::save(std::string *error) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return save_unlocked(error);
}

bool ThemeManager::reload(std::string *error) {
  return load(error);
}

bool ThemeManager::save_unlocked(std::string *error) const {
  std::error_code ec;
  const auto path = config_path();
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    if (error != nullptr) *error = "Cannot create theme config directory: " + ec.message();
    return false;
  }

  nlohmann::json doc;
  doc["schema"] = 1;
  doc["active_theme"] = active_theme_id_;

  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    if (error != nullptr) *error = "Cannot write " + path.string();
    return false;
  }
  out << doc.dump(2) << "\n";
  if (!out) {
    if (error != nullptr) *error = "Failed while writing " + path.string();
    return false;
  }
  return true;
}

void ThemeManager::ensure_defaults_unlocked() {
  if (active_theme_id_.empty()) active_theme_id_ = "default";
}

void ThemeManager::load_bundled_themes_unlocked() {
  if (bundled_manifest_path_.empty()) return;

  nlohmann::json doc;
  std::string error;
  std::vector<ThemeDefinition> parsed;
  if (parse_json_file(bundled_manifest_path_, doc, &error) &&
      parse_manifest_themes(bundled_manifest_path_, doc, parsed, &error)) {
    for (auto &theme : parsed) {
      auto it = std::find_if(themes_.begin(), themes_.end(),
          [&](const ThemeDefinition &t) { return t.id == theme.id; });
      if (it == themes_.end()) {
        themes_.push_back(std::move(theme));
      }
    }
  }
}

std::vector<ThemeDefinition> ThemeManager::themes() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return themes_;
}

const ThemeDefinition *ThemeManager::find_theme(const std::string &id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto &theme : themes_) {
    if (theme.id == id) return &theme;
  }
  return nullptr;
}

bool ThemeManager::set_active_theme(const std::string &id, std::string *error) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(themes_.begin(), themes_.end(),
        [&](const ThemeDefinition &t) { return t.id == id; });
    if (it == themes_.end()) {
      if (error != nullptr) *error = "Theme not found: " + id;
      return false;
    }
    active_theme_id_ = id;
  }
  return save_unlocked(error);
}

std::string ThemeManager::active_theme_id() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return active_theme_id_;
}

const ThemeDefinition *ThemeManager::active_theme() const {
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto &theme : themes_) {
    if (theme.id == active_theme_id_) return &theme;
  }
  return themes_.empty() ? nullptr : &themes_.front();
}

ui::Palette ThemeManager::to_ui_palette(const ThemePalette &palette) {
  ui::Palette p;
  p.bg0 = palette.bg0.to_imvec4();
  p.bg1 = palette.bg1.to_imvec4();
  p.bg2 = palette.bg2.to_imvec4();
  p.bg3 = palette.bg3.to_imvec4();
  p.panel = palette.panel.to_imvec4();
  p.panel2 = palette.panel2.to_imvec4();
  p.border = palette.border.to_imvec4();
  p.border_hot = palette.border_hot.to_imvec4();
  p.text = palette.text.to_imvec4();
  p.muted = palette.muted.to_imvec4();
  p.dim = palette.dim.to_imvec4();
  p.primary = palette.primary.to_imvec4();
  p.primary2 = palette.primary2.to_imvec4();
  p.link = palette.link.to_imvec4();
  p.success = palette.success.to_imvec4();
  p.warning = palette.warning.to_imvec4();
  p.danger = palette.danger.to_imvec4();
  return p;
}

void ThemeManager::apply_active_theme() const {
  const ThemeDefinition *theme = active_theme();
  if (theme == nullptr) return;
  ui::set_palette(to_ui_palette(theme->palette));
  ui::apply_theme();
}

} // namespace memdbg::frontend::themes
