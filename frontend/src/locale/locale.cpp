/*
 * MemDBG - Locale manager implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "locale.hpp"
#include "ui/embedded_assets.inc"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

namespace memdbg::frontend::locale {

// ---- Language metadata ----

const char *lang_code(Lang lang) {
  switch (lang) {
  case Lang::EN: return "en";
  case Lang::ES: return "es";
  case Lang::IT: return "it";
  case Lang::FR: return "fr";
  case Lang::PT: return "pt";
  case Lang::DE: return "de";
  case Lang::RU: return "ru";
  case Lang::JA: return "ja";
  default:       return "en";
  }
}

const char *lang_name(Lang lang) {
  switch (lang) {
  case Lang::EN: return "English";
  case Lang::ES: return "Espa\u00f1ol";
  case Lang::IT: return "Italiano";
  case Lang::FR: return "Fran\u00e7ais";
  case Lang::PT: return "Portugu\u00eas";
  case Lang::DE: return "Deutsch";
  case Lang::RU: return "\u0420\u0443\u0441\u0441\u043a\u0438\u0439";
  case Lang::JA: return "\u65e5\u672c\u8a9e";
  default:       return "English";
  }
}

Lang lang_from_code(const char *code) {
  if (!code || code[0] == '\0') return Lang::EN;
  for (int i = 0; i < static_cast<int>(Lang::COUNT); ++i) {
    Lang l = static_cast<Lang>(i);
    if (std::strcmp(lang_code(l), code) == 0) return l;
  }
  return Lang::EN;
}

Lang detect_system_lang() {
  // Try LC_ALL / LANG environment variable first.
  const char *env = std::getenv("LC_ALL");
  if (!env || env[0] == '\0') env = std::getenv("LANG");
  if (!env || env[0] == '\0') return Lang::EN;

  // Match the first two characters.
  if (std::strncmp(env, "en", 2) == 0) return Lang::EN;
  if (std::strncmp(env, "es", 2) == 0) return Lang::ES;
  if (std::strncmp(env, "it", 2) == 0) return Lang::IT;
  if (std::strncmp(env, "fr", 2) == 0) return Lang::FR;
  if (std::strncmp(env, "pt", 2) == 0) return Lang::PT;
  if (std::strncmp(env, "de", 2) == 0) return Lang::DE;
  if (std::strncmp(env, "ru", 2) == 0) return Lang::RU;
  if (std::strncmp(env, "ja", 2) == 0) return Lang::JA;
  return Lang::EN;
}

// ---- Manager ----

Manager &Manager::instance() {
  static Manager mgr;
  return mgr;
}

bool Manager::load(const char *json_path) {
  std::ifstream in(json_path);
  if (!in) return false;

  nlohmann::json doc;
  try {
    in >> doc;
  } catch (const nlohmann::json::parse_error &) {
    return false;
  }

  if (!doc.is_object()) return false;

  // Determine language from file name: en.json -> EN, es.json -> ES, etc.
  std::string path(json_path);
  Lang detected = Lang::EN;
  for (int i = 0; i < static_cast<int>(Lang::COUNT); ++i) {
    Lang l = static_cast<Lang>(i);
    std::string suffix = std::string(lang_code(l)) + ".json";
    if (path.size() >= suffix.size() &&
        path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0) {
      detected = l;
      break;
    }
  }

  std::unordered_map<std::string, std::string> kv;
  for (auto it = doc.begin(); it != doc.end(); ++it) {
    if (it.value().is_string())
      kv[it.key()] = it.value().get<std::string>();
  }

  strings_[detected] = std::move(kv);
  return true;
}

bool Manager::load_mem(const char *filename, const unsigned char *data, size_t size) {
  if (!data || size == 0) return false;

  nlohmann::json doc;
  try {
    doc = nlohmann::json::parse(reinterpret_cast<const char *>(data),
                                 reinterpret_cast<const char *>(data) + size);
  } catch (const nlohmann::json::parse_error &) {
    return false;
  }

  if (!doc.is_object()) return false;

  // Determine language from filename: en.json -> EN, es.json -> ES, etc.
  std::string path(filename);
  Lang detected = Lang::EN;
  for (int i = 0; i < static_cast<int>(Lang::COUNT); ++i) {
    Lang l = static_cast<Lang>(i);
    std::string suffix = std::string(lang_code(l)) + ".json";
    if (path.size() >= suffix.size() &&
        path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0) {
      detected = l;
      break;
    }
  }

  std::unordered_map<std::string, std::string> kv;
  for (auto it = doc.begin(); it != doc.end(); ++it) {
    if (it.value().is_string())
      kv[it.key()] = it.value().get<std::string>();
  }

  strings_[detected] = std::move(kv);
  return true;
}

bool Manager::set_active(Lang lang) {
  if (strings_.find(lang) == strings_.end()) return false;
  active_.store(lang, std::memory_order_relaxed);
  return true;
}

bool Manager::is_loaded(Lang lang) const {
  return strings_.find(lang) != strings_.end();
}

int Manager::loaded_count() const {
  return static_cast<int>(strings_.size());
}

int Manager::translation_progress(Lang lang) const {
  if (lang == Lang::EN) return 100;

  auto lang_it = strings_.find(lang);
  if (lang_it == strings_.end()) return 0;

  auto en_it = strings_.find(Lang::EN);
  if (en_it == strings_.end()) return 0;

  const auto &en_kv = en_it->second;
  const auto &lang_kv = lang_it->second;

  if (en_kv.empty()) return 100;

  int translated = 0;
  for (const auto &[key, en_val] : en_kv) {
    auto it = lang_kv.find(key);
    if (it != lang_kv.end() && it->second != en_val)
      ++translated;
  }

  return (translated * 100) / static_cast<int>(en_kv.size());
}

const char *Manager::get(const char *key) const {
  Lang current = active_.load(std::memory_order_relaxed);
  auto lang_it = strings_.find(current);
  if (lang_it == strings_.end()) return key;

  const auto &kv = lang_it->second;
  auto it = kv.find(key);
  if (it == kv.end()) {
    // Fall back to English if available and different from active.
    if (current != Lang::EN) {
      auto en_it = strings_.find(Lang::EN);
      if (en_it != strings_.end()) {
        auto eit = en_it->second.find(key);
        if (eit != en_it->second.end()) return eit->second.c_str();
      }
    }
    return key;
  }
  return it->second.c_str();
}

} // namespace memdbg::frontend::locale
