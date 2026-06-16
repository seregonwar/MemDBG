/*
 * MemDBG - Locale / i18n system.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Community-friendly translation layer.
 * Add or update JSON files under locales/ to contribute a language.
 */

#ifndef MEMDBG_FRONTEND_LOCALE_HPP
#define MEMDBG_FRONTEND_LOCALE_HPP

#include <atomic>
#include <cstddef>
#include <string>
#include <unordered_map>

namespace memdbg::frontend::locale {

// ---- Language codes ----
enum class Lang : int {
  EN = 0,  // English
  ES,      // Spanish
  IT,      // Italian
  FR,      // French
  PT,      // Portuguese
  DE,      // German
  RU,      // Russian
  JA,      // Japanese
  COUNT
};

const char *lang_code(Lang lang);
const char *lang_name(Lang lang);

// Parse a language code string ("en", "es", ...) to Lang. Returns EN on failure.
Lang lang_from_code(const char *code);

// Detect OS locale and map to a supported language, defaulting to EN.
Lang detect_system_lang();

// ---- Manager ----
// All methods are safe to call from any thread.  tr() uses a relaxed
// atomic load so the active language may lag by at most one frame after
// a set_active() call, which is acceptable for a UI.
class Manager {
public:
  static Manager &instance();

  // Load translations from the given JSON file path. Returns false on error.
  // Must be called before set_active() for the corresponding language.
  bool load(const char *json_path);

  // Switch active language. Returns false if that language was not loaded.
  bool set_active(Lang lang);
  Lang active() const { return active_.load(std::memory_order_relaxed); }

  // Look up a key; returns the key itself as fallback.
  const char *get(const char *key) const;

  // True when at least one translation set is loaded.
  bool ready() const { return !strings_.empty(); }

  // True when translations for `lang` were successfully loaded.
  bool is_loaded(Lang lang) const;

  // Number of loaded languages (for UI feedback).
  int loaded_count() const;

  // Returns 0–100: percentage of keys in `lang` that differ from English.
  // English itself always returns 100.  Unloaded languages return 0.
  int translation_progress(Lang lang) const;

private:
  Manager() = default;

  std::atomic<Lang> active_{Lang::EN};
  // Map:  language -> ( key -> value )
  std::unordered_map<Lang, std::unordered_map<std::string, std::string>> strings_;
};

// ---- Convenience ----

// Returns the translated string for `key` in the active language.
inline const char *tr(const char *key) {
  return Manager::instance().get(key);
}

} // namespace memdbg::frontend::locale

#endif // MEMDBG_FRONTEND_LOCALE_HPP
