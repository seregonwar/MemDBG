/*
 * MemDBG - Shared repository utilities (plugin + cheat).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Inline utility functions shared between PluginManager and CheatRepository:
 * string munging, FNV-1a hashing, JSON accessors, and bundled-manifest lookup.
 */

#pragma once

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

namespace memdbg::frontend {

/* ---- String utilities ---- */

inline bool starts_with(const std::string &value, const char *prefix) {
  const std::string p(prefix);
  return value.size() >= p.size() && value.compare(0, p.size(), p) == 0;
}

inline std::string trim_copy(std::string value) {
  auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(),
      [&](char c) { return !is_space(static_cast<unsigned char>(c)); }));
  value.erase(std::find_if(value.rbegin(), value.rend(),
      [&](char c) { return !is_space(static_cast<unsigned char>(c)); }).base(),
      value.end());
  return value;
}

inline std::string lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

/* ---- Hashing ---- */

inline uint64_t fnv1a64(const std::string &value) {
  uint64_t hash = 1469598103934665603ULL;
  for (unsigned char c : value) {
    hash ^= c;
    hash *= 1099511628211ULL;
  }
  return hash;
}

inline std::string slugify(const std::string &value, const char *fallback) {
  std::string out;
  out.reserve(value.size());
  bool prev_dash = false;
  for (unsigned char c : value) {
    if (std::isalnum(c) != 0) {
      out.push_back(static_cast<char>(std::tolower(c)));
      prev_dash = false;
    } else if (!prev_dash && !out.empty()) {
      out.push_back('-');
      prev_dash = true;
    }
  }
  while (!out.empty() && out.back() == '-') out.pop_back();
  if (out.empty()) out = fallback;
  return out;
}

inline std::string make_source_id(const std::string &url) {
  std::ostringstream oss;
  oss << std::hex << std::nouppercase << fnv1a64(url);
  return slugify(url, "source") + "-" + oss.str();
}

/* ---- URL utilities ---- */

inline bool is_remote_url(const std::string &value) {
  const std::string lower = lower_copy(value);
  return starts_with(lower, "http://") || starts_with(lower, "https://");
}

/* ---- JSON helpers ---- */

inline std::string json_string(const nlohmann::json &doc,
                               std::initializer_list<const char *> keys,
                               const std::string &fallback = {}) {
  for (const char *key : keys) {
    auto it = doc.find(key);
    if (it != doc.end() && it->is_string())
      return trim_copy(it->get<std::string>());
  }
  return fallback;
}

inline bool json_bool(const nlohmann::json &doc, const char *key,
                      bool fallback) {
  auto it = doc.find(key);
  if (it == doc.end()) return fallback;
  if (it->is_boolean()) return it->get<bool>();
  if (it->is_string()) {
    const std::string value = lower_copy(trim_copy(it->get<std::string>()));
    return value == "1" || value == "true" || value == "yes" || value == "on";
  }
  return fallback;
}

inline uint64_t json_u64(const nlohmann::json &doc,
                         std::initializer_list<const char *> keys,
                         uint64_t fallback = 0) {
  for (const char *key : keys) {
    auto it = doc.find(key);
    if (it == doc.end()) continue;
    if (it->is_number_unsigned()) return it->get<uint64_t>();
    if (it->is_number_integer()) {
      const int64_t value = it->get<int64_t>();
      return value > 0 ? static_cast<uint64_t>(value) : 0U;
    }
    if (it->is_string()) {
      try {
        const std::string value_str = trim_copy(it->get<std::string>());
        if (!value_str.empty())
          return static_cast<uint64_t>(std::stoull(value_str));
      } catch (...) {
      }
    }
  }
  return fallback;
}

/* ---- Filesystem ---- */

inline std::filesystem::path find_bundled_manifest(
    const std::filesystem::path &bundle_root, const char *repo_dir_name) {
  std::vector<std::filesystem::path> roots;
  if (!bundle_root.empty()) roots.push_back(bundle_root);
  std::error_code ec;
  roots.push_back(std::filesystem::current_path(ec));

  for (const auto &root : roots) {
    if (root.empty()) continue;
    std::filesystem::path current = root;
    for (int depth = 0; depth < 8; ++depth) {
      const auto candidate = current / repo_dir_name / "manifest.json";
      ec.clear();
      if (std::filesystem::exists(candidate, ec) && !ec)
        return std::filesystem::weakly_canonical(candidate, ec);
      if (!current.has_parent_path() || current.parent_path() == current)
        break;
      current = current.parent_path();
    }
  }
  return {};
}

} // namespace memdbg::frontend
