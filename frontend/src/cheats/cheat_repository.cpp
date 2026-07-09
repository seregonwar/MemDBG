/*
 * MemDBG - Cheat repository and source management.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "cheat_repository.hpp"

#include "core/repo_utils.hpp"
#include "platform.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <system_error>

namespace memdbg::frontend::cheats {

namespace {

using memdbg::frontend::starts_with;
using memdbg::frontend::trim_copy;
using memdbg::frontend::lower_copy;
using memdbg::frontend::make_source_id;
using memdbg::frontend::is_remote_url;
using memdbg::frontend::json_string;
using memdbg::frontend::json_bool;
using memdbg::frontend::json_u64;
using memdbg::frontend::find_bundled_manifest;

std::string make_cheat_install_key(const std::string &game_id,
                                   const std::string &version) {
  return game_id + "/" + version;
}

} // namespace

const char *cheat_format_name(CheatFormat fmt) {
  switch (fmt) {
  case CheatFormat::JSON: return "GoldHEN JSON";
  case CheatFormat::SHN:  return "Reaper SHN";
  case CheatFormat::MC4:  return "Reaper MC4";
  default:                return "Unknown";
  }
}

CheatFormat cheat_format_from_string(const std::string &value) {
  const std::string lower = lower_copy(trim_copy(value));
  if (lower == "json" || lower == "goldhen") return CheatFormat::JSON;
  if (lower == "shn" || lower == "reaper") return CheatFormat::SHN;
  if (lower == "mc4") return CheatFormat::MC4;
  return CheatFormat::Unknown;
}

std::string cheat_format_ext(CheatFormat fmt) {
  switch (fmt) {
  case CheatFormat::JSON: return ".json";
  case CheatFormat::SHN:  return ".shn";
  case CheatFormat::MC4:  return ".mc4";
  default:                return ".json";
  }
}

void CheatRepository::set_bundle_root(std::filesystem::path root) {
  std::lock_guard<std::mutex> lock(mutex_);
  bundle_root_ = std::move(root);
  bundled_manifest_path_ = find_bundled_manifest(bundle_root_, "cheat-repository");
}

std::filesystem::path CheatRepository::bundled_manifest_path() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return bundled_manifest_path_;
}

std::filesystem::path CheatRepository::config_path() const {
  return platform::app_config_dir() / "cheats.json";
}

std::filesystem::path CheatRepository::cheat_data_dir() const {
  return platform::app_data_dir() / "cheats";
}

std::filesystem::path CheatRepository::source_cache_manifest_path(const CheatSource &source) const {
  return platform::app_cache_dir() / "cheats" / "sources" / source.id / "index.txt";
}

/* ---- Load / Save ---- */

bool CheatRepository::load(std::string *error) {
  std::lock_guard<std::mutex> lock(mutex_);
  return load_unlocked(error);
}

bool CheatRepository::load_unlocked(std::string *error) {
  sources_.clear();
  catalog_.clear();
  installed_.clear();

  if (bundled_manifest_path_.empty())
    bundled_manifest_path_ = find_bundled_manifest(bundle_root_, "cheat-repository");

  nlohmann::json doc;
  const auto path = config_path();
  std::ifstream in(path, std::ios::binary);
  if (in) {
    try {
      in >> doc;
    } catch (const std::exception &ex) {
      if (error != nullptr) *error = "Cheat settings parse failed: " + std::string(ex.what());
      ensure_defaults_unlocked();
      load_cached_catalog_unlocked();
      return false;
    }

    if (auto sources_it = doc.find("sources");
        sources_it != doc.end() && sources_it->is_array()) {
      for (const auto &src_doc : *sources_it) {
        if (!src_doc.is_object()) continue;
        CheatSource source;
        source.name = json_string(src_doc, {"name"}, "Cheat Source");
        source.url = json_string(src_doc, {"url"});
        if (source.url.empty()) continue;
        source.id = json_string(src_doc, {"id"}, make_source_id(source.url));
        source.cheats_base_url = json_string(src_doc, {"cheats_base_url"});
        source.index_format = json_string(src_doc, {"index_format"}, "flat_txt");
        source.format = json_string(src_doc, {"format"}, "json");
        source.homepage = json_string(src_doc, {"homepage"});
        source.enabled = json_bool(src_doc, "enabled", true);
        source.status = "Cached";
        sources_.push_back(std::move(source));
      }
    }

    if (auto installed_it = doc.find("installed");
        installed_it != doc.end() && installed_it->is_object()) {
      for (auto it = installed_it->begin(); it != installed_it->end(); ++it) {
        if (!it.value().is_object()) continue;
        InstalledRecord record;
        record.source_id = json_string(it.value(), {"source_id"});
        record.game_id = json_string(it.value(), {"game_id"});
        record.version = json_string(it.value(), {"version"});
        record.format = json_string(it.value(), {"format"});
        record.path = json_string(it.value(), {"path"});
        if (!record.game_id.empty())
          installed_[make_cheat_install_key(record.game_id, record.version)] = std::move(record);
      }
    }
  }

  ensure_defaults_unlocked();
  load_cached_catalog_unlocked();
  return true;
}

bool CheatRepository::save(std::string *error) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return save_unlocked(error);
}

bool CheatRepository::save_unlocked(std::string *error) const {
  std::error_code ec;
  const auto path = config_path();
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    if (error != nullptr) *error = "Cannot create cheat config directory: " + ec.message();
    return false;
  }

  nlohmann::json doc;
  doc["schema"] = 1;
  doc["sources"] = nlohmann::json::array();
  for (const auto &source : sources_) {
    doc["sources"].push_back({
        {"id", source.id},
        {"name", source.name},
        {"url", source.url},
        {"cheats_base_url", source.cheats_base_url},
        {"index_format", source.index_format},
        {"format", source.format},
        {"homepage", source.homepage},
        {"enabled", source.enabled},
    });
  }

  nlohmann::json installed_json = nlohmann::json::object();
  for (const auto &[key, record] : installed_) {
    installed_json[key] = {
        {"source_id", record.source_id},
        {"game_id", record.game_id},
        {"version", record.version},
        {"format", record.format},
        {"path", record.path.string()},
    };
  }
  doc["installed"] = std::move(installed_json);

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

void CheatRepository::ensure_defaults_unlocked() {
  /* Load default sources from bundled manifest if present */
  if (!bundled_manifest_path_.empty()) {
    std::error_code ec;
    if (std::filesystem::exists(bundled_manifest_path_, ec)) {
      nlohmann::json doc;
      std::ifstream in(bundled_manifest_path_, std::ios::binary);
      if (in) {
        try {
          in >> doc;
        } catch (...) {}

        if (auto srcs = doc.find("sources"); srcs != doc.end() && srcs->is_array()) {
          for (const auto &src_doc : *srcs) {
            if (!src_doc.is_object()) continue;
            CheatSource source;
            source.name = json_string(src_doc, {"name"}, "Cheat Source");
            source.url = json_string(src_doc, {"url"});
            if (source.url.empty()) continue;
            source.id = json_string(src_doc, {"id"}, make_source_id(source.url));
            source.cheats_base_url = json_string(src_doc, {"cheats_base_url"});
            source.index_format = json_string(src_doc, {"index_format"}, "flat_txt");
            source.format = json_string(src_doc, {"format"}, "json");
            source.homepage = json_string(src_doc, {"homepage"});
            source.enabled = true;
            source.status = "Bundled";

            /* Check if already present */
            bool exists = false;
            for (const auto &s : sources_) {
              if (s.url == source.url) { exists = true; break; }
            }
            if (!exists) sources_.push_back(std::move(source));
          }
        }
      }
    }
  }
}

void CheatRepository::load_cached_catalog_unlocked() {
  catalog_.clear();
  for (auto &source : sources_) {
    if (!source.enabled) {
      source.status = "Disabled";
      source.last_ok = false;
      continue;
    }
    const std::filesystem::path cache_path = source_cache_manifest_path(source);
    std::error_code ec;
    if (!std::filesystem::exists(cache_path, ec)) {
      source.status = "Not refreshed";
      source.last_ok = false;
      continue;
    }

    /* Read cached index file */
    std::ifstream in(cache_path, std::ios::binary);
    if (!in) {
      source.status = "Cannot read cache";
      source.last_ok = false;
      continue;
    }
    std::string content((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());

    std::vector<CheatCatalogEntry> entries;
    std::string parse_error;
    bool ok = false;
    if (source.index_format == "flat_txt") {
      ok = parse_flat_txt_index(content, source, entries, &parse_error);
    } else {
      ok = parse_manifest_json(content, source, entries, &parse_error);
    }

    if (ok) {
      source.status = "Cached (" + std::to_string(entries.size()) + " cheats)";
      source.cheat_count = static_cast<int>(entries.size());
      source.last_ok = true;
      catalog_.insert(catalog_.end(), entries.begin(), entries.end());
    } else {
      source.status = parse_error.empty() ? "Index parse failed" : parse_error;
      source.last_ok = false;
    }
  }

  /* Mark installed entries */
  for (auto &entry : catalog_) {
    auto it = installed_.find(make_cheat_install_key(entry.game_id, entry.version));
    if (it != installed_.end()) {
      entry.installed = true;
      entry.installed_path = it->second.path;
    }
  }
}

/* ---- Public accessors ---- */

std::vector<CheatSource> CheatRepository::sources() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return sources_;
}

std::vector<CheatCatalogEntry> CheatRepository::catalog() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<CheatCatalogEntry> out = catalog_;
  for (auto &entry : out) {
    auto it = installed_.find(make_cheat_install_key(entry.game_id, entry.version));
    if (it != installed_.end()) {
      entry.installed = true;
      entry.installed_path = it->second.path;
    }
  }
  return out;
}

/* ---- Source management ---- */

bool CheatRepository::add_source(const std::string &name,
                                 const std::string &url,
                                 const std::string &cheats_base_url,
                                 const std::string &index_format,
                                 const std::string &format,
                                 const std::string &homepage,
                                 std::string *error) {
  const std::string trimmed_url = trim_copy(url);
  if (trimmed_url.empty()) {
    if (error != nullptr) *error = "Source URL is empty";
    return false;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto &existing : sources_) {
    if (existing.url == trimmed_url) {
      if (error != nullptr) *error = "Source already exists";
      return false;
    }
  }

  CheatSource source;
  source.name = trim_copy(name).empty() ? "Cheat Repository" : trim_copy(name);
  source.url = trimmed_url;
  source.id = make_source_id(trimmed_url);
  source.cheats_base_url = trim_copy(cheats_base_url);
  source.index_format = trim_copy(index_format).empty() ? "flat_txt" : trim_copy(index_format);
  source.format = trim_copy(format).empty() ? "json" : trim_copy(format);
  source.homepage = trim_copy(homepage);
  source.enabled = true;
  source.status = "Not refreshed";
  sources_.push_back(std::move(source));
  return save_unlocked(error);
}

bool CheatRepository::remove_source(size_t index, std::string *error) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (index >= sources_.size()) {
    if (error != nullptr) *error = "Source index out of range";
    return false;
  }
  sources_.erase(sources_.begin() + static_cast<std::ptrdiff_t>(index));
  load_cached_catalog_unlocked();
  return save_unlocked(error);
}

bool CheatRepository::set_source_enabled(size_t index, bool enabled,
                                         std::string *error) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (index >= sources_.size()) {
    if (error != nullptr) *error = "Source index out of range";
    return false;
  }
  sources_[index].enabled = enabled;
  load_cached_catalog_unlocked();
  return save_unlocked(error);
}

/* ---- Refresh ---- */

bool CheatRepository::refresh_all(std::string *error) {
  std::vector<CheatSource> sources_copy;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    sources_copy = sources_;
  }

  std::vector<CheatSource> refreshed_sources;
  std::vector<CheatCatalogEntry> refreshed_catalog;
  const bool ok = refresh_sources(sources_copy, refreshed_sources, refreshed_catalog, error);

  {
    std::lock_guard<std::mutex> lock(mutex_);
    sources_ = std::move(refreshed_sources);
    catalog_ = std::move(refreshed_catalog);
    for (auto &entry : catalog_) {
      auto it = installed_.find(make_cheat_install_key(entry.game_id, entry.version));
      if (it != installed_.end()) {
        entry.installed = true;
        entry.installed_path = it->second.path;
      }
    }
    std::string save_error;
    (void)save_unlocked(&save_error);
  }
  return ok;
}

bool CheatRepository::refresh_source(size_t index, std::string *error) {
  CheatSource source;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= sources_.size()) {
      if (error != nullptr) *error = "Source index out of range";
      return false;
    }
    source = sources_[index];
  }

  CheatSource refreshed;
  std::vector<CheatCatalogEntry> packages;
  const bool ok = refresh_one(source, refreshed, packages, error);

  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < sources_.size()) sources_[index] = refreshed;
    catalog_.erase(std::remove_if(catalog_.begin(), catalog_.end(),
        [&](const CheatCatalogEntry &entry) { return entry.source_id == source.id; }),
        catalog_.end());
    catalog_.insert(catalog_.end(), packages.begin(), packages.end());
    for (auto &entry : catalog_) {
      auto it = installed_.find(make_cheat_install_key(entry.game_id, entry.version));
      if (it != installed_.end()) {
        entry.installed = true;
        entry.installed_path = it->second.path;
      }
    }
    std::string save_error;
    (void)save_unlocked(&save_error);
  }
  return ok;
}

bool CheatRepository::refresh_sources(const std::vector<CheatSource> &sources,
                                      std::vector<CheatSource> &out_sources,
                                      std::vector<CheatCatalogEntry> &out_catalog,
                                      std::string *error) {
  bool all_ok = true;
  std::string first_error;
  out_sources.clear();
  out_catalog.clear();
  for (const auto &source : sources) {
    CheatSource refreshed;
    std::vector<CheatCatalogEntry> packages;
    std::string source_error;
    if (!refresh_one(source, refreshed, packages, &source_error)) {
      all_ok = false;
      if (first_error.empty()) first_error = source.name + ": " + source_error;
    }
    out_sources.push_back(std::move(refreshed));
    out_catalog.insert(out_catalog.end(), packages.begin(), packages.end());
  }
  if (!all_ok && error != nullptr) *error = first_error;
  return all_ok;
}

bool CheatRepository::refresh_one(const CheatSource &source,
                                  CheatSource &out_source,
                                  std::vector<CheatCatalogEntry> &out_packages,
                                  std::string *error) {
  out_source = source;
  out_packages.clear();
  if (!out_source.enabled) {
    out_source.status = "Disabled";
    out_source.last_ok = false;
    return true;
  }

  /* Download the index file */
  const std::filesystem::path cache_path = source_cache_manifest_path(out_source);
  std::error_code ec;
  std::filesystem::create_directories(cache_path.parent_path(), ec);

  if (is_remote_url(out_source.url)) {
    const auto tmp = cache_path.string() + ".tmp";
    std::filesystem::remove(tmp, ec);
    if (!platform::download_file(out_source.url, tmp)) {
      out_source.status = "Download failed";
      out_source.last_ok = false;
      if (error != nullptr) *error = "Download failed: " + out_source.url;
      std::filesystem::remove(tmp, ec);
      return false;
    }
    std::filesystem::rename(tmp, cache_path, ec);
  }

  /* Read and parse */
  std::ifstream in(cache_path, std::ios::binary);
  if (!in) {
    out_source.status = "Cannot read downloaded index";
    out_source.last_ok = false;
    if (error != nullptr) *error = "Cannot read: " + cache_path.string();
    return false;
  }
  std::string content((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());

  std::string parse_error;
  bool ok = false;
  if (out_source.index_format == "flat_txt") {
    ok = parse_flat_txt_index(content, out_source, out_packages, &parse_error);
  } else {
    ok = parse_manifest_json(content, out_source, out_packages, &parse_error);
  }

  if (!ok) {
    out_source.status = parse_error;
    out_source.last_ok = false;
    if (error != nullptr) *error = parse_error;
    return false;
  }

  out_source.cheat_count = static_cast<int>(out_packages.size());
  out_source.status = "Ready (" + std::to_string(out_packages.size()) + " cheats)";
  out_source.last_ok = true;
  return true;
}

/* ---- Index parsers ---- */

bool CheatRepository::parse_flat_txt_index(const std::string &content,
                                           const CheatSource &source,
                                           std::vector<CheatCatalogEntry> &entries,
                                           std::string *error) {
  entries.clear();
  /* Format: CUSA00002_01.00.json=Killzone: Shadow Fall */
  std::istringstream iss(content);
  std::string line;
  int line_num = 0;

  while (std::getline(iss, line)) {
    ++line_num;
    line = trim_copy(line);
    if (line.empty() || line[0] == '#') continue;

    /* Split on first '=' */
    const size_t eq = line.find('=');
    if (eq == std::string::npos || eq == 0) continue;

    const std::string filename = trim_copy(line.substr(0, eq));
    const std::string title = trim_copy(line.substr(eq + 1));

    /* Parse filename: CUSA00002_01.00.json -> game_id=CUSA00002, version=01.00, ext=json
       Also handles variants like CUSA00018_01.21_default.elf.json -> game_id=CUSA00018, version=01.21 */
    const size_t dot = filename.find_last_of('.');
    const std::string ext = (dot != std::string::npos) ? lower_copy(filename.substr(dot)) : "";
    const std::string name_part = (dot != std::string::npos) ? filename.substr(0, dot) : filename;

    /* Game IDs are 9 chars: CUSA + 5 digits or PPSA + 5 digits.
       Minimum filename is just the ID (e.g. CUSA12345.json). */
    if (name_part.size() < 9) continue;
    const std::string game_id = name_part.substr(0, 9);
    std::string version;
    if (name_part.size() >= 11 && name_part[9] == '_') {
      const std::string rest = name_part.substr(10); /* skip "CUSA00000_" */
      const size_t next_us = rest.find('_');
      version = (next_us != std::string::npos) ? rest.substr(0, next_us) : rest;
    }

    CheatCatalogEntry entry;
    entry.source_id = source.id;
    entry.source_name = source.name;
    entry.game_id = game_id;
    entry.title = title;
    entry.version = version;
    entry.format = source.format;
    entry.path = source.format + "/" + filename;
    entry.url = source.cheats_base_url + "cheats/" + source.format + "/" + filename;

    entries.push_back(std::move(entry));
  }

  if (entries.empty() && error != nullptr)
    *error = "No cheat entries found in index (parsed " + std::to_string(line_num) + " lines)";

  return !entries.empty();
}

bool CheatRepository::parse_manifest_json(const std::string &content,
                                          const CheatSource &source,
                                          std::vector<CheatCatalogEntry> &entries,
                                          std::string *error) {
  entries.clear();
  nlohmann::json doc;
  try {
    doc = nlohmann::json::parse(content);
  } catch (const std::exception &ex) {
    if (error != nullptr) *error = "JSON parse failed: " + std::string(ex.what());
    return false;
  }

  auto cheats_it = doc.find("cheats");
  if (cheats_it == doc.end() || !cheats_it->is_array()) {
    if (error != nullptr) *error = "Manifest needs a cheats array";
    return false;
  }

  for (const auto &item : *cheats_it) {
    if (!item.is_object()) continue;

    CheatCatalogEntry entry;
    entry.source_id = source.id;
    entry.source_name = source.name;
    entry.game_id = json_string(item, {"game_id", "id"});
    entry.title = json_string(item, {"title", "name"});
    entry.version = json_string(item, {"version"});
    entry.format = json_string(item, {"format"}, source.format);
    entry.path = json_string(item, {"path"});
    entry.url = json_string(item, {"url"});
    entry.credits = json_string(item, {"credits"});
    entry.size = json_u64(item, {"size"});

    if (entry.game_id.empty() || entry.url.empty()) continue;
    if (entry.title.empty()) entry.title = entry.game_id;

    /* Build URL from path if not specified */
    if (entry.url.empty() && !entry.path.empty())
      entry.url = source.cheats_base_url + entry.path;

    entries.push_back(std::move(entry));
  }

  if (entries.empty() && error != nullptr)
    *error = "No valid cheat entries in manifest";
  return !entries.empty();
}

/* ---- Lookup helpers ---- */

bool CheatRepository::find_entry_unlocked(const std::string &game_id,
                                          const std::string &version,
                                          const std::string &source_id,
                                          CheatCatalogEntry &out) const {
  for (const auto &entry : catalog_) {
    if (entry.game_id != game_id) continue;
    if (!version.empty() && entry.version != version) continue;
    if (!source_id.empty() && entry.source_id != source_id) continue;
    out = entry;
    return true;
  }
  return false;
}

bool CheatRepository::find_installed_unlocked(const std::string &game_id,
                                              const std::string &version,
                                              InstalledRecord &out) const {
  auto it = installed_.find(make_cheat_install_key(game_id, version));
  if (it == installed_.end()) return false;
  out = it->second;
  return true;
}

/* ---- Install / Uninstall ---- */

bool CheatRepository::install_cheat(const std::string &game_id,
                                    const std::string &version,
                                    const std::string &source_id,
                                    std::string *error) {
  CheatCatalogEntry entry;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!find_entry_unlocked(game_id, version, source_id, entry)) {
      if (error != nullptr) *error = "Cheat not found in catalog";
      return false;
    }
  }

  std::string install_error;
  if (!install_cheat_unlocked(entry, &install_error)) {
    if (error != nullptr) *error = install_error;
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    InstalledRecord record;
    record.source_id = entry.source_id;
    record.game_id = entry.game_id;
    record.version = entry.version;
    record.format = entry.format;
    record.path = cheat_data_dir() / entry.game_id / (entry.version + cheat_format_ext(
        cheat_format_from_string(entry.format)));
    installed_[make_cheat_install_key(entry.game_id, entry.version)] = record;
    entry.installed = true;
    entry.installed_path = record.path;
    for (auto &cat_entry : catalog_) {
      if (cat_entry.game_id == entry.game_id && cat_entry.version == entry.version) {
        cat_entry.installed = true;
        cat_entry.installed_path = record.path;
      }
    }
    return save_unlocked(error);
  }
}

bool CheatRepository::install_cheat_unlocked(const CheatCatalogEntry &entry,
                                             std::string *error) {
  if (entry.url.empty()) {
    if (error != nullptr) *error = "Cheat has no download URL";
    return false;
  }

  const auto dest = cheat_data_dir() / entry.game_id /
                    (entry.version + cheat_format_ext(cheat_format_from_string(entry.format)));
  std::error_code ec;
  std::filesystem::create_directories(dest.parent_path(), ec);
  if (ec) {
    if (error != nullptr) *error = "Cannot create cheat directory: " + ec.message();
    return false;
  }

  if (!is_remote_url(entry.url)) {
    if (error != nullptr) *error = "Only remote URLs are supported for cheat download";
    return false;
  }

  const auto tmp = dest.string() + ".tmp";
  std::filesystem::remove(tmp, ec);
  if (!platform::download_file(entry.url, tmp)) {
    if (error != nullptr) *error = "Download failed: " + entry.url;
    std::filesystem::remove(tmp, ec);
    return false;
  }
  std::filesystem::rename(tmp, dest, ec);
  if (ec) {
    std::filesystem::remove(dest, ec);
    ec.clear();
    std::filesystem::rename(tmp, dest, ec);
  }
  if (ec) {
    if (error != nullptr) *error = "Cannot move downloaded file: " + ec.message();
    std::filesystem::remove(tmp, ec);
    return false;
  }
  return true;
}

bool CheatRepository::uninstall_cheat(const std::string &game_id,
                                      const std::string &version,
                                      std::string *error) {
  std::lock_guard<std::mutex> lock(mutex_);
  InstalledRecord record;
  if (!find_installed_unlocked(game_id, version, record)) {
    if (error != nullptr) *error = "Cheat is not installed";
    return false;
  }

  std::error_code ec;
  if (!record.path.empty()) std::filesystem::remove(record.path, ec);
  installed_.erase(make_cheat_install_key(game_id, version));

  for (auto &entry : catalog_) {
    if (entry.game_id == game_id && entry.version == version) {
      entry.installed = false;
      entry.installed_path.clear();
    }
  }
  return save_unlocked(error);
}

/* ---- Fetch content ---- */

bool CheatRepository::fetch_cheat_content(const CheatCatalogEntry &entry,
                                          std::string &content,
                                          std::string *error) {
  /* Check installed first */
  {
    std::lock_guard<std::mutex> lock(mutex_);
    InstalledRecord record;
    if (find_installed_unlocked(entry.game_id, entry.version, record)) {
      std::ifstream in(record.path, std::ios::binary);
      if (in) {
        content.assign((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
        return true;
      }
    }
  }

  /* Download from remote */
  if (entry.url.empty()) {
    if (error != nullptr) *error = "No URL for cheat content";
    return false;
  }

  /* Download to temp and read */
  const auto tmp_dir = platform::app_cache_dir() / "cheats" / "temp";
  std::error_code ec;
  std::filesystem::create_directories(tmp_dir, ec);
  const auto tmp = tmp_dir / (entry.game_id + "_" + entry.version + ".tmp");
  std::filesystem::remove(tmp, ec);

  if (!platform::download_file(entry.url, tmp)) {
    if (error != nullptr) *error = "Download failed: " + entry.url;
    std::filesystem::remove(tmp, ec);
    return false;
  }

  std::ifstream in(tmp, std::ios::binary);
  if (!in) {
    if (error != nullptr) *error = "Cannot read downloaded cheat";
    std::filesystem::remove(tmp, ec);
    return false;
  }
  content.assign((std::istreambuf_iterator<char>(in)),
                  std::istreambuf_iterator<char>());
  std::filesystem::remove(tmp, ec);
  return true;
}

} // namespace memdbg::frontend::cheats
