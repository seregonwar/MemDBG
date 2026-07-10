/*
 * MemDBG - Frontend plugin repository and script runner.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_PLUGIN_MANAGER_HPP
#define MEMDBG_FRONTEND_PLUGIN_MANAGER_HPP

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace memdbg::frontend::plugins {

constexpr const char *kDefaultSourceName = "MemDBG Plugin Repo";
constexpr const char *kDefaultSourceUrl =
    "https://raw.githubusercontent.com/seregonwar/MemDBG-Plugin/main/manifest.json";

enum class PluginLanguage {
  Unknown,
  Python,
  Lua,
};

struct PluginSource {
  std::string id;
  std::string name;
  std::string url;
  bool enabled = true;
  bool last_ok = false;
  std::string status;
};

struct PluginFile {
  std::string path;
  std::string url;
  std::string resolved_url;
  std::string sha256;
};

struct PluginPackage {
  std::string source_id;
  std::string source_name;
  std::string source_url;
  std::filesystem::path source_manifest_path;

  std::string id;
  std::string name;
  std::string version;
  std::string short_description;
  std::string description;
  std::string author;
  std::string icon_url;
  std::string homepage;
  std::string repository;
  std::string license;
  std::string min_memdbg_version;
  uint64_t download_count = 0;
  PluginLanguage language = PluginLanguage::Unknown;
  std::string entry;
  std::vector<std::string> tags;
  std::vector<std::string> permissions;
  std::vector<PluginFile> files;

  bool installed = false;
  bool enabled = true;
  std::filesystem::path installed_path;
};

struct PluginRunContext {
  std::string host;
  int debug_port = 0;
  int udp_port = 0;
  bool connected = false;
  int32_t selected_pid = 0;
  std::string selected_process_name;
  std::string dump_path;
  std::string trainer_file_path;
  uint32_t protocol_version = 0;
  uint32_t capabilities = 0;
  size_t map_count = 0;
  size_t scan_hit_count = 0;
  size_t trainer_entry_count = 0;

  // Sandbox policy (from user settings)
  bool sandbox_enabled = true;
  bool sandbox_filesystem = false;
  bool sandbox_subprocess = false;
  bool sandbox_network = false;
  bool sandbox_native_modules = false;
  char sandbox_require_whitelist[512] = "";
};

struct PluginRunResult {
  bool ok = false;
  int exit_code = -1;
  std::string plugin_id;
  std::string command;
  std::string output;
  std::string error;
};

std::string normalize_source_url(std::string value);
const char *language_name(PluginLanguage language);
PluginLanguage language_from_string(const std::string &value);

class PluginManager {
public:
  void set_bundle_root(std::filesystem::path root);

  bool load(std::string *error = nullptr);
  bool save(std::string *error = nullptr) const;

  std::vector<PluginSource> sources() const;
  std::vector<PluginPackage> catalog() const;

  bool add_source(const std::string &name, const std::string &url,
                  std::string *error = nullptr);
  bool remove_source(size_t index, std::string *error = nullptr);
  bool set_source_enabled(size_t index, bool enabled,
                          std::string *error = nullptr);

  bool refresh_all(std::string *error = nullptr);
  bool refresh_source(size_t index, std::string *error = nullptr);

  bool install_package(const std::string &package_id,
                       const std::string &source_id,
                       std::string *error = nullptr);
  bool uninstall_package(const std::string &package_id,
                         std::string *error = nullptr);
  bool set_package_enabled(const std::string &package_id, bool enabled,
                           std::string *error = nullptr);

  PluginRunResult run_plugin(const std::string &package_id,
                             const PluginRunContext &context);

  std::filesystem::path bundled_manifest_path() const;
  std::filesystem::path config_path() const;
  std::filesystem::path plugin_data_dir() const;

  struct InstalledRecord {
    std::string source_id;
    std::string source_url;
    std::string name;
    std::string version;
    std::string entry;
    PluginLanguage language = PluginLanguage::Unknown;
    bool enabled = true;
    std::filesystem::path path;
  };

private:
  bool load_unlocked(std::string *error);
  bool save_unlocked(std::string *error) const;
  void ensure_defaults_unlocked();
  void load_cached_catalog_unlocked();

  bool refresh_sources(const std::vector<PluginSource> &sources,
                       std::vector<PluginSource> &out_sources,
                       std::vector<PluginPackage> &out_catalog,
                       std::string *error);
  bool refresh_one(const PluginSource &source,
                   PluginSource &out_source,
                   std::vector<PluginPackage> &out_packages,
                   std::string *error);

  bool install_package_unlocked(const PluginPackage &package,
                                std::string *error);
  bool find_package_unlocked(const std::string &package_id,
                             const std::string &source_id,
                             PluginPackage &out) const;
  bool find_installed_unlocked(const std::string &package_id,
                               InstalledRecord &out) const;

  std::filesystem::path source_cache_manifest_path(const PluginSource &source) const;

  mutable std::mutex mutex_;
  std::filesystem::path bundle_root_;
  std::filesystem::path bundled_manifest_path_;
  std::vector<PluginSource> sources_;
  std::vector<PluginPackage> catalog_;
  std::unordered_map<std::string, InstalledRecord> installed_;
};

} // namespace memdbg::frontend::plugins

#endif /* MEMDBG_FRONTEND_PLUGIN_MANAGER_HPP */
