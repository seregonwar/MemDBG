/*
 * MemDBG - Frontend plugin repository and script runner.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "plugin_manager.hpp"

#include "platform.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>

#if defined(_WIN32)
#include <process.h>
#define MEMDBG_POPEN _popen
#define MEMDBG_PCLOSE _pclose
#else
#include <sys/wait.h>
#define MEMDBG_POPEN popen
#define MEMDBG_PCLOSE pclose
#endif

namespace memdbg::frontend::plugins {

namespace {

constexpr size_t kMaxCapturedOutput = 256U * 1024U;

bool starts_with(const std::string &value, const char *prefix) {
  const std::string p(prefix);
  return value.size() >= p.size() && value.compare(0, p.size(), p) == 0;
}

bool ends_with(const std::string &value, const char *suffix) {
  const std::string s(suffix);
  return value.size() >= s.size() &&
         value.compare(value.size() - s.size(), s.size(), s) == 0;
}

std::string trim_copy(std::string value) {
  auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(),
      [&](char c) { return !is_space(static_cast<unsigned char>(c)); }));
  value.erase(std::find_if(value.rbegin(), value.rend(),
      [&](char c) { return !is_space(static_cast<unsigned char>(c)); }).base(),
      value.end());
  return value;
}

std::string lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

std::vector<std::string> split_path(std::string value) {
  std::vector<std::string> parts;
  while (!value.empty() && value.front() == '/') value.erase(value.begin());
  std::stringstream ss(value);
  std::string item;
  while (std::getline(ss, item, '/')) {
    if (!item.empty()) parts.push_back(item);
  }
  return parts;
}

uint64_t fnv1a64(const std::string &value) {
  uint64_t hash = 1469598103934665603ULL;
  for (unsigned char c : value) {
    hash ^= c;
    hash *= 1099511628211ULL;
  }
  return hash;
}

std::string hex_u64(uint64_t value) {
  std::ostringstream oss;
  oss << std::hex << std::nouppercase << value;
  return oss.str();
}

std::string slugify(const std::string &value, const char *fallback) {
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

std::string make_source_id(const std::string &url) {
  return slugify(url, "source") + "-" + hex_u64(fnv1a64(url));
}

std::string make_package_dir_name(const std::string &id) {
  return slugify(id, "plugin") + "-" + hex_u64(fnv1a64(id));
}

bool is_remote_url(const std::string &value) {
  const std::string lower = lower_copy(value);
  return starts_with(lower, "http://") || starts_with(lower, "https://");
}

bool is_file_url(const std::string &value) {
  return starts_with(lower_copy(value), "file://");
}

std::filesystem::path expand_home(std::filesystem::path path) {
  const std::string text = path.string();
  if (text.empty() || text[0] != '~') return path;
  const char *home = std::getenv("HOME");
#if defined(_WIN32)
  if (home == nullptr || home[0] == '\0') home = std::getenv("USERPROFILE");
#endif
  if (home == nullptr || home[0] == '\0') return path;
  if (text.size() == 1U) return std::filesystem::path(home);
  if (text[1] == '/' || text[1] == '\\')
    return std::filesystem::path(home) / text.substr(2);
  return path;
}

std::filesystem::path path_from_file_url(const std::string &value) {
  std::string path = value.substr(7);
#if defined(_WIN32)
  if (starts_with(path, "/") && path.size() > 2U && path[2] == ':')
    path.erase(path.begin());
#endif
  return std::filesystem::path(path);
}

std::filesystem::path local_path_from_source_url(const std::string &url) {
  if (is_file_url(url)) return path_from_file_url(url);
  return expand_home(std::filesystem::path(url));
}

std::string parent_url(const std::string &url) {
  const size_t slash = url.find_last_of('/');
  if (slash == std::string::npos) return url;
  return url.substr(0, slash + 1U);
}

bool is_absolute_or_remote(const std::string &value) {
  if (is_remote_url(value) || is_file_url(value)) return true;
  std::filesystem::path path(value);
  return path.is_absolute();
}

std::string normalize_github_url(const std::string &value) {
  const std::string prefix = "https://github.com/";
  const std::string lower = lower_copy(value);
  if (!starts_with(lower, prefix.c_str())) return "";

  std::string rest = value.substr(prefix.size());
  while (!rest.empty() && rest.back() == '/') rest.pop_back();
  std::vector<std::string> parts = split_path(rest);
  if (parts.size() < 2U) return "";

  std::string owner = parts[0];
  std::string repo = parts[1];
  if (ends_with(repo, ".git")) repo.resize(repo.size() - 4U);

  std::string branch = "main";
  std::string path;
  if (parts.size() >= 4U && (parts[2] == "tree" || parts[2] == "blob")) {
    branch = parts[3];
    for (size_t i = 4U; i < parts.size(); ++i) {
      if (!path.empty()) path += "/";
      path += parts[i];
    }
  }

  if (!path.empty() && !ends_with(path, "manifest.json") && parts[2] == "blob") {
    return "https://raw.githubusercontent.com/" + owner + "/" + repo + "/" +
           branch + "/" + path;
  }
  if (!path.empty() && !ends_with(path, "/")) path += "/";
  path += "manifest.json";
  return "https://raw.githubusercontent.com/" + owner + "/" + repo + "/" +
         branch + "/" + path;
}

std::string basename_from_path_or_url(const std::string &value) {
  const size_t slash = value.find_last_of("/\\");
  std::string base = slash == std::string::npos ? value : value.substr(slash + 1U);
  const size_t query = base.find_first_of("?#");
  if (query != std::string::npos) base.resize(query);
  return base.empty() ? "plugin-script" : base;
}

bool relative_path_safe(const std::filesystem::path &path) {
  if (path.empty() || path.is_absolute()) return false;
  for (const auto &part : path) {
    const std::string text = part.string();
    if (text.empty() || text == "." || text == "..") return false;
  }
  return true;
}

std::filesystem::path safe_relative_path(const std::string &path_text,
                                         const std::string &fallback) {
  std::filesystem::path path(path_text.empty() ? fallback : path_text);
  if (relative_path_safe(path)) return path;
  return std::filesystem::path(basename_from_path_or_url(fallback.empty() ? path_text : fallback));
}

std::string shell_quote_posix(const std::string &value) {
  std::string out = "'";
  for (char c : value) {
    if (c == '\'') out += "'\\''";
    else out.push_back(c);
  }
  out += "'";
  return out;
}

[[maybe_unused]] std::string shell_quote_windows(const std::string &value) {
  std::string out = "\"";
  size_t backslashes = 0;
  for (char c : value) {
    if (c == '\\') {
      ++backslashes;
      continue;
    }
    if (c == '"') {
      out.append(backslashes * 2U + 1U, '\\');
      out.push_back('"');
      backslashes = 0;
      continue;
    }
    out.append(backslashes, '\\');
    backslashes = 0;
    out.push_back(c);
  }
  out.append(backslashes * 2U, '\\');
  out.push_back('"');
  return out;
}

std::string shell_quote(const std::string &value) {
#if defined(_WIN32)
  return shell_quote_windows(value);
#else
  return shell_quote_posix(value);
#endif
}

std::string first_command_token(const std::string &command) {
  std::istringstream iss(command);
  std::string token;
  iss >> token;
  return token;
}

bool command_exists(const std::string &command) {
  const std::string token = first_command_token(command);
  if (token.empty()) return false;
#if defined(MEMDBG_PLATFORM_IOS)
  (void)token;
  return false;
#elif defined(_WIN32)
  const std::string check = "where " + shell_quote_windows(token) + " >NUL 2>NUL";
  return std::system(check.c_str()) == 0;
#else
  const std::string check = "command -v " + shell_quote_posix(token) + " >/dev/null 2>&1";
  return std::system(check.c_str()) == 0;
#endif
}

std::string find_interpreter(PluginLanguage language) {
  const std::vector<std::string> candidates =
      language == PluginLanguage::Python
          ? std::vector<std::string>{"python3", "python", "py -3"}
          : std::vector<std::string>{"lua", "luajit", "lua5.4", "lua5.3"};
  for (const auto &candidate : candidates) {
    if (command_exists(candidate)) return candidate;
  }
  return "";
}

int decode_exit_code(int raw) {
  if (raw < 0) return raw;
#if defined(_WIN32)
  return raw;
#else
  if (WIFEXITED(raw)) return WEXITSTATUS(raw);
  if (WIFSIGNALED(raw)) return 128 + WTERMSIG(raw);
  return raw;
#endif
}

PluginRunResult run_shell_capture(const std::string &command) {
  PluginRunResult result;
  result.command = command;

  FILE *pipe = MEMDBG_POPEN(command.c_str(), "r");
  if (pipe == nullptr) {
    result.error = "Cannot start script process";
    return result;
  }

  std::array<char, 4096> buffer{};
  bool truncated = false;
  while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    if (result.output.size() + std::strlen(buffer.data()) <= kMaxCapturedOutput) {
      result.output += buffer.data();
    } else {
      truncated = true;
    }
  }

  const int raw_code = MEMDBG_PCLOSE(pipe);
  result.exit_code = decode_exit_code(raw_code);
  result.ok = result.exit_code == 0;
  if (truncated) result.output += "\n[MemDBG] Output truncated.\n";
  if (!result.ok && result.error.empty())
    result.error = "Script exited with code " + std::to_string(result.exit_code);
  return result;
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

bool json_bool(const nlohmann::json &doc, const char *key, bool fallback) {
  auto it = doc.find(key);
  if (it == doc.end()) return fallback;
  if (it->is_boolean()) return it->get<bool>();
  if (it->is_string()) {
    const std::string value = lower_copy(trim_copy(it->get<std::string>()));
    return value == "1" || value == "true" || value == "yes" || value == "on";
  }
  return fallback;
}

uint64_t json_u64(const nlohmann::json &doc,
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
        const std::string value = trim_copy(it->get<std::string>());
        if (!value.empty()) return static_cast<uint64_t>(std::stoull(value));
      } catch (...) {
      }
    }
  }
  return fallback;
}

std::vector<std::string> json_string_array(const nlohmann::json &doc,
                                           std::initializer_list<const char *> keys) {
  std::vector<std::string> out;
  for (const char *key : keys) {
    auto it = doc.find(key);
    if (it == doc.end()) continue;
    if (it->is_string()) {
      const std::string value = trim_copy(it->get<std::string>());
      if (!value.empty()) out.push_back(value);
      return out;
    }
    if (!it->is_array()) continue;
    for (const auto &item : *it) {
      if (!item.is_string()) continue;
      const std::string value = trim_copy(item.get<std::string>());
      if (!value.empty()) out.push_back(value);
    }
    return out;
  }
  return out;
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

std::filesystem::path find_bundled_manifest(const std::filesystem::path &bundle_root) {
  std::vector<std::filesystem::path> roots;
  if (!bundle_root.empty()) roots.push_back(bundle_root);
  std::error_code ec;
  roots.push_back(std::filesystem::current_path(ec));

  for (const auto &root : roots) {
    if (root.empty()) continue;
    std::filesystem::path current = root;
    for (int depth = 0; depth < 8; ++depth) {
      const auto candidate = current / "plugin-repository" / "manifest.json";
      ec.clear();
      if (std::filesystem::exists(candidate, ec) && !ec)
        return std::filesystem::weakly_canonical(candidate, ec);
      if (!current.has_parent_path() || current.parent_path() == current) break;
      current = current.parent_path();
    }
  }
  return {};
}

std::string resolve_url_or_path(const std::string &base_manifest_url,
                                const std::filesystem::path &manifest_path,
                                const std::string &relative) {
  if (relative.empty()) return relative;
  if (is_absolute_or_remote(relative)) return relative;

  if (is_remote_url(base_manifest_url)) {
    return parent_url(base_manifest_url) + relative;
  }

  std::filesystem::path base;
  if (!manifest_path.empty()) base = manifest_path.parent_path();
  else base = local_path_from_source_url(base_manifest_url).parent_path();
  return (base / relative).string();
}

bool copy_or_download_file(const std::string &url_or_path,
                           const std::filesystem::path &dest,
                           std::string *error) {
  std::error_code ec;
  std::filesystem::create_directories(dest.parent_path(), ec);
  if (ec) {
    if (error != nullptr) *error = "Cannot create " + dest.parent_path().string() + ": " + ec.message();
    return false;
  }

  const auto tmp = dest.string() + ".tmp";
  std::filesystem::remove(tmp, ec);
  if (is_remote_url(url_or_path)) {
    if (!platform::download_file(url_or_path, tmp)) {
      if (error != nullptr) *error = "Download failed: " + url_or_path;
      std::filesystem::remove(tmp, ec);
      return false;
    }
  } else {
    const std::filesystem::path src = is_file_url(url_or_path)
        ? path_from_file_url(url_or_path)
        : expand_home(std::filesystem::path(url_or_path));
    ec.clear();
    std::filesystem::copy_file(src, tmp,
        std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
      if (error != nullptr) *error = "Copy failed: " + src.string() + ": " + ec.message();
      std::filesystem::remove(tmp, ec);
      return false;
    }
  }

  ec.clear();
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

PluginSource default_source() {
  PluginSource source;
  source.id = make_source_id(kDefaultSourceUrl);
  source.name = kDefaultSourceName;
  source.url = kDefaultSourceUrl;
  source.enabled = true;
  source.status = "Not refreshed";
  return source;
}

bool source_is_default(const PluginSource &source) {
  return source.url == kDefaultSourceUrl || normalize_source_url(source.url) == kDefaultSourceUrl;
}

bool parse_manifest_packages(const PluginSource &source,
                             const std::filesystem::path &manifest_path,
                             const nlohmann::json &doc,
                             std::vector<PluginPackage> &packages,
                             std::string *error) {
  const std::string repo_name = json_string(doc, {"name", "label"}, source.name);
  const std::string repo_homepage = json_string(doc, {"homepage", "url", "repository"});
  const nlohmann::json *items = nullptr;
  auto plugins_it = doc.find("plugins");
  auto packages_it = doc.find("packages");
  if (plugins_it != doc.end() && plugins_it->is_array()) items = &(*plugins_it);
  else if (packages_it != doc.end() && packages_it->is_array()) items = &(*packages_it);
  else {
    if (error != nullptr) *error = "Manifest needs a plugins or packages array";
    return false;
  }

  std::vector<PluginPackage> parsed;
  for (const auto &item : *items) {
    if (!item.is_object()) continue;

    PluginPackage pkg;
    pkg.source_id = source.id;
    pkg.source_name = repo_name;
    pkg.source_url = source.url;
    pkg.source_manifest_path = manifest_path;
    pkg.id = json_string(item, {"id", "package", "identifier"});
    pkg.name = json_string(item, {"name", "title"}, pkg.id);
    pkg.version = json_string(item, {"version"}, "0.0.0");
    pkg.short_description = json_string(item, {
        "summary", "short_description", "shortDescription", "subtitle"
    });
    pkg.description = json_string(item, {
        "full_description", "fullDescription",
        "long_description", "longDescription",
        "body", "description"
    }, pkg.short_description);
    if (pkg.short_description.empty()) pkg.short_description = pkg.description;
    pkg.author = json_string(item, {"author", "maintainer"});
    pkg.icon_url = json_string(item, {"icon", "image", "thumbnail", "artwork"});
    if (!pkg.icon_url.empty())
      pkg.icon_url = resolve_url_or_path(source.url, manifest_path, pkg.icon_url);
    pkg.homepage = json_string(item, {"homepage"}, repo_homepage);
    pkg.repository = json_string(item, {"repository"});
    pkg.license = json_string(item, {"license"});
    pkg.min_memdbg_version = json_string(item, {"min_memdbg_version", "minMemDBG"});
    pkg.download_count = json_u64(item, {"downloads", "download_count", "downloadCount"});
    if (auto stats_it = item.find("stats"); stats_it != item.end() && stats_it->is_object()) {
      pkg.download_count = json_u64(*stats_it, {"downloads", "download_count", "downloadCount"},
                                    pkg.download_count);
    }
    pkg.language = language_from_string(json_string(item, {"language", "type"}));
    pkg.entry = json_string(item, {"entry", "main", "script"});
    pkg.tags = json_string_array(item, {"tags", "categories", "section"});
    pkg.permissions = json_string_array(item, {"permissions"});

    if (pkg.id.empty() || pkg.name.empty()) continue;

    auto files_it = item.find("files");
    if (files_it != item.end() && files_it->is_array()) {
      for (const auto &file_item : *files_it) {
        PluginFile file;
        if (file_item.is_string()) {
          file.url = trim_copy(file_item.get<std::string>());
          file.path = file.url;
        } else if (file_item.is_object()) {
          file.path = json_string(file_item, {"path", "name"});
          file.url = json_string(file_item, {"url", "download"}, file.path);
          file.sha256 = json_string(file_item, {"sha256", "hash"});
        }
        if (file.url.empty() && !file.path.empty()) file.url = file.path;
        if (file.path.empty()) file.path = basename_from_path_or_url(file.url);
        file.path = safe_relative_path(file.path, file.url).generic_string();
        file.resolved_url = resolve_url_or_path(source.url, manifest_path, file.url);
        if (!file.resolved_url.empty()) pkg.files.push_back(std::move(file));
      }
    }

    if (pkg.files.empty()) {
      PluginFile file;
      file.url = json_string(item, {"download", "url", "file"}, pkg.entry);
      if (file.url.empty() && !pkg.entry.empty()) file.url = pkg.entry;
      file.path = pkg.entry.empty() ? basename_from_path_or_url(file.url) : pkg.entry;
      file.path = safe_relative_path(file.path, file.url).generic_string();
      file.resolved_url = resolve_url_or_path(source.url, manifest_path, file.url);
      if (!file.resolved_url.empty()) pkg.files.push_back(std::move(file));
    }

    if (pkg.entry.empty() && !pkg.files.empty()) pkg.entry = pkg.files.front().path;
    parsed.push_back(std::move(pkg));
  }

  packages = std::move(parsed);
  return true;
}

void merge_installed_flags(std::vector<PluginPackage> &catalog,
                           const std::unordered_map<std::string, PluginManager::InstalledRecord> &installed) {
  for (auto &pkg : catalog) {
    auto it = installed.find(pkg.id);
    if (it == installed.end()) continue;
    pkg.installed = true;
    pkg.enabled = it->second.enabled;
    pkg.installed_path = it->second.path;
  }
}

} // namespace

std::string normalize_source_url(std::string value) {
  value = trim_copy(std::move(value));
  if (value.empty()) return value;

  const std::string github = normalize_github_url(value);
  if (!github.empty()) return github;

  if (is_remote_url(value)) {
    while (!value.empty() && value.back() == '/') value.pop_back();
    if (ends_with(lower_copy(value), ".json")) return value;
    return value + "/manifest.json";
  }

  if (is_file_url(value)) {
    std::filesystem::path path = path_from_file_url(value);
    if (path.extension() != ".json") path /= "manifest.json";
    return "file://" + path.string();
  }

  std::filesystem::path path = expand_home(std::filesystem::path(value));
  if (path.extension() != ".json") path /= "manifest.json";
  return path.string();
}

const char *language_name(PluginLanguage language) {
  switch (language) {
  case PluginLanguage::Python: return "Python";
  case PluginLanguage::Lua: return "Lua";
  default: return "Unknown";
  }
}

PluginLanguage language_from_string(const std::string &value) {
  const std::string lower = lower_copy(trim_copy(value));
  if (lower == "python" || lower == "py" || lower == "python3") return PluginLanguage::Python;
  if (lower == "lua" || lower == "luajit") return PluginLanguage::Lua;
  return PluginLanguage::Unknown;
}

void PluginManager::set_bundle_root(std::filesystem::path root) {
  std::lock_guard<std::mutex> lock(mutex_);
  bundle_root_ = std::move(root);
  bundled_manifest_path_ = find_bundled_manifest(bundle_root_);
}

std::filesystem::path PluginManager::bundled_manifest_path() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return bundled_manifest_path_;
}

std::filesystem::path PluginManager::config_path() const {
  return platform::app_config_dir() / "plugins.json";
}

std::filesystem::path PluginManager::plugin_data_dir() const {
  return platform::app_data_dir() / "plugins";
}

std::filesystem::path PluginManager::source_cache_manifest_path(const PluginSource &source) const {
  return platform::app_cache_dir() / "plugins" / "sources" / source.id / "manifest.json";
}

bool PluginManager::load(std::string *error) {
  std::lock_guard<std::mutex> lock(mutex_);
  return load_unlocked(error);
}

bool PluginManager::load_unlocked(std::string *error) {
  sources_.clear();
  catalog_.clear();
  installed_.clear();

  if (bundled_manifest_path_.empty()) bundled_manifest_path_ = find_bundled_manifest(bundle_root_);

  nlohmann::json doc;
  const auto path = config_path();
  std::ifstream in(path, std::ios::binary);
  if (in) {
    try {
      in >> doc;
    } catch (const std::exception &ex) {
      if (error != nullptr) *error = "Plugin settings parse failed: " + std::string(ex.what());
      ensure_defaults_unlocked();
      load_cached_catalog_unlocked();
      return false;
    }

    if (auto sources_it = doc.find("sources");
        sources_it != doc.end() && sources_it->is_array()) {
      for (const auto &src_doc : *sources_it) {
        if (!src_doc.is_object()) continue;
        PluginSource source;
        source.name = json_string(src_doc, {"name"}, "Repository");
        source.url = normalize_source_url(json_string(src_doc, {"url"}));
        if (source.url.empty()) continue;
        source.id = json_string(src_doc, {"id"}, make_source_id(source.url));
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
        record.source_url = json_string(it.value(), {"source_url"});
        record.name = json_string(it.value(), {"name"}, it.key());
        record.version = json_string(it.value(), {"version"});
        record.entry = json_string(it.value(), {"entry"});
        record.language = language_from_string(json_string(it.value(), {"language"}));
        record.enabled = json_bool(it.value(), "enabled", true);
        record.path = json_string(it.value(), {"path"});
        if (record.path.empty()) record.path = plugin_data_dir() / make_package_dir_name(it.key());
        installed_[it.key()] = std::move(record);
      }
    }
  }

  ensure_defaults_unlocked();
  load_cached_catalog_unlocked();
  return true;
}

bool PluginManager::save(std::string *error) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return save_unlocked(error);
}

bool PluginManager::save_unlocked(std::string *error) const {
  std::error_code ec;
  const auto path = config_path();
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    if (error != nullptr) *error = "Cannot create plugin config directory: " + ec.message();
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
        {"enabled", source.enabled},
    });
  }

  nlohmann::json installed_json = nlohmann::json::object();
  for (const auto &[id, record] : installed_) {
    installed_json[id] = {
        {"source_id", record.source_id},
        {"source_url", record.source_url},
        {"name", record.name},
        {"version", record.version},
        {"entry", record.entry},
        {"language", language_name(record.language)},
        {"enabled", record.enabled},
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

void PluginManager::ensure_defaults_unlocked() {
  const auto exists = std::find_if(sources_.begin(), sources_.end(),
      [](const PluginSource &source) { return source.url == kDefaultSourceUrl; });
  if (exists == sources_.end()) sources_.insert(sources_.begin(), default_source());
}

void PluginManager::load_cached_catalog_unlocked() {
  catalog_.clear();
  for (auto &source : sources_) {
    if (!source.enabled) {
      source.status = "Disabled";
      source.last_ok = false;
      continue;
    }
    std::filesystem::path manifest = source_cache_manifest_path(source);
    if (!std::filesystem::exists(manifest) && source_is_default(source) &&
        !bundled_manifest_path_.empty()) {
      manifest = bundled_manifest_path_;
    }
    if (!std::filesystem::exists(manifest)) {
      source.status = "Not refreshed";
      source.last_ok = false;
      continue;
    }

    nlohmann::json doc;
    std::string error;
    std::vector<PluginPackage> parsed;
    PluginSource parse_source = source;
    if (manifest == bundled_manifest_path_) parse_source.url = manifest.string();
    if (parse_json_file(manifest, doc, &error) &&
        parse_manifest_packages(parse_source, manifest, doc, parsed, &error)) {
      source.status = manifest == bundled_manifest_path_ ? "Bundled manifest" : "Cached";
      source.last_ok = true;
      catalog_.insert(catalog_.end(), parsed.begin(), parsed.end());
    } else {
      source.status = error.empty() ? "Manifest parse failed" : error;
      source.last_ok = false;
    }
  }
  merge_installed_flags(catalog_, installed_);
}

std::vector<PluginSource> PluginManager::sources() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return sources_;
}

std::vector<PluginPackage> PluginManager::catalog() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<PluginPackage> out = catalog_;
  merge_installed_flags(out, installed_);
  return out;
}

bool PluginManager::add_source(const std::string &name,
                               const std::string &url,
                               std::string *error) {
  const std::string normalized = normalize_source_url(url);
  if (normalized.empty()) {
    if (error != nullptr) *error = "Source URL is empty";
    return false;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  const auto duplicate = std::find_if(sources_.begin(), sources_.end(),
      [&](const PluginSource &source) { return source.url == normalized; });
  if (duplicate != sources_.end()) {
    if (error != nullptr) *error = "Source already exists";
    return false;
  }

  PluginSource source;
  source.name = trim_copy(name).empty() ? "Plugin Repository" : trim_copy(name);
  source.url = normalized;
  source.id = make_source_id(normalized);
  source.enabled = true;
  source.status = "Not refreshed";
  sources_.push_back(std::move(source));
  return save_unlocked(error);
}

bool PluginManager::remove_source(size_t index, std::string *error) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (index >= sources_.size()) {
    if (error != nullptr) *error = "Source index out of range";
    return false;
  }
  sources_.erase(sources_.begin() + static_cast<std::ptrdiff_t>(index));
  load_cached_catalog_unlocked();
  return save_unlocked(error);
}

bool PluginManager::set_source_enabled(size_t index, bool enabled,
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

bool PluginManager::refresh_all(std::string *error) {
  std::vector<PluginSource> sources_copy;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    sources_copy = sources_;
  }

  std::vector<PluginSource> refreshed_sources;
  std::vector<PluginPackage> refreshed_catalog;
  const bool ok = refresh_sources(sources_copy, refreshed_sources, refreshed_catalog, error);

  {
    std::lock_guard<std::mutex> lock(mutex_);
    sources_ = std::move(refreshed_sources);
    catalog_ = std::move(refreshed_catalog);
    merge_installed_flags(catalog_, installed_);
    std::string save_error;
    (void)save_unlocked(&save_error);
  }
  return ok;
}

bool PluginManager::refresh_source(size_t index, std::string *error) {
  PluginSource source;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= sources_.size()) {
      if (error != nullptr) *error = "Source index out of range";
      return false;
    }
    source = sources_[index];
  }

  PluginSource refreshed;
  std::vector<PluginPackage> packages;
  const bool ok = refresh_one(source, refreshed, packages, error);

  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < sources_.size()) sources_[index] = refreshed;
    catalog_.erase(std::remove_if(catalog_.begin(), catalog_.end(),
        [&](const PluginPackage &pkg) { return pkg.source_id == source.id; }),
        catalog_.end());
    catalog_.insert(catalog_.end(), packages.begin(), packages.end());
    merge_installed_flags(catalog_, installed_);
    std::string save_error;
    (void)save_unlocked(&save_error);
  }
  return ok;
}

bool PluginManager::refresh_sources(const std::vector<PluginSource> &sources,
                                    std::vector<PluginSource> &out_sources,
                                    std::vector<PluginPackage> &out_catalog,
                                    std::string *error) {
  bool all_ok = true;
  std::string first_error;
  out_sources.clear();
  out_catalog.clear();
  for (const auto &source : sources) {
    PluginSource refreshed;
    std::vector<PluginPackage> packages;
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

bool PluginManager::refresh_one(const PluginSource &source,
                                PluginSource &out_source,
                                std::vector<PluginPackage> &out_packages,
                                std::string *error) {
  out_source = source;
  out_source.url = normalize_source_url(out_source.url);
  out_packages.clear();
  if (!out_source.enabled) {
    out_source.status = "Disabled";
    out_source.last_ok = false;
    return true;
  }

  std::filesystem::path manifest_path = source_cache_manifest_path(out_source);
  bool used_bundled = false;
  std::string fetch_error;
  if (is_remote_url(out_source.url)) {
    if (!copy_or_download_file(out_source.url, manifest_path, &fetch_error)) {
      if (source_is_default(out_source) && !bundled_manifest_path_.empty()) {
        manifest_path = bundled_manifest_path_;
        used_bundled = true;
      } else {
        out_source.status = fetch_error;
        out_source.last_ok = false;
        if (error != nullptr) *error = fetch_error;
        return false;
      }
    }
  } else {
    manifest_path = local_path_from_source_url(out_source.url);
  }

  nlohmann::json doc;
  std::string parse_error;
  PluginSource parse_source = out_source;
  if (used_bundled) parse_source.url = manifest_path.string();
  if (!parse_json_file(manifest_path, doc, &parse_error) ||
      !parse_manifest_packages(parse_source, manifest_path, doc, out_packages, &parse_error)) {
    out_source.status = parse_error;
    out_source.last_ok = false;
    if (error != nullptr) *error = parse_error;
    return false;
  }

  out_source.status = used_bundled
      ? "Using bundled fallback"
      : "Ready (" + std::to_string(out_packages.size()) + " plugins)";
  out_source.last_ok = true;
  return true;
}

bool PluginManager::find_package_unlocked(const std::string &package_id,
                                          const std::string &source_id,
                                          PluginPackage &out) const {
  for (const auto &pkg : catalog_) {
    if (pkg.id != package_id) continue;
    if (!source_id.empty() && pkg.source_id != source_id) continue;
    out = pkg;
    return true;
  }
  return false;
}

bool PluginManager::find_installed_unlocked(const std::string &package_id,
                                            InstalledRecord &out) const {
  auto it = installed_.find(package_id);
  if (it == installed_.end()) return false;
  out = it->second;
  return true;
}

bool PluginManager::install_package(const std::string &package_id,
                                    const std::string &source_id,
                                    std::string *error) {
  PluginPackage package;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!find_package_unlocked(package_id, source_id, package)) {
      if (error != nullptr) *error = "Plugin not found in catalog";
      return false;
    }
  }

  std::string install_error;
  if (!install_package_unlocked(package, &install_error)) {
    if (error != nullptr) *error = install_error;
    return false;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  InstalledRecord record;
  record.source_id = package.source_id;
  record.source_url = package.source_url;
  record.name = package.name;
  record.version = package.version;
  record.entry = package.entry;
  record.language = package.language;
  record.enabled = true;
  record.path = plugin_data_dir() / make_package_dir_name(package.id);
  installed_[package.id] = record;
  merge_installed_flags(catalog_, installed_);
  return save_unlocked(error);
}

bool PluginManager::install_package_unlocked(const PluginPackage &package,
                                             std::string *error) {
  if (package.files.empty()) {
    if (error != nullptr) *error = "Plugin has no files";
    return false;
  }
  if (package.language == PluginLanguage::Unknown) {
    if (error != nullptr) *error = "Plugin language is unknown";
    return false;
  }

  const auto root = plugin_data_dir() / make_package_dir_name(package.id);
  std::error_code ec;
  std::filesystem::create_directories(root, ec);
  if (ec) {
    if (error != nullptr) *error = "Cannot create plugin directory: " + ec.message();
    return false;
  }

  for (const auto &file : package.files) {
    const auto rel = safe_relative_path(file.path, file.resolved_url);
    const auto dest = root / rel;
    if (!copy_or_download_file(file.resolved_url, dest, error)) return false;
  }

  const auto entry_path = root / safe_relative_path(package.entry, package.entry);
  if (!std::filesystem::exists(entry_path)) {
    if (error != nullptr) *error = "Plugin entry was not installed: " + entry_path.string();
    return false;
  }
  return true;
}

bool PluginManager::uninstall_package(const std::string &package_id,
                                      std::string *error) {
  std::lock_guard<std::mutex> lock(mutex_);
  InstalledRecord record;
  if (!find_installed_unlocked(package_id, record)) {
    if (error != nullptr) *error = "Plugin is not installed";
    return false;
  }

  std::error_code ec;
  if (!record.path.empty()) std::filesystem::remove_all(record.path, ec);
  if (ec) {
    if (error != nullptr) *error = "Cannot remove plugin directory: " + ec.message();
    return false;
  }

  installed_.erase(package_id);
  merge_installed_flags(catalog_, installed_);
  return save_unlocked(error);
}

bool PluginManager::set_package_enabled(const std::string &package_id,
                                        bool enabled,
                                        std::string *error) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = installed_.find(package_id);
  if (it == installed_.end()) {
    if (error != nullptr) *error = "Plugin is not installed";
    return false;
  }
  it->second.enabled = enabled;
  merge_installed_flags(catalog_, installed_);
  return save_unlocked(error);
}

PluginRunResult PluginManager::run_plugin(const std::string &package_id,
                                          const PluginRunContext &context) {
  InstalledRecord record;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!find_installed_unlocked(package_id, record)) {
      PluginRunResult result;
      result.plugin_id = package_id;
      result.error = "Plugin is not installed";
      return result;
    }
  }

  PluginRunResult result;
  result.plugin_id = package_id;
  if (!record.enabled) {
    result.error = "Plugin is disabled";
    return result;
  }
  if (record.language == PluginLanguage::Unknown) {
    result.error = "Plugin language is unknown";
    return result;
  }

  const auto interpreter = find_interpreter(record.language);
  if (interpreter.empty()) {
    result.error = std::string(language_name(record.language)) + " interpreter not found";
    return result;
  }

  const auto root = record.path.empty()
      ? plugin_data_dir() / make_package_dir_name(package_id)
      : record.path;
  const auto entry = root / safe_relative_path(record.entry, record.entry);
  if (!std::filesystem::exists(entry)) {
    result.error = "Plugin entry not found: " + entry.string();
    return result;
  }

  std::error_code ec;
  const auto runtime_dir = platform::app_cache_dir() / "plugins" / "runtime";
  std::filesystem::create_directories(runtime_dir, ec);
  if (ec) {
    result.error = "Cannot create plugin runtime directory: " + ec.message();
    return result;
  }

  const auto context_path = runtime_dir / (make_package_dir_name(package_id) + "-context.json");
  nlohmann::json doc;
  doc["memdbg"] = {
      {"frontend", "MemDBG"},
      {"protocol_version", context.protocol_version},
      {"capabilities", context.capabilities},
  };
  doc["console"] = {
      {"host", context.host},
      {"debug_port", context.debug_port},
      {"udp_port", context.udp_port},
      {"connected", context.connected},
  };
  doc["process"] = {
      {"pid", context.selected_pid},
      {"name", context.selected_process_name},
  };
  doc["paths"] = {
      {"dump", context.dump_path},
      {"trainer", context.trainer_file_path},
      {"plugin", root.string()},
  };
  doc["state"] = {
      {"map_count", context.map_count},
      {"scan_hit_count", context.scan_hit_count},
      {"trainer_entry_count", context.trainer_entry_count},
  };

  {
    std::ofstream out(context_path, std::ios::binary | std::ios::trunc);
    if (!out) {
      result.error = "Cannot write plugin context";
      return result;
    }
    out << doc.dump(2) << "\n";
  }

  const std::string command =
#if defined(_WIN32)
      "cd /d " + shell_quote(root.string()) +
      " && set \"MEMDBG_CONTEXT=" + context_path.string() + "\"" +
      " && set \"MEMDBG_PLUGIN_DIR=" + root.string() + "\"" +
      " && set \"PYTHONPATH=" + root.string() + ";%PYTHONPATH%\"" +
      " && " + interpreter + " " +
#else
      "cd " + shell_quote(root.string()) +
      " && MEMDBG_CONTEXT=" + shell_quote(context_path.string()) +
      " MEMDBG_PLUGIN_DIR=" + shell_quote(root.string()) +
      " PYTHONPATH=" + shell_quote(root.string()) + ":${PYTHONPATH:-}" +
      " " + interpreter + " " +
#endif
      shell_quote(entry.string()) + " " + shell_quote(context_path.string()) + " 2>&1";
  result = run_shell_capture(command);
  result.plugin_id = package_id;
  return result;
}

} // namespace memdbg::frontend::plugins
