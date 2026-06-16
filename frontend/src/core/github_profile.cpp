/*
 * MemDBG - GitHub profile loader for frontend credits.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "github_profile.hpp"

#include "platform.hpp"

#include <GLFW/glfw3.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace memdbg::frontend {

namespace {

std::string read_text_file(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

std::string json_string_value(const std::string &json, const char *key) {
  std::string marker = "\"";
  marker += key;
  marker += "\"";
  size_t pos = json.find(marker);
  if (pos == std::string::npos) {
    return {};
  }
  pos = json.find(':', pos + marker.size());
  if (pos == std::string::npos) {
    return {};
  }
  pos = json.find('"', pos);
  if (pos == std::string::npos) {
    return {};
  }

  std::string value;
  bool escape = false;
  for (size_t i = pos + 1; i < json.size(); ++i) {
    char c = json[i];
    if (escape) {
      value.push_back(c);
      escape = false;
      continue;
    }
    if (c == '\\') {
      escape = true;
      continue;
    }
    if (c == '"') {
      break;
    }
    value.push_back(c);
  }
  return value;
}

void worker_main(GitHubProfile *profile) {
  std::string error;
  std::string name;
  std::string bio;
  std::string avatar_url;
  std::vector<unsigned char> pixels;
  int width = 0;
  int height = 0;

  try {
    const auto cache = platform::app_cache_dir();
    std::filesystem::create_directories(cache);
    const auto json_path = cache / "seregonwar.json";
    const auto avatar_path = cache / "seregonwar-avatar";

    if (!platform::download_file("https://api.github.com/users/seregonwar",
                                 json_path)) {
      error = "GitHub profile download failed";
    } else {
      const std::string json = read_text_file(json_path);
      name = json_string_value(json, "name");
      bio = json_string_value(json, "bio");
      avatar_url = json_string_value(json, "avatar_url");
      if (avatar_url.empty()) {
        error = "GitHub avatar URL not found";
      } else if (!platform::download_file(avatar_url, avatar_path)) {
        error = "GitHub avatar download failed";
      } else {
        int channels = 0;
        unsigned char *raw = stbi_load(avatar_path.string().c_str(), &width,
                                       &height, &channels, 4);
        if (raw == nullptr || width <= 0 || height <= 0) {
          error = "GitHub avatar decode failed";
        } else {
          pixels.assign(raw, raw + (width * height * 4));
        }
        stbi_image_free(raw);
      }
    }
  } catch (const std::exception &ex) {
    error = ex.what();
  }

  {
    std::lock_guard<std::mutex> lock(profile->mutex);
    if (!name.empty()) {
      profile->name = name;
    }
    profile->bio = bio;
    profile->avatar_url = avatar_url;
    profile->error = error;
    profile->pixels = std::move(pixels);
    profile->image_width = width;
    profile->image_height = height;
  }
  profile->worker_done.store(true);
}

} // namespace

void github_profile_start(GitHubProfile &profile) {
  bool expected = false;
  if (!profile.started.compare_exchange_strong(expected, true)) {
    return;
  }
  profile.worker_done.store(false);
  profile.worker = std::thread(worker_main, &profile);
}

void github_profile_pump_texture(GitHubProfile &profile) {
  if (!profile.worker_done.load() || profile.texture != 0U) {
    return;
  }

  std::lock_guard<std::mutex> lock(profile.mutex);
  if (profile.pixels.empty() || profile.image_width <= 0 ||
      profile.image_height <= 0 || profile.texture != 0U) {
    return;
  }

  GLuint tex = 0;
  glGenTextures(1, &tex);
  glBindTexture(GL_TEXTURE_2D, tex);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, profile.image_width,
               profile.image_height, 0, GL_RGBA, GL_UNSIGNED_BYTE,
               profile.pixels.data());
  glBindTexture(GL_TEXTURE_2D, 0);
  profile.texture = static_cast<uint32_t>(tex);
  profile.pixels.clear();
  profile.pixels.shrink_to_fit();
}

void github_profile_shutdown(GitHubProfile &profile) {
  if (profile.worker.joinable()) {
    profile.worker.join();
  }
  if (profile.texture != 0U) {
    GLuint tex = static_cast<GLuint>(profile.texture);
    glDeleteTextures(1, &tex);
    profile.texture = 0U;
  }
}

ImTextureID github_profile_texture_id(const GitHubProfile &profile) {
  return reinterpret_cast<ImTextureID>(
      static_cast<intptr_t>(profile.texture));
}

} // namespace memdbg::frontend
