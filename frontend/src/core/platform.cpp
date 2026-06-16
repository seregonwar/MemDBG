/*
 * MemDBG - Frontend platform helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "platform.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <sstream>

#if defined(_WIN32)
#include <shellapi.h>
#include <windows.h>
#else
#include <cerrno>
#include <unistd.h>
#endif

namespace memdbg::frontend::platform {

namespace {

#if defined(_WIN32)
std::mutex g_winsock_mutex;
int g_winsock_refs = 0;
#endif

int clamp_socket_size(size_t size) {
  const size_t max_size = static_cast<size_t>(std::numeric_limits<int>::max());
  return static_cast<int>(std::min(size, max_size));
}

const char *env_value(const char *name) {
  const char *value = std::getenv(name);
  return value != nullptr && value[0] != '\0' ? value : nullptr;
}

std::filesystem::path home_dir() {
#if defined(_WIN32)
  if (const char *profile = env_value("USERPROFILE")) {
    return std::filesystem::path(profile);
  }
  const char *drive = env_value("HOMEDRIVE");
  const char *path = env_value("HOMEPATH");
  if (drive != nullptr && path != nullptr) {
    return std::filesystem::path(std::string(drive) + path);
  }
#else
  if (const char *home = env_value("HOME")) {
    return std::filesystem::path(home);
  }
#endif
  return std::filesystem::temp_directory_path();
}

[[maybe_unused]] std::string shell_quote_posix(const std::string &value) {
  std::string out = "'";
  for (char c : value) {
    if (c == '\'') {
      out += "'\\''";
    } else {
      out.push_back(c);
    }
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

} // namespace

socket_handle_t invalid_socket() {
#if defined(_WIN32)
  return INVALID_SOCKET;
#else
  return -1;
#endif
}

bool socket_startup(std::string *error) {
#if defined(_WIN32)
  std::lock_guard<std::mutex> lock(g_winsock_mutex);
  if (g_winsock_refs == 0) {
    WSADATA data{};
    int rc = WSAStartup(MAKEWORD(2, 2), &data);
    if (rc != 0) {
      if (error != nullptr) {
        *error = "WSAStartup: " + socket_error_text(rc);
      }
      return false;
    }
  }
  ++g_winsock_refs;
#else
  (void)error;
#endif
  return true;
}

void socket_cleanup() {
#if defined(_WIN32)
  std::lock_guard<std::mutex> lock(g_winsock_mutex);
  if (g_winsock_refs <= 0) {
    return;
  }
  --g_winsock_refs;
  if (g_winsock_refs == 0) {
    WSACleanup();
  }
#endif
}

bool socket_valid(socket_handle_t fd) { return fd != invalid_socket(); }

void socket_close(socket_handle_t fd) {
  if (!socket_valid(fd)) {
    return;
  }
#if defined(_WIN32)
  closesocket(fd);
#else
  close(fd);
#endif
}

void socket_shutdown_both(socket_handle_t fd) {
  if (!socket_valid(fd)) {
    return;
  }
#if defined(_WIN32)
  shutdown(fd, SD_BOTH);
#else
  shutdown(fd, SHUT_RDWR);
#endif
}

bool socket_set_recv_timeout(socket_handle_t fd, uint32_t timeout_ms) {
#if defined(_WIN32)
  DWORD timeout = timeout_ms;
  return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                    reinterpret_cast<const char *>(&timeout),
                    sizeof(timeout)) == 0;
#else
  timeval timeout{};
  timeout.tv_sec = static_cast<long>(timeout_ms / 1000U);
  timeout.tv_usec = static_cast<long>((timeout_ms % 1000U) * 1000U);
  return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                    sizeof(timeout)) == 0;
#endif
}

bool socket_set_send_timeout(socket_handle_t fd, uint32_t timeout_ms) {
#if defined(_WIN32)
  DWORD timeout = timeout_ms;
  return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                    reinterpret_cast<const char *>(&timeout),
                    sizeof(timeout)) == 0;
#else
  timeval timeout{};
  timeout.tv_sec = static_cast<long>(timeout_ms / 1000U);
  timeout.tv_usec = static_cast<long>((timeout_ms % 1000U) * 1000U);
  return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                    sizeof(timeout)) == 0;
#endif
}

bool socket_set_reuse_addr(socket_handle_t fd) {
  int one = 1;
  return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                    reinterpret_cast<const char *>(&one), sizeof(one)) == 0;
}

bool socket_set_recv_buffer(socket_handle_t fd, int bytes) {
  return setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                    reinterpret_cast<const char *>(&bytes), sizeof(bytes)) == 0;
}

int socket_recv(socket_handle_t fd, void *buffer, size_t size) {
  int chunk = clamp_socket_size(size);
#if defined(_WIN32)
  return recv(fd, static_cast<char *>(buffer), chunk, 0);
#else
  return static_cast<int>(recv(fd, buffer, static_cast<size_t>(chunk), 0));
#endif
}

int socket_send(socket_handle_t fd, const void *buffer, size_t size) {
  int chunk = clamp_socket_size(size);
#if defined(_WIN32)
  return send(fd, static_cast<const char *>(buffer), chunk, 0);
#else
  return static_cast<int>(send(fd, buffer, static_cast<size_t>(chunk), 0));
#endif
}

int socket_recvfrom(socket_handle_t fd, void *buffer, size_t size,
                    sockaddr *source, socklen_type *source_len) {
  int chunk = clamp_socket_size(size);
#if defined(_WIN32)
  return recvfrom(fd, static_cast<char *>(buffer), chunk, 0, source, source_len);
#else
  return static_cast<int>(
      recvfrom(fd, buffer, static_cast<size_t>(chunk), 0, source, source_len));
#endif
}

int socket_last_error_code() {
#if defined(_WIN32)
  return WSAGetLastError();
#else
  return errno;
#endif
}

bool socket_error_interrupted(int code) {
#if defined(_WIN32)
  return code == WSAEINTR;
#else
  return code == EINTR;
#endif
}

bool socket_error_would_block(int code) {
#if defined(_WIN32)
  return code == WSAEWOULDBLOCK || code == WSAETIMEDOUT;
#else
  return code == EAGAIN || code == EWOULDBLOCK;
#endif
}

bool socket_error_permission(int code) {
#if defined(_WIN32)
  return code == WSAEACCES;
#else
  return code == EACCES;
#endif
}

std::string socket_error_text(int code) {
#if defined(_WIN32)
  char *message = nullptr;
  DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS;
  DWORD len = FormatMessageA(flags, nullptr, static_cast<DWORD>(code), 0,
                             reinterpret_cast<LPSTR>(&message), 0, nullptr);
  std::string out;
  if (len != 0 && message != nullptr) {
    out.assign(message, message + len);
    while (!out.empty() && (out.back() == '\r' || out.back() == '\n' ||
                            out.back() == ' ')) {
      out.pop_back();
    }
    LocalFree(message);
  }
  if (out.empty()) {
    out = "socket error " + std::to_string(code);
  }
  return out;
#else
  return std::strerror(code);
#endif
}

std::filesystem::path app_config_dir() {
#if defined(_WIN32)
  if (const char *local = env_value("LOCALAPPDATA")) {
    return std::filesystem::path(local) / "MemDBG";
  }
  if (const char *roaming = env_value("APPDATA")) {
    return std::filesystem::path(roaming) / "MemDBG";
  }
  return home_dir() / "AppData" / "Local" / "MemDBG";
#elif defined(__APPLE__)
  return home_dir() / "Library" / "Application Support" / "MemDBG";
#else
  if (const char *xdg = env_value("XDG_CONFIG_HOME")) {
    return std::filesystem::path(xdg) / "MemDBG";
  }
  return home_dir() / ".config" / "MemDBG";
#endif
}

std::filesystem::path app_cache_dir() {
#if defined(_WIN32)
  if (const char *local = env_value("LOCALAPPDATA")) {
    return std::filesystem::path(local) / "MemDBG" / "Cache";
  }
  return app_config_dir() / "Cache";
#elif defined(__APPLE__)
  return home_dir() / "Library" / "Caches" / "MemDBG";
#else
  if (const char *xdg = env_value("XDG_CACHE_HOME")) {
    return std::filesystem::path(xdg) / "MemDBG";
  }
  return home_dir() / ".cache" / "memdbg";
#endif
}

bool open_url(const std::string &url) {
#if defined(_WIN32)
  HINSTANCE result = ShellExecuteA(nullptr, "open", url.c_str(), nullptr,
                                   nullptr, SW_SHOWNORMAL);
  return reinterpret_cast<intptr_t>(result) > 32;
#elif defined(__APPLE__)
  std::string command = "open " + shell_quote_posix(url);
  return std::system(command.c_str()) == 0;
#else
  std::string command = "xdg-open " + shell_quote_posix(url);
  return std::system(command.c_str()) == 0;
#endif
}

bool download_file(const std::string &url, const std::filesystem::path &out) {
#if defined(_WIN32)
  std::string command =
      "curl.exe -LfsS --max-time 8 -H " +
      shell_quote_windows("Accept: application/vnd.github+json") + " " +
      shell_quote_windows(url) + " -o " + shell_quote_windows(out.string());
#else
  std::string command =
      "curl -LfsS --max-time 8 -H " +
      shell_quote_posix("Accept: application/vnd.github+json") + " " +
      shell_quote_posix(url) + " -o " + shell_quote_posix(out.string());
#endif
  return std::system(command.c_str()) == 0;
}

} // namespace memdbg::frontend::platform
