/*
 * MemDBG - Raw ELF sender for PS4/PS5 payload loaders.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "payload_sender.hpp"

#include "platform.hpp"

#include <array>
#include <fstream>

namespace memdbg::frontend {

namespace {

constexpr uintmax_t kMaxPayloadBytes = 256U * 1024U * 1024U;
constexpr uint32_t kPayloadSendTimeoutMs = 30000U;

} // namespace

bool send_payload_elf(const std::string &host, uint16_t port,
                      const std::filesystem::path &path,
                      std::string &error) {
  error.clear();
  std::error_code ec;
  const uintmax_t file_size = std::filesystem::file_size(path, ec);
  if (ec || file_size < 4U || file_size > kMaxPayloadBytes) {
    error = ec ? "Cannot read payload ELF: " + ec.message()
               : "Payload ELF has an invalid size";
    return false;
  }

  std::ifstream input(path, std::ios::binary);
  std::array<unsigned char, 4> magic{};
  if (!input.read(reinterpret_cast<char *>(magic.data()), magic.size()) ||
      magic != std::array<unsigned char, 4>{0x7fU, 'E', 'L', 'F'}) {
    error = "Selected payload is not an ELF file";
    return false;
  }
  input.clear();
  input.seekg(0, std::ios::beg);

  std::string startup_error;
  if (!platform::socket_startup(&startup_error)) {
    error = startup_error;
    return false;
  }
  const auto cleanup_runtime = [] { platform::socket_cleanup(); };

  platform::socket_handle_t socket_fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!platform::socket_valid(socket_fd)) {
    error = "Cannot create payload sender socket: " +
            platform::socket_error_text(platform::socket_last_error_code());
    cleanup_runtime();
    return false;
  }
  const auto close_socket = [&] {
    platform::socket_close(socket_fd);
    cleanup_runtime();
  };

  (void)platform::socket_set_send_timeout(socket_fd, kPayloadSendTimeoutMs);
  (void)platform::socket_set_nosigpipe(socket_fd);

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  if (::inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) {
    error = "Invalid target IPv4 address";
    close_socket();
    return false;
  }
  if (::connect(socket_fd, reinterpret_cast<sockaddr *>(&address),
                sizeof(address)) != 0) {
    error = "Cannot connect to payload loader on " + host + ":" +
            std::to_string(port) + ": " +
            platform::socket_error_text(platform::socket_last_error_code());
    close_socket();
    return false;
  }

  std::array<char, 64U * 1024U> buffer{};
  uintmax_t sent_total = 0U;
  while (input && sent_total < file_size) {
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const std::streamsize count = input.gcount();
    if (count <= 0) break;
    size_t offset = 0U;
    const size_t length = static_cast<size_t>(count);
    while (offset < length) {
      const int sent = platform::socket_send(socket_fd, buffer.data() + offset,
                                             length - offset);
      if (sent <= 0) {
        error = "Payload upload failed after " + std::to_string(sent_total) +
                " bytes: " +
                platform::socket_error_text(platform::socket_last_error_code());
        close_socket();
        return false;
      }
      offset += static_cast<size_t>(sent);
      sent_total += static_cast<uintmax_t>(sent);
    }
  }

  if (sent_total != file_size) {
    error = "Payload upload was incomplete";
    close_socket();
    return false;
  }
#if defined(_WIN32)
  (void)::shutdown(socket_fd, SD_SEND);
#else
  (void)::shutdown(socket_fd, SHUT_WR);
#endif
  close_socket();
  return true;
}

} // namespace memdbg::frontend
