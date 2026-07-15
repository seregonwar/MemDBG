/*
 * MemDBG payload sender regression tests.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "payload_sender.hpp"
#include "platform.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

using namespace memdbg::frontend;

namespace {

bool check(bool condition, const char *name) {
  std::cout << (condition ? "[PASS] " : "[FAIL] ") << name << '\n';
  return condition;
}

} // namespace

int main() {
  bool ok = true;
  const auto temp = std::filesystem::temp_directory_path() /
                    "memdbg-payload-sender-test.elf";
  const std::vector<unsigned char> expected = {
      0x7fU, 'E', 'L', 'F', 1U, 2U, 3U, 4U, 5U, 6U};
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char *>(expected.data()),
              static_cast<std::streamsize>(expected.size()));
  }

  std::string startup_error;
  ok &= check(platform::socket_startup(&startup_error), "socket runtime starts");
  platform::socket_handle_t listener = ::socket(AF_INET, SOCK_STREAM, 0);
  ok &= check(platform::socket_valid(listener), "loopback listener created");

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  ok &= check(::bind(listener, reinterpret_cast<sockaddr *>(&address),
                     sizeof(address)) == 0,
              "loopback listener bound");
  ok &= check(::listen(listener, 1) == 0, "loopback listener active");
  platform::socklen_type address_size = sizeof(address);
  ok &= check(::getsockname(listener, reinterpret_cast<sockaddr *>(&address),
                            &address_size) == 0,
              "loopback port resolved");

  std::vector<unsigned char> received;
  std::thread server([&] {
    sockaddr_in peer{};
    platform::socklen_type peer_size = sizeof(peer);
    auto client = ::accept(listener, reinterpret_cast<sockaddr *>(&peer),
                           &peer_size);
    if (!platform::socket_valid(client)) return;
    std::array<unsigned char, 64> buffer{};
    for (;;) {
      const int count = platform::socket_recv(client, buffer.data(),
                                              buffer.size());
      if (count <= 0) break;
      received.insert(received.end(), buffer.begin(),
                      buffer.begin() + count);
    }
    platform::socket_close(client);
  });

  std::string error;
  const bool sent = send_payload_elf(
      "127.0.0.1", ntohs(address.sin_port), temp, error);
  server.join();
  platform::socket_close(listener);
  platform::socket_cleanup();
  ok &= check(sent && error.empty(), "ELF upload succeeds");
  ok &= check(received == expected, "ELF bytes arrive without framing");

  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    out << "not an elf";
  }
  error.clear();
  ok &= check(!send_payload_elf("127.0.0.1", 9021, temp, error) &&
                  error.find("not an ELF") != std::string::npos,
              "non-ELF payload is rejected before connecting");
  std::error_code ec;
  std::filesystem::remove(temp, ec);

  return ok ? 0 : 1;
}
