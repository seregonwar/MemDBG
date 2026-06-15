/*
 * memDBG - UDP log listener for the ImGui frontend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "udp_log_listener.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <iomanip>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace memdbg::frontend {

UdpLogListener::UdpLogListener() = default;

UdpLogListener::~UdpLogListener() { stop(); }

bool UdpLogListener::start(uint16_t port) {
  stop();
  {
    std::lock_guard<std::mutex> lock(mutex_);
    last_error_.clear();
    startup_done_ = false;
    startup_ok_ = false;
    port_ = port;
  }
  stop_requested_.store(false);
  thread_ = std::thread(&UdpLogListener::thread_main, this, port);

  std::unique_lock<std::mutex> lock(mutex_);
  bool signaled = startup_cv_.wait_for(lock, std::chrono::seconds(2), [this] {
    return startup_done_;
  });
  if (!signaled || !startup_ok_) {
    if (!signaled) {
      last_error_ = "UDP listener startup timed out";
    }
    lock.unlock();
    stop();
    return false;
  }
  return true;
}

void UdpLogListener::stop() {
  stop_requested_.store(true);
  if (thread_.joinable()) {
    thread_.join();
  }
  running_.store(false);
}

bool UdpLogListener::running() const { return running_.load(); }

std::string UdpLogListener::last_error() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return last_error_;
}

UdpLogStats UdpLogListener::stats() const {
  std::lock_guard<std::mutex> lock(mutex_);
  UdpLogStats out;
  out.received = received_;
  out.dropped = dropped_;
  out.port = port_;
  return out;
}

std::vector<std::string> UdpLogListener::snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return lines_;
}

void UdpLogListener::clear() {
  std::lock_guard<std::mutex> lock(mutex_);
  lines_.clear();
}

static std::string current_time_text() {
  auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#if defined(_WIN32)
  localtime_s(&tm, &t);
#else
  localtime_r(&t, &tm);
#endif
  char buffer[32];
  if (std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &tm) == 0) {
    return "00:00:00";
  }
  return buffer;
}

static std::string endpoint_text(const sockaddr_in &addr) {
  char host[INET_ADDRSTRLEN] = "";
  if (::inet_ntop(AF_INET, &addr.sin_addr, host, sizeof(host)) == nullptr) {
    std::snprintf(host, sizeof(host), "unknown");
  }
  std::ostringstream out;
  out << host << ":" << ntohs(addr.sin_port);
  return out.str();
}

void UdpLogListener::thread_main(uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    std::lock_guard<std::mutex> lock(mutex_);
    last_error_ = std::string("socket: ") + std::strerror(errno);
    startup_done_ = true;
    startup_ok_ = false;
    startup_cv_.notify_all();
    running_.store(false);
    return;
  }

  int one = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  timeval timeout{};
  timeout.tv_sec = 0;
  timeout.tv_usec = 250000;
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    std::lock_guard<std::mutex> lock(mutex_);
    last_error_ = std::string("bind: ") + std::strerror(errno);
    startup_done_ = true;
    startup_ok_ = false;
    startup_cv_.notify_all();
    running_.store(false);
    (void)::close(fd);
    return;
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    startup_done_ = true;
    startup_ok_ = true;
    port_ = port;
    startup_cv_.notify_all();
  }
  running_.store(true);

  while (!stop_requested_.load()) {
    char buffer[1500];
    sockaddr_in source{};
    socklen_t source_len = sizeof(source);
    ssize_t n = ::recvfrom(fd, buffer, sizeof(buffer) - 1U, 0,
                           reinterpret_cast<sockaddr *>(&source),
                           &source_len);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        continue;
      }
      std::lock_guard<std::mutex> lock(mutex_);
      last_error_ = std::string("recv: ") + std::strerror(errno);
      break;
    }
    if (n == 0) {
      continue;
    }

    buffer[n] = '\0';
    std::string message(buffer);
    while (!message.empty() &&
           (message.back() == '\n' || message.back() == '\r')) {
      message.pop_back();
    }

    std::ostringstream line;
    line << "[" << current_time_text() << "] " << endpoint_text(source)
         << " " << message;

    std::lock_guard<std::mutex> lock(mutex_);
    received_++;
    lines_.push_back(line.str());
    if (lines_.size() > 4000U) {
      const size_t erase_count = 1000U;
      lines_.erase(lines_.begin(), lines_.begin() + erase_count);
      dropped_ += erase_count;
    }
  }

  (void)::close(fd);
  running_.store(false);
}

} // namespace memdbg::frontend
