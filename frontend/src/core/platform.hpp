/*
 * MemDBG - Frontend platform helpers.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_PLATFORM_HPP
#define MEMDBG_FRONTEND_PLATFORM_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif

namespace memdbg::frontend::platform {

#if defined(_WIN32)
using socket_handle_t = SOCKET;
using socklen_type = int;
#else
using socket_handle_t = int;
using socklen_type = socklen_t;
#endif

socket_handle_t invalid_socket();
bool socket_startup(std::string *error = nullptr);
void socket_cleanup();
bool socket_valid(socket_handle_t fd);
void socket_close(socket_handle_t fd);
void socket_shutdown_both(socket_handle_t fd);
bool socket_set_recv_timeout(socket_handle_t fd, uint32_t timeout_ms);
bool socket_set_send_timeout(socket_handle_t fd, uint32_t timeout_ms);
bool socket_set_reuse_addr(socket_handle_t fd);
bool socket_set_broadcast(socket_handle_t fd);
bool socket_set_recv_buffer(socket_handle_t fd, int bytes);
int socket_recv(socket_handle_t fd, void *buffer, size_t size);
int socket_send(socket_handle_t fd, const void *buffer, size_t size);
int socket_recvfrom(socket_handle_t fd, void *buffer, size_t size,
                    sockaddr *source, socklen_type *source_len);
int socket_last_error_code();
bool socket_error_interrupted(int code);
bool socket_error_would_block(int code);
bool socket_error_permission(int code);
std::string socket_error_text(int code);

std::filesystem::path app_config_dir();
std::filesystem::path app_cache_dir();
bool open_url(const std::string &url);
bool download_file(const std::string &url, const std::filesystem::path &out);

} // namespace memdbg::frontend::platform

#endif /* MEMDBG_FRONTEND_PLATFORM_HPP */
