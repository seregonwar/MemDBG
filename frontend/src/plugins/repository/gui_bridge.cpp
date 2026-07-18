/*
 * MemDBG - GUI plugin bridge implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "gui_bridge.hpp"
#include "protocol_broker.hpp"
#include "ui_widgets.hpp"
#include "ui_icons.hpp"
#include "platform.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <thread>

#if defined(MEMDBG_PLATFORM_IOS)
/* iOS does not support fork/exec or popen; GUI plugin hosting is disabled. */
#elif defined(_WIN32)
#include <process.h>
#define MEMDBG_POPEN  _popen
#define MEMDBG_PCLOSE _pclose
#else
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#define MEMDBG_POPEN  popen
#define MEMDBG_PCLOSE pclose
#endif

namespace memdbg::frontend::plugins {

#if defined(MEMDBG_PLATFORM_IOS)

/* iOS does not allow fork/exec/popen — GUI plugin hosting is disabled.
 * Provide stub implementations so the linker is satisfied and draw_app can
 * safely call into us (no plugin will ever start). */

GuiBridge::GuiBridge() = default;
GuiBridge::~GuiBridge() = default;
bool GuiBridge::start_protocol_broker(ClientPool &) { return false; }
uint16_t GuiBridge::protocol_broker_port() const { return 0U; }

bool GuiBridge::start(const std::filesystem::path &python_exe,
                     const std::filesystem::path &script_path,
                     const std::filesystem::path &context_path) {
  (void)python_exe; (void)script_path; (void)context_path;
  return false;
}

void GuiBridge::stop() {}
void GuiBridge::begin_frame() {}
void GuiBridge::end_frame() {}
void GuiBridge::render_widgets() {}
void GuiBridge::render_widget(const std::shared_ptr<GuiWidget> &) {}
void GuiBridge::post_event(const GuiEvent &) {}
void GuiBridge::flush_events() {}
void GuiBridge::reader_thread() {}
void GuiBridge::writer_thread() {}
void GuiBridge::write_message_to_pipe(FILE *, const nlohmann::json &) {}
void GuiBridge::stderr_thread() {}
void GuiBridge::parse_ui_update(const nlohmann::json &) {}
std::shared_ptr<GuiWidget> GuiBridge::parse_widget(const nlohmann::json &) {
  return nullptr;
}
std::string GuiBridge::stderr_text() const { return {}; }
std::string GuiBridge::debug_info() const { return "iOS stub (gui plugins disabled)"; }
ImVec4 GuiBridge::widget_color(const std::string &) const { return ImVec4(1, 1, 1, 1); }

#else

namespace {

constexpr size_t kMaxMessageSize = 512U * 1024U;  /* 512 KiB per message */

bool starts_with(const std::string &value, const char *prefix) {
  const std::string p(prefix);
  return value.size() >= p.size() && value.compare(0, p.size(), p) == 0;
}

std::string lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

bool string_to_bool(const std::string &value) {
  const std::string lower = lower_copy(value);
  return lower == "true" || lower == "1" || lower == "yes" || lower == "on";
}

std::string json_string(const nlohmann::json &obj, const char *key,
                        const std::string &fallback = {}) {
  auto it = obj.find(key);
  if (it != obj.end() && it->is_string()) return it->get<std::string>();
  return fallback;
}

int json_int(const nlohmann::json &obj, const char *key, int fallback = 0) {
  auto it = obj.find(key);
  if (it != obj.end() && it->is_number_integer()) return it->get<int>();
  if (it != obj.end() && it->is_string()) {
    try { return std::stoi(it->get<std::string>()); } catch (...) {}
  }
  return fallback;
}

uint64_t json_u64(const nlohmann::json &obj, const char *key,
                  uint64_t fallback = 0U) {
  auto it = obj.find(key);
  if (it == obj.end()) return fallback;
  if (it->is_number_unsigned()) return it->get<uint64_t>();
  if (it->is_number_integer()) {
    const int64_t value = it->get<int64_t>();
    return value < 0 ? fallback : static_cast<uint64_t>(value);
  }
  if (it->is_string()) {
    std::string text = it->get<std::string>();
    auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
    text.erase(text.begin(), std::find_if(text.begin(), text.end(),
        [&](char c) { return !is_space(static_cast<unsigned char>(c)); }));
    text.erase(std::find_if(text.rbegin(), text.rend(),
        [&](char c) { return !is_space(static_cast<unsigned char>(c)); }).base(),
        text.end());
    try {
      size_t used = 0;
      const int base = starts_with(lower_copy(text), "0x") ? 16 : 10;
      uint64_t value = std::stoull(text, &used, base);
      return used == text.size() ? value : fallback;
    } catch (...) {}
  }
  return fallback;
}

float json_float(const nlohmann::json &obj, const char *key, float fallback = 0.0f) {
  auto it = obj.find(key);
  if (it != obj.end() && it->is_number()) return it->get<float>();
  if (it != obj.end() && it->is_string()) {
    try { return std::stof(it->get<std::string>()); } catch (...) {}
  }
  return fallback;
}

bool json_bool(const nlohmann::json &obj, const char *key, bool fallback = false) {
  auto it = obj.find(key);
  if (it != obj.end()) {
    if (it->is_boolean()) return it->get<bool>();
    if (it->is_string()) return string_to_bool(it->get<std::string>());
  }
  return fallback;
}

std::vector<std::string> json_string_array(const nlohmann::json &obj,
                                           const char *key) {
  std::vector<std::string> out;
  auto it = obj.find(key);
  if (it != obj.end() && it->is_array()) {
    for (const auto &item : *it) {
      if (item.is_string()) out.push_back(item.get<std::string>());
      else if (item.is_number()) out.push_back(std::to_string(item.get<int>()));
    }
  }
  return out;
}

std::vector<std::vector<std::string>> json_2d_string_array(
    const nlohmann::json &obj, const char *key) {
  std::vector<std::vector<std::string>> out;
  auto it = obj.find(key);
  if (it != obj.end() && it->is_array()) {
    for (const auto &row : *it) {
      if (!row.is_array()) continue;
      std::vector<std::string> cells;
      for (const auto &cell : row) {
        if (cell.is_string()) cells.push_back(cell.get<std::string>());
        else if (cell.is_number()) cells.push_back(std::to_string(cell.get<int>()));
        else cells.push_back("");
      }
      if (!cells.empty()) out.push_back(std::move(cells));
    }
  }
  return out;
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

} // namespace


/* ------------------------------------------------------------------ */
/*  GuiBridge                                                          */
/* ------------------------------------------------------------------ */

GuiBridge::GuiBridge() = default;

GuiBridge::~GuiBridge() {
  stop();
}

bool GuiBridge::start_protocol_broker(ClientPool &pool) {
  if (!protocol_broker_) protocol_broker_ = std::make_unique<ProtocolBroker>();
  return protocol_broker_->start(pool);
}

uint16_t GuiBridge::protocol_broker_port() const {
  return protocol_broker_ ? protocol_broker_->port() : 0U;
}

bool GuiBridge::start(const std::filesystem::path &python_exe,
                      const std::filesystem::path &script_path,
                      const std::filesystem::path &context_path) {
  if (running_.load(std::memory_order_acquire)) return false;

  if (!std::filesystem::exists(python_exe) || !std::filesystem::exists(script_path)) {
    return false;
  }

  /* Build the command to run the Python plugin in persistent GUI mode */
  std::string command;
#if defined(_WIN32)
  command = "set \"MEMDBG_CONTEXT=" + context_path.string() + "\" && "
            "set \"MEMDBG_GUI_MODE=1\" && "
            "\"" + python_exe.string() + "\" "
            "\"" + script_path.string() + "\" "
            "\"" + context_path.string() + "\" 2>&1";
#else
  command = "MEMDBG_CONTEXT='" + context_path.string() + "' "
            "MEMDBG_GUI_MODE=1 "
            "'" + python_exe.string() + "' "
            "'" + script_path.string() + "' "
            "'" + context_path.string() + "' 2>&1";
#endif

  /* We use popen for stdout (read) and need a separate pipe for stdin (write).
   * Since popen is unidirectional, we use a bidirectional approach:
   * - Create a pair of pipes
   * - Fork
   * - Child: redirect stdin/stdout, exec the command
   * - Parent: hold the other ends
   */
#if defined(_WIN32)
  /* Windows: use _popen for stdout; stdin via named pipe or file */
  stdin_pipe_ = MEMDBG_POPEN(command.c_str(), "w");
  stdout_pipe_ = nullptr;  /* not bidirectional with popen on Windows */
  if (stdin_pipe_ == nullptr) return false;
  child_pid_ = 0;
#else
  /* POSIX: create three pipes (stdout, stdin, stderr) before forking */
  int stdout_pipe_fd[2];
  int stdin_pipe_fd[2];
  int stderr_pipe_fd[2];

  if (::pipe(stdout_pipe_fd) != 0) return false;
  if (::pipe(stdin_pipe_fd) != 0) {
    ::close(stdout_pipe_fd[0]); ::close(stdout_pipe_fd[1]);
    return false;
  }
  if (::pipe(stderr_pipe_fd) != 0) {
    ::close(stdout_pipe_fd[0]); ::close(stdout_pipe_fd[1]);
    ::close(stdin_pipe_fd[0]);  ::close(stdin_pipe_fd[1]);
    return false;
  }

  pid_t pid = ::fork();
  if (pid < 0) {
    ::close(stdout_pipe_fd[0]); ::close(stdout_pipe_fd[1]);
    ::close(stdin_pipe_fd[0]);  ::close(stdin_pipe_fd[1]);
    ::close(stderr_pipe_fd[0]); ::close(stderr_pipe_fd[1]);
    return false;
  }

  if (pid == 0) {
    /* === Child process === */
    ::close(stdout_pipe_fd[0]);  /* close read end of stdout pipe */
    ::close(stdin_pipe_fd[1]);   /* close write end of stdin pipe */
    ::close(stderr_pipe_fd[0]);  /* close read end of stderr pipe */

    ::dup2(stdout_pipe_fd[1], STDOUT_FILENO);
    ::dup2(stdin_pipe_fd[0],  STDIN_FILENO);
    ::dup2(stderr_pipe_fd[1], STDERR_FILENO);

    ::close(stdout_pipe_fd[1]);
    ::close(stdin_pipe_fd[0]);
    ::close(stderr_pipe_fd[1]);

    const char *argv[] = {
      python_exe.c_str(),
      script_path.c_str(),
      context_path.c_str(),
      nullptr,
    };

    ::setenv("MEMDBG_CONTEXT", context_path.c_str(), 1);
    ::setenv("MEMDBG_GUI_MODE", "1", 1);
    ::setenv("PYTHONUNBUFFERED", "1", 1);

    ::execvp(python_exe.c_str(), const_cast<char *const *>(argv));
    ::_exit(127);
  }

  /* === Parent process === */
  ::close(stdout_pipe_fd[1]);  /* close write end of stdout pipe */
  ::close(stdin_pipe_fd[0]);   /* close read end of stdin pipe */
  ::close(stderr_pipe_fd[1]);  /* close write end of stderr pipe */

  stdout_pipe_ = ::fdopen(stdout_pipe_fd[0], "r");
  stdin_pipe_  = ::fdopen(stdin_pipe_fd[1],  "w");
  stderr_pipe_ = ::fdopen(stderr_pipe_fd[0], "r");
  child_pid_   = static_cast<int>(pid);

  if (stdout_pipe_ == nullptr || stdin_pipe_ == nullptr ||
      stderr_pipe_ == nullptr) {
    if (stdout_pipe_) ::fclose(stdout_pipe_);
    else ::close(stdout_pipe_fd[0]);
    if (stdin_pipe_) ::fclose(stdin_pipe_);
    else ::close(stdin_pipe_fd[1]);
    if (stderr_pipe_) ::fclose(stderr_pipe_);
    else ::close(stderr_pipe_fd[0]);
    stdout_pipe_ = nullptr;
    stdin_pipe_ = nullptr;
    stderr_pipe_ = nullptr;
    ::kill(pid, SIGTERM);
    child_pid_ = 0;
    return false;
  }

  /* Set stdout pipe to line-buffered for MCP framing */
  ::setvbuf(stdout_pipe_, nullptr, _IOLBF, 0);
  ::setvbuf(stdin_pipe_, nullptr, _IOLBF, 0);
#endif

  running_.store(true, std::memory_order_release);
  has_tree_.store(false, std::memory_order_release);
  writer_stop_.store(false, std::memory_order_release);

  /* Start reader thread (stdout = MCP messages) */
  reader_thread_ = std::thread(&GuiBridge::reader_thread, this);

  /* Start writer thread */
  writer_thread_ = std::thread(&GuiBridge::writer_thread, this);

  /* Start stderr reader thread */
  stderr_thread_ = std::thread(&GuiBridge::stderr_thread, this);

  return true;
}

void GuiBridge::stop() {
  /* Unblock a plugin that is waiting on a local protocol request before we
   * wait for its stdio threads.  The console-side pool remains owned by the
   * application and is not torn down here. */
  if (protocol_broker_) protocol_broker_->stop();

  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  /* Send exit notification */
  {
    nlohmann::json exit_msg;
    exit_msg["jsonrpc"] = "2.0";
    exit_msg["method"] = "exit";
    exit_msg["params"] = nlohmann::json::object();
    write_message_to_pipe(stdin_pipe_, exit_msg);
  }

  running_.store(false, std::memory_order_release);
  writer_stop_.store(true, std::memory_order_release);
  event_cv_.notify_all();

  /* Join threads */
  if (reader_thread_.joinable()) reader_thread_.join();
  if (writer_thread_.joinable()) writer_thread_.join();
  if (stderr_thread_.joinable()) stderr_thread_.join();

  /* Close pipes */
  if (stdout_pipe_ != nullptr) {
    ::fclose(stdout_pipe_);
    stdout_pipe_ = nullptr;
  }
  if (stdin_pipe_ != nullptr) {
    ::fclose(stdin_pipe_);
    stdin_pipe_ = nullptr;
  }
  if (stderr_pipe_ != nullptr) {
    ::fclose(stderr_pipe_);
    stderr_pipe_ = nullptr;
  }

#if !defined(_WIN32)
  /* Reap child */
  if (child_pid_ > 0) {
    ::kill(child_pid_, SIGTERM);
    int status = 0;
    ::waitpid(child_pid_, &status, 0);
    child_pid_ = 0;
  }
#endif

  /* Clear widget trees */
  {
    std::lock_guard<std::mutex> lock(tree_mutex_);
    pending_tree_.clear();
    active_tree_.clear();
  }
  has_tree_.store(false, std::memory_order_release);
}

/* ------------------------------------------------------------------ */
/*  Frame lifecycle                                                    */
/* ------------------------------------------------------------------ */

void GuiBridge::begin_frame() {
  /* Atomically swap the pending tree into the active tree */
  if (!has_tree_.load(std::memory_order_acquire)) return;

  std::lock_guard<std::mutex> lock(tree_mutex_);
  active_tree_ = std::move(pending_tree_);
  pending_tree_.clear();
  has_tree_.store(false, std::memory_order_release);
}

void GuiBridge::end_frame() {
  /* Flush events collected during rendering */
  flush_events();
}

void GuiBridge::render_widgets() {
  if (active_tree_.empty()) return;
  for (const auto &widget : active_tree_) {
    render_widget(widget);
  }
}

/* ------------------------------------------------------------------ */
/*  Render a single widget (recursive)                                  */
/* ------------------------------------------------------------------ */

void GuiBridge::render_widget(const std::shared_ptr<GuiWidget> &widget) {
  if (widget == nullptr) return;

  const std::string &type = widget->type;
  const float scl = ui::dpi_scale();

  if (type == "text") {
    ImVec4 col = widget_color(widget->color.empty() ? "text" : widget->color);
    ImGui::TextColored(col, "%s", widget->text.c_str());

  } else if (type == "text_colored") {
    ImVec4 col = widget_color(widget->color.empty() ? "primary" : widget->color);
    ImGui::TextColored(col, "%s", widget->text.c_str());

  } else if (type == "separator") {
    ImGui::Separator();

  } else if (type == "spacing") {
    for (int i = 0; i < widget->count; ++i) ImGui::Spacing();

  } else if (type == "same_line") {
    ImGui::SameLine(widget->offset, widget->spacing);

  } else if (type == "button") {
    if (widget->disabled) ImGui::BeginDisabled();
    bool clicked = false;
    ImVec2 size(widget->width * scl, widget->height > 0.0f ? widget->height * scl : 0.0f);
    if (widget->width <= 0.0f && widget->height <= 0.0f) {
      size = ImVec2(0, 0);
    }

    if (widget->variant == "soft") {
      clicked = ui::soft_button(widget->label.c_str(), size);
    } else if (widget->variant == "danger") {
      clicked = ui::danger_button(widget->label.c_str(), size);
    } else {
      clicked = ui::primary_button(widget->label.c_str(), size);
    }
    if (widget->disabled) ImGui::EndDisabled();
    if (clicked) post_event({widget->id, "click", ""});

  } else if (type == "checkbox") {
    widget->current_checked = widget->checked;
    if (ImGui::Checkbox(widget->label.c_str(), &widget->current_checked)) {
      post_event({widget->id, "toggled", widget->current_checked ? "true" : "false"});
    }

  } else if (type == "input_int") {
    widget->current_int = widget->int_value;
    if (widget->width > 0.0f) ImGui::SetNextItemWidth(widget->width * scl);
    if (ImGui::InputInt(widget->label.c_str(), &widget->current_int,
                         widget->step, widget->step_fast)) {
      post_event({widget->id, "edited", std::to_string(widget->current_int)});
    }
    if (ImGui::IsItemDeactivatedAfterEdit()) {
      post_event({widget->id, "deactivated", std::to_string(widget->current_int)});
    }

  } else if (type == "input_float") {
    widget->current_float = widget->float_value;
    if (widget->width > 0.0f) ImGui::SetNextItemWidth(widget->width * scl);
    if (ImGui::InputFloat(widget->label.c_str(), &widget->current_float,
                           widget->step_float, widget->step_fast_float, "%.4f")) {
      post_event({widget->id, "edited", std::to_string(widget->current_float)});
    }
    if (ImGui::IsItemDeactivatedAfterEdit()) {
      post_event({widget->id, "deactivated", std::to_string(widget->current_float)});
    }

  } else if (type == "input_text") {
    /* Use a fixed-size buffer */
    widget->current_text.resize(4096, '\0');
    if (widget->text_value.size() < 4096) {
      std::memcpy(&widget->current_text[0], widget->text_value.c_str(),
                  widget->text_value.size());
    }
    widget->current_text[std::min(widget->text_value.size(), size_t(4095))] = '\0';

    ImGuiInputTextFlags flags = widget->multiline
        ? ImGuiInputTextFlags_None
        : ImGuiInputTextFlags_EnterReturnsTrue;
    if (!widget->hint.empty())
      flags |= ImGuiInputTextFlags_None;  /* hint shown via placeholder */

    if (widget->width > 0.0f) ImGui::SetNextItemWidth(widget->width * scl);

    if (widget->multiline) {
      ImVec2 text_size(widget->width > 0.0f ? widget->width * scl : -1.0f,
                       widget->height > 0.0f ? widget->height * scl : 60.0f * scl);
      if (ImGui::InputTextMultiline(
              widget->label.c_str(),
              &widget->current_text[0], widget->current_text.size(),
              text_size, flags)) {
        widget->current_text.resize(std::strlen(widget->current_text.c_str()));
        post_event({widget->id, "edited", widget->current_text});
      }
    } else {
      if (ImGui::InputTextWithHint(
              widget->label.empty() ? "##input" : widget->label.c_str(),
              widget->hint.c_str(),
              &widget->current_text[0], widget->current_text.size(),
              flags)) {
        widget->current_text.resize(std::strlen(widget->current_text.c_str()));
        post_event({widget->id, "edited", widget->current_text});
      }
    }
    if (ImGui::IsItemDeactivatedAfterEdit()) {
      widget->current_text.resize(std::strlen(widget->current_text.c_str()));
      post_event({widget->id, "deactivated", widget->current_text});
    }

  } else if (type == "slider_int") {
    widget->current_int = widget->int_value;
    if (widget->width > 0.0f) ImGui::SetNextItemWidth(widget->width * scl);
    if (ImGui::SliderInt(widget->label.c_str(), &widget->current_int,
                          widget->min_int, widget->max_int)) {
      post_event({widget->id, "edited", std::to_string(widget->current_int)});
    }
    if (ImGui::IsItemDeactivatedAfterEdit()) {
      post_event({widget->id, "deactivated", std::to_string(widget->current_int)});
    }

  } else if (type == "slider_float") {
    widget->current_float = widget->float_value;
    if (widget->width > 0.0f) ImGui::SetNextItemWidth(widget->width * scl);
    if (ImGui::SliderFloat(widget->label.c_str(), &widget->current_float,
                            widget->min_float, widget->max_float, "%.4f")) {
      post_event({widget->id, "edited", std::to_string(widget->current_float)});
    }
    if (ImGui::IsItemDeactivatedAfterEdit()) {
      post_event({widget->id, "deactivated", std::to_string(widget->current_float)});
    }

  } else if (type == "combo") {
    widget->current_combo_selected = widget->selected;
    if (widget->width > 0.0f) ImGui::SetNextItemWidth(widget->width * scl);

    std::string preview;
    if (widget->current_combo_selected >= 0 &&
        widget->current_combo_selected < static_cast<int>(widget->items.size())) {
      preview = widget->items[static_cast<size_t>(widget->current_combo_selected)];
    }

    if (ImGui::BeginCombo(widget->label.c_str(), preview.c_str())) {
      for (size_t i = 0; i < widget->items.size(); ++i) {
        const bool is_selected = static_cast<int>(i) == widget->current_combo_selected;
        if (ImGui::Selectable(widget->items[i].c_str(), is_selected)) {
          widget->current_combo_selected = static_cast<int>(i);
          post_event({widget->id, "edited", std::to_string(widget->current_combo_selected)});
          post_event({widget->id, "selected", std::to_string(widget->current_combo_selected)});
        }
        if (is_selected) ImGui::SetItemDefaultFocus();
      }
      ImGui::EndCombo();
    }

  } else if (type == "begin_group") {
    ImGui::BeginGroup();

  } else if (type == "end_group") {
    ImGui::EndGroup();

  } else if (type == "begin_child") {
    ImVec2 child_size(widget->width > 0.0f ? widget->width * scl : 0.0f,
                      widget->height > 0.0f ? widget->height * scl : 0.0f);
    ImGuiWindowFlags child_flags = widget->border ? ImGuiWindowFlags_None
                                                   : ImGuiWindowFlags_NoBackground;
    ImGui::BeginChild(widget->id.c_str(), child_size,
                      widget->border ? true : false, child_flags);

  } else if (type == "end_child") {
    ImGui::EndChild();

  } else if (type == "batch_read_table") {
    /* Efficient multi-address batch-read memory viewer.
       Items: [{address, label?, value_type?, value?}, ...]
       Renders a compact table with a Refresh button that triggers
       a "refresh_batch" event so the Python plugin can issue
       a batch_read call. */
    ImGui::BeginGroup();

    /* Refresh button */
    if (ui::soft_button((std::string(icons::kRefresh) + " Refresh##" + widget->id).c_str(),
                        ImVec2(90.0f * scl, 26.0f * scl))) {
      /* Build JSON array of {address, length} from items */
      nlohmann::json addrs = nlohmann::json::array();
      for (const auto &child : widget->children) {
        if (child->type == "batch_item") {
          nlohmann::json item;
          item["address"] = child->address_value;
          item["length"] = child->step > 0 ? child->step : 4;
          addrs.push_back(item);
        }
      }
      post_event({widget->id, "refresh_batch", addrs.dump()});
    }
    ImGui::SameLine();
    ImGui::TextColored(ui::colors().dim, "%zu addresses", widget->children.size());
    ImGui::Spacing();

    /* Table */
    if (!widget->children.empty()) {
      float table_h = widget->height > 0.0f ? widget->height * scl :
                      std::min(300.0f * scl,
                               static_cast<float>(widget->children.size()) * 22.0f * scl + 28.0f * scl);
      if (ImGui::BeginTable(
              (widget->id + "_table").c_str(), 4,
              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
              ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
              ImVec2(widget->width > 0.0f ? widget->width * scl : 0.0f, table_h))) {
        ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthStretch, 0.3f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 0.25f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.30f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 56.0f * scl);
        ImGui::TableHeadersRow();

        for (const auto &child : widget->children) {
          if (child->type != "batch_item") continue;
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          ImGui::TextUnformatted(child->label.c_str());
          ImGui::TableSetColumnIndex(1);
          ImGui::TextColored(ui::colors().link, "0x%llX",
                             static_cast<unsigned long long>(child->address_value));
          ImGui::TableSetColumnIndex(2);
          ImGui::TextUnformatted(child->text_value.c_str());
          ImGui::TableSetColumnIndex(3);
          ImGui::TextColored(ui::colors().dim, "%s", child->text.c_str());
        }
        ImGui::EndTable();
      }
    }
    ImGui::EndGroup();

  } else if (type == "batch_item") {
    /* batch_item children are not rendered directly;
       they are consumed by the batch_read_table parent. */

  } else if (type == "table") {
    if (ImGui::BeginTable(widget->id.c_str(),
                          static_cast<int>(widget->headers.size()),
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
                          ImVec2(widget->width * scl,
                                 widget->height > 0.0f ? widget->height * scl : 0.0f))) {
      for (const auto &header : widget->headers) {
        ImGui::TableSetupColumn(header.c_str(),
                                ImGuiTableColumnFlags_WidthStretch);
      }
      ImGui::TableHeadersRow();

      for (const auto &row : widget->rows) {
        ImGui::TableNextRow();
        for (size_t col = 0; col < row.size(); ++col) {
          ImGui::TableSetColumnIndex(static_cast<int>(col));
          ImGui::TextUnformatted(row[col].c_str());
        }
      }
      ImGui::EndTable();
    }
  }

  /* Render children recursively */
  for (const auto &child : widget->children) {
    render_widget(child);
  }
}

/* ------------------------------------------------------------------ */
/*  Event posting                                                      */
/* ------------------------------------------------------------------ */

void GuiBridge::post_event(const GuiEvent &event) {
  std::lock_guard<std::mutex> lock(event_mutex_);
  pending_events_.push_back(event);
  event_cv_.notify_one();
}

void GuiBridge::flush_events() {
  /* This is called from the render thread; events are consumed by the writer
   * thread asynchronously.  We just wake it up. */
  event_cv_.notify_one();
}

/* ------------------------------------------------------------------ */
/*  Reader thread                                                      */
/* ------------------------------------------------------------------ */

void GuiBridge::reader_thread() {
  while (running_.load(std::memory_order_acquire)) {
    if (stdout_pipe_ == nullptr) break;

    /* Read MCP-style framed message: Content-Length header + JSON body */
    std::string header_line;
    int ch = 0;
    while ((ch = ::fgetc(stdout_pipe_)) != EOF) {
      if (ch == '\r') continue;
      if (ch == '\n') break;
      header_line += static_cast<char>(ch);
    }
    if (ch == EOF) break;

    /* Consume possible \r\n */
    if (header_line.empty()) {
      /* Empty line = end of headers */
      header_line.clear();
      while ((ch = ::fgetc(stdout_pipe_)) != EOF) {
        if (ch == '\r') continue;
        if (ch == '\n') break;
        header_line += static_cast<char>(ch);
      }
    }

    int content_length = 0;
    if (!header_line.empty()) {
      std::string key;
      std::string value;
      size_t colon = header_line.find(':');
      if (colon != std::string::npos) {
        key = lower_copy(trim_copy(header_line.substr(0, colon)));
        value = trim_copy(header_line.substr(colon + 1));
        if (key == "content-length") {
          try { content_length = std::stoi(value); } catch (...) { content_length = 0; }
        }
      }

      /* Read remaining headers */
      while (true) {
        std::string line;
        while ((ch = ::fgetc(stdout_pipe_)) != EOF) {
          if (ch == '\r') continue;
          if (ch == '\n') break;
          line += static_cast<char>(ch);
        }
        if (line.empty()) break;
        colon = line.find(':');
        if (colon != std::string::npos && content_length == 0) {
          key = lower_copy(trim_copy(line.substr(0, colon)));
          value = trim_copy(line.substr(colon + 1));
          if (key == "content-length") {
            try { content_length = std::stoi(value); } catch (...) {}
          }
        }
      }
    }

    if (content_length <= 0 || content_length > static_cast<int>(kMaxMessageSize)) {
      continue;
    }

    /* Read JSON body */
    std::vector<char> body(static_cast<size_t>(content_length) + 1, '\0');
    size_t total_read = 0;
    while (total_read < static_cast<size_t>(content_length)) {
      size_t n = ::fread(&body[total_read], 1,
                         static_cast<size_t>(content_length) - total_read,
                         stdout_pipe_);
      if (n == 0) break;
      total_read += n;
    }
    body[total_read] = '\0';

    /* Parse JSON */
    nlohmann::json msg;
    try {
      msg = nlohmann::json::parse(body.data());
    } catch (...) {
      continue;  /* skip malformed messages */
    }

    std::string method = json_string(msg, "method");
    if (method == "ui_update") {
      auto widgets_it = msg.find("params");
      if (widgets_it != msg.end() && widgets_it->is_object()) {
        auto arr = widgets_it->find("widgets");
        if (arr != widgets_it->end() && arr->is_array()) {
          std::lock_guard<std::mutex> lock(tree_mutex_);
          pending_tree_.clear();
          for (const auto &w : *arr) {
            if (w.is_object()) {
              auto widget = parse_widget(w);
              if (widget) pending_tree_.push_back(std::move(widget));
            }
          }
          has_tree_.store(true, std::memory_order_release);
        }
      }
    }
    /* Other messages (responses, errors) are silently consumed */
  }
}

/* ------------------------------------------------------------------ */
/*  Writer thread                                                      */
/* ------------------------------------------------------------------ */

void GuiBridge::writer_thread() {
  while (!writer_stop_.load(std::memory_order_acquire)) {
    std::vector<GuiEvent> batch;

    {
      std::unique_lock<std::mutex> lock(event_mutex_);
      event_cv_.wait(lock, [this]() {
        return !pending_events_.empty() || writer_stop_.load(std::memory_order_acquire);
      });
      if (writer_stop_.load(std::memory_order_acquire) && pending_events_.empty()) break;
      batch = std::move(pending_events_);
      pending_events_.clear();
    }

    for (const auto &event : batch) {
      nlohmann::json msg;
      msg["jsonrpc"] = "2.0";
      msg["method"] = "ui_event";
      msg["params"]["id"] = event.widget_id;
      msg["params"]["event"] = event.event;
      if (!event.value.empty()) msg["params"]["value"] = event.value;

      write_message_to_pipe(stdin_pipe_, msg);
    }
  }

  /* Drain remaining events */
  std::lock_guard<std::mutex> lock(event_mutex_);
  for (const auto &event : pending_events_) {
    nlohmann::json msg;
    msg["jsonrpc"] = "2.0";
    msg["method"] = "ui_event";
    msg["params"]["id"] = event.widget_id;
    msg["params"]["event"] = event.event;
    if (!event.value.empty()) msg["params"]["value"] = event.value;
    write_message_to_pipe(stdin_pipe_, msg);
  }
  pending_events_.clear();
}

/* ------------------------------------------------------------------ */
/*  JSON-RPC message write                                             */
/* ------------------------------------------------------------------ */

void GuiBridge::write_message_to_pipe(FILE *pipe, const nlohmann::json &msg) {
  if (pipe == nullptr) return;
  std::string payload = msg.dump();
  ::fprintf(pipe, "Content-Length: %zu\r\n\r\n", payload.size());
  ::fwrite(payload.data(), 1, payload.size(), pipe);
  ::fflush(pipe);
}

/* ------------------------------------------------------------------ */
/*  Stderr reader thread                                               */
/* ------------------------------------------------------------------ */

void GuiBridge::stderr_thread() {
  while (running_.load(std::memory_order_acquire)) {
    if (stderr_pipe_ == nullptr) break;

    char buf[4096];
    char *line = ::fgets(buf, sizeof(buf), stderr_pipe_);
    if (line == nullptr) {
      break;  /* EOF or error — pipe is gone */
    }

    std::lock_guard<std::mutex> lock(stderr_mutex_);
    if (stderr_output_.size() < kMaxStderrBytes) {
      stderr_output_ += line;
      /* Truncate if over limit */
      if (stderr_output_.size() > kMaxStderrBytes) {
        stderr_output_.resize(kMaxStderrBytes);
        stderr_output_ += "\n... (stderr truncated)";
      }
    }
  }
}

std::string GuiBridge::stderr_text() const {
  std::lock_guard<std::mutex> lock(stderr_mutex_);
  return stderr_output_;
}

std::string GuiBridge::debug_info() const {
  std::string out;
  out += "=== Bridge Diagnostics ===\n";
  out += "Running: " + std::string(running_.load(std::memory_order_acquire) ? "YES" : "NO") + "\n";
  out += "Child PID: " + std::to_string(child_pid_) + "\n";

  /* Active tree (UI thread — no lock needed) */
  out += "Active tree widgets: " + std::to_string(active_tree_.size()) + "\n";

  /* Pending tree (reader thread writes — lock needed) */
  {
    std::lock_guard<std::mutex> lock(tree_mutex_);
    out += "Pending tree widgets: " + std::to_string(pending_tree_.size()) + "\n";
    out += "Has pending flag: " + std::string(has_tree_.load(std::memory_order_acquire) ? "YES" : "NO") + "\n";
  }

  /* Stderr */
  std::string err = stderr_text();
  out += "Stderr bytes: " + std::to_string(err.size()) + "\n";

  /* Pipes */
  out += "Stdout pipe: " + std::string(stdout_pipe_ != nullptr ? "open" : "CLOSED") + "\n";
  out += "Stdin pipe: " + std::string(stdin_pipe_ != nullptr ? "open" : "CLOSED") + "\n";
  out += "Stderr pipe: " + std::string(stderr_pipe_ != nullptr ? "open" : "CLOSED") + "\n";

  /* Threads */
  out += "Reader thread: " + std::string(reader_thread_.joinable() ? "running" : "stopped") + "\n";
  out += "Writer thread: " + std::string(writer_thread_.joinable() ? "running" : "stopped") + "\n";
  out += "Stderr thread: " + std::string(stderr_thread_.joinable() ? "running" : "stopped") + "\n";

  return out;
}

/* ------------------------------------------------------------------ */
/*  Widget tree parsing                                                */
/* ------------------------------------------------------------------ */

void GuiBridge::parse_ui_update(const nlohmann::json &widgets) {
  if (!widgets.is_array()) return;
  std::lock_guard<std::mutex> lock(tree_mutex_);
  pending_tree_.clear();
  for (const auto &w : widgets) {
    if (w.is_object()) {
      auto widget = parse_widget(w);
      if (widget) pending_tree_.push_back(std::move(widget));
    }
  }
  has_tree_.store(true, std::memory_order_release);
}

std::shared_ptr<GuiWidget> GuiBridge::parse_widget(const nlohmann::json &obj) {
  auto widget = std::make_shared<GuiWidget>();

  widget->type = json_string(obj, "type");
  if (widget->type.empty()) return nullptr;

  widget->id      = json_string(obj, "id");
  widget->label   = json_string(obj, "label");
  widget->text    = json_string(obj, "text");
  widget->color   = json_string(obj, "color");
  widget->variant = json_string(obj, "variant");
  widget->hint    = json_string(obj, "hint");

  widget->checked          = json_bool(obj, "checked");
  widget->int_value        = json_int(obj, "value", json_int(obj, "int_value"));
  widget->float_value      = json_float(obj, "value", json_float(obj, "float_value"));
  widget->text_value       = json_string(obj, "value", json_string(obj, "text_value"));
  widget->step             = json_int(obj, "step", 1);
  widget->step_fast        = json_int(obj, "step_fast", 100);
  widget->step_float       = json_float(obj, "step", 0.1f);
  widget->step_fast_float  = json_float(obj, "step_fast", 1.0f);
  widget->min_int          = json_int(obj, "min", 0);
  widget->max_int          = json_int(obj, "max", 100);
  widget->min_float        = json_float(obj, "min", 0.0f);
  widget->max_float        = json_float(obj, "max", 1.0f);
  widget->selected         = json_int(obj, "selected");
  widget->multiline        = json_bool(obj, "multiline");
  widget->disabled         = json_bool(obj, "disabled");

  widget->width   = json_float(obj, "width");
  widget->height  = json_float(obj, "height");
  widget->offset  = json_float(obj, "offset");
  widget->spacing = json_float(obj, "spacing", -1.0f);
  widget->count   = json_int(obj, "count", 1);
  widget->border  = json_bool(obj, "border", true);

  widget->items   = json_string_array(obj, "items");
  widget->headers = json_string_array(obj, "headers");
  widget->rows    = json_2d_string_array(obj, "rows");

  /* batch_read_table: parse items array into batch_item children */
  if (widget->type == "batch_read_table") {
    auto items_it = obj.find("items");
    if (items_it != obj.end() && items_it->is_array()) {
      for (const auto &item : *items_it) {
        if (!item.is_object()) continue;
        auto child = std::make_shared<GuiWidget>();
        child->type = "batch_item";
        child->label = json_string(item, "label", json_string(item, "name"));
        child->address_value = json_u64(item, "address");
        child->text_value = json_string(item, "value", "...");
        child->text = json_string(item, "value_type", "hex");
        child->step = json_int(item, "length", 4);
        widget->children.push_back(std::move(child));
      }
    }
  }

  /* Init runtime copies */
  widget->current_text    = widget->text_value;
  widget->current_float   = widget->float_value;
  widget->current_int     = widget->int_value;
  widget->current_checked = widget->checked;
  widget->current_selected = widget->selected;
  widget->current_combo_selected = widget->selected;

  /* Parse children */
  auto children_it = obj.find("children");
  if (children_it != obj.end() && children_it->is_array()) {
    for (const auto &child : *children_it) {
      if (child.is_object()) {
        auto child_widget = parse_widget(child);
        if (child_widget) widget->children.push_back(std::move(child_widget));
      }
    }
  }

  return widget;
}

/* ------------------------------------------------------------------ */
/*  Colour helpers                                                     */
/* ------------------------------------------------------------------ */

ImVec4 GuiBridge::widget_color(const std::string &color_name) const {
  if (color_name == "muted")    return ui::colors().muted;
  if (color_name == "dim")      return ui::colors().dim;
  if (color_name == "primary")  return ui::colors().primary;
  if (color_name == "primary2") return ui::colors().primary2;
  if (color_name == "success")  return ui::colors().success;
  if (color_name == "warning")  return ui::colors().warning;
  if (color_name == "danger")   return ui::colors().danger;
  if (color_name == "link")     return ui::colors().link;
  return ui::colors().text;
}

#endif // !MEMDBG_PLATFORM_IOS

} // namespace memdbg::frontend::plugins
