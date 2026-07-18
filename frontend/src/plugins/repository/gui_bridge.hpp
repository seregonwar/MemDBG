/*
 * MemDBG - GUI plugin bridge (Python -> ImGui rendering).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_GUI_BRIDGE_HPP
#define MEMDBG_FRONTEND_GUI_BRIDGE_HPP

#include "imgui.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace memdbg::frontend { class ClientPool; }

namespace memdbg::frontend::plugins {

class ProtocolBroker;

/* ------------------------------------------------------------------ */
/*  Widget tree node                                                   */
/* ------------------------------------------------------------------ */

struct GuiWidget {
  std::string type;

  /* Common */
  std::string id;
  std::string label;
  std::string text;
  std::string color;       /* "text", "muted", "dim", "primary", "primary2",
                               "success", "warning", "danger", "link" */
  std::string variant;     /* button: "primary", "soft", "danger" */
  std::string hint;

  /* Interactable values */
  bool        checked = false;
  int         int_value = 0;
  float       float_value = 0.0f;
  std::string text_value;
  int         step = 1;
  int         step_fast = 100;
  float       step_float = 0.1f;
  float       step_fast_float = 1.0f;
  int         min_int = 0;
  int         max_int = 100;
  float       min_float = 0.0f;
  float       max_float = 1.0f;
  int         selected = 0;
  std::vector<std::string> items;   /* combo items */
  bool        multiline = false;
  bool        disabled = false;

  /* Layout */
  float       width = 0.0f;
  float       height = 0.0f;
  float       offset = 0.0f;
  float       spacing = -1.0f;
  int         count = 1;   /* spacing */
  bool        border = true;

  /* Table */
  std::vector<std::string> headers;
  std::vector<std::vector<std::string>> rows;

  /* Children (non-table) */
  std::vector<std::shared_ptr<GuiWidget>> children;

  /* Runtime (set by renderer) */
  std::string current_text;    /* current InputText value */
  float       current_float = 0.0f;
  int         current_int = 0;
  bool        current_checked = false;
  int         current_selected = 0;
  int         current_combo_selected = 0;
  uint64_t    address_value = 0;  /* batch_item memory address */
};

/* ------------------------------------------------------------------ */
/*  UI event (C++ -> Python)                                           */
/* ------------------------------------------------------------------ */

struct GuiEvent {
  std::string widget_id;
  std::string event;       /* "click", "edited", "toggled", "selected",
                               "deactivated" */
  std::string value;       /* optional value as string */
};

/* ------------------------------------------------------------------ */
/*  GuiBridge — manages persistent plugin process + ImGui rendering    */
/* ------------------------------------------------------------------ */

class GuiBridge {
public:
  GuiBridge();
  ~GuiBridge();

  GuiBridge(const GuiBridge &) = delete;
  GuiBridge &operator=(const GuiBridge &) = delete;

  /* Lifecycle */
  bool start(const std::filesystem::path &python_exe,
             const std::filesystem::path &script_path,
             const std::filesystem::path &context_path);
  bool start_protocol_broker(ClientPool &pool);
  uint16_t protocol_broker_port() const;
  void stop();
  bool running() const { return running_.load(std::memory_order_acquire); }

  /* Frame update: swap in the latest widget tree, render, flush events */
  void begin_frame();
  bool has_tree() const { return has_tree_.load(std::memory_order_acquire); }
  bool has_active_tree() const { return !active_tree_.empty(); }
  void end_frame();   /* flush pending events */

  /* Render the current widget tree (called between begin/end_frame) */
  void render_widgets();

  /* Flush pending events to Python stdin (called from any thread) */
  void flush_events();

  /* Captured stderr from the plugin process */
  std::string stderr_text() const;

  /* Debug diagnostics (click-to-copy friendly) */
  std::string debug_info() const;

private:
  /* Process I/O threads */
  void reader_thread();
  void writer_thread();

  /* Parse a ui_update notification and build the widget tree */
  void parse_ui_update(const nlohmann::json &widgets);
  std::shared_ptr<GuiWidget> parse_widget(const nlohmann::json &obj);

  /* Render a single widget (recursive) */
  void render_widget(const std::shared_ptr<GuiWidget> &widget);

  /* Post an event for the writer thread */
  void post_event(const GuiEvent &event);

  /* Write a JSON-RPC message to the process stdin */
  static void write_message_to_pipe(FILE *pipe, const nlohmann::json &msg);

  /* Colour helpers */
  ImVec4 widget_color(const std::string &color_name) const;

  /* Process handle */
  FILE *stdin_pipe_ = nullptr;
  FILE *stdout_pipe_ = nullptr;
  int child_pid_ = 0;
  std::atomic<bool> running_{false};

  /* Reader thread */
  std::thread reader_thread_;
  mutable std::mutex tree_mutex_;
  std::vector<std::shared_ptr<GuiWidget>> pending_tree_;
  std::vector<std::shared_ptr<GuiWidget>> active_tree_;
  std::atomic<bool> has_tree_{false};

  /* Writer thread */
  std::thread writer_thread_;
  std::mutex event_mutex_;
  std::condition_variable event_cv_;
  std::vector<GuiEvent> pending_events_;
  std::atomic<bool> writer_stop_{false};

  /* Stderr reader thread */
  void stderr_thread();
  FILE *stderr_pipe_ = nullptr;
  std::thread stderr_thread_;
  mutable std::mutex stderr_mutex_;
  std::string stderr_output_;
  static constexpr size_t kMaxStderrBytes = 64U * 1024U;
  std::unique_ptr<ProtocolBroker> protocol_broker_;
};

} // namespace memdbg::frontend::plugins

#endif /* MEMDBG_FRONTEND_GUI_BRIDGE_HPP */
