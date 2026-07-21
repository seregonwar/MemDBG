/*
 * MemDBG - Mobile network/discovery UI.
 */
#include "../internal.hpp"
namespace memdbg::frontend {

void draw_mobile_network(AppState &state, ImVec2 size) {
  ensure_console_targets(state);
  poll_mobile_discovery(state);

  const float scl = ui::dpi_scale();
  const auto &palette = ui::colors();
  const bool connected = state.client.connected();
  const bool locked = connected || connect_sequence_pending(state);

  ImGui::BeginChild("MobileNetwork", size, false,
                    ImGuiWindowFlags_AlwaysVerticalScrollbar);
  ImGui::TextColored(palette.primary2, "%s", "Console");
  ImGui::SameLine();
  ui::status_dot(state.conn.connect_pending ? palette.warning :
                 connected ? palette.success : palette.dim);
  ImGui::SameLine();
  ImGui::TextColored(connected ? palette.success :
                     state.conn.connect_pending ? palette.warning : palette.danger,
                     "%s", state.conn.connect_pending ? "Connecting" :
                          connected ? "Connected" : "Offline");

  ImGui::Spacing();
  ImGui::BeginChild("MobileNetworkSummary", ImVec2(0, 112.0f * scl), true,
                    ImGuiWindowFlags_NoScrollbar);
  const ConsoleTarget current_target = {
      state.target_name, state.host, state.debug_port, state.udp_port,
      state.payload_port, state.payload_platform
  };
  mobile_info_row("Target", state.target_name, palette.text);
  mobile_info_row("Endpoint", mobile_target_endpoint(current_target),
                  connected ? palette.text : palette.muted);
  mobile_info_row("UDP", state.udp_listener.running() ? "Listening" : "Stopped",
                  state.udp_listener.running() ? palette.success : palette.dim);
  mobile_info_row("Payload", state.has_hello ? "Handshake OK" : "No hello",
                  state.has_hello ? palette.success : palette.dim);
  ImGui::EndChild();

  if (connect_sequence_pending(state)) {
    if (mobile_action_button(std::string(icons::kDisconnect) +
                             "  Cancel connection", false, true)) {
      cancel_connect(state);
    }
  } else {
    ImGui::BeginDisabled(client_async_busy(state));
    if (connected) {
      if (mobile_action_button(std::string(icons::kGauge) + "  Ping payload",
                               false)) {
        set_status(state, state.client.ping() ? "Ping OK"
                                              : state.client.last_error());
      }
      if (mobile_action_button(std::string(icons::kDisconnect) +
                               "  Disconnect", false, true)) {
        disconnect_console(state);
      }
    } else {
      if (mobile_action_button(std::string(icons::kConnect) + "  Connect",
                               true)) {
        save_current_console_target(state);
        connect_console(state, ConnectIntent::ManualFreshConnection);
      }
    }
    ImGui::EndDisabled();
  }

  draw_mobile_section_label("Target");
  ImGui::BeginDisabled(locked);
  std::string preview = state.console_targets.empty()
      ? "No saved targets"
      : state.console_targets[static_cast<size_t>(
            std::clamp(state.selected_target_index, 0,
                       static_cast<int>(state.console_targets.size()) - 1))].name;
  ImGui::SetNextItemWidth(-1.0f);
  if (ImGui::BeginCombo("##MobileTargetProfile", preview.c_str())) {
    for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
      const ConsoleTarget &target = state.console_targets[static_cast<size_t>(i)];
      const bool selected = i == state.selected_target_index;
      const std::string label = target.name + "  " +
                                mobile_target_endpoint(target);
      if (ImGui::Selectable(label.c_str(), selected))
        select_console_target(state, i);
      if (selected) ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }

  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText("Name##MobileTargetName", state.target_name,
                   sizeof(state.target_name));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputText("IPv4##MobileTargetHost", state.host, sizeof(state.host));
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("Debug TCP##MobileDebugPort", &state.debug_port);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("UDP logs##MobileUdpPort", &state.udp_port);
  ImGui::SetNextItemWidth(-1.0f);
  ImGui::InputInt("Payload ELF##MobilePayloadPort", &state.payload_port);
  const char *platform_options[] = {"Auto", "PS4", "PS5"};
  ImGui::SetNextItemWidth(-1.0f);
  if (ImGui::Combo("Platform##MobilePayloadPlatform", &state.payload_platform,
                   platform_options, 3)) {
    state.payload_fetcher.set_platform(payload_platform_filter(state.payload_platform));
  }
  normalize_ports(state);

  ImGui::Checkbox("Auto inject on startup##MobileAutoInject",
                  &state.payload_auto_inject);
  ImGui::Checkbox("Auto shutdown on exit##MobileAutoShutdown",
                  &state.payload_auto_shutdown);

  ImGui::BeginDisabled(connected || connect_sequence_pending(state) ||
                       state.payload_inject_pending);
  if (mobile_action_button(std::string(icons::kConnect) +
                           "  Inject & connect", true)) {
    save_current_console_target(state);
    request_payload_inject(state, true);
  }
  ImGui::EndDisabled();

  const float gap = 6.0f * scl;
  const float button_w = (ImGui::GetContentRegionAvail().x - gap * 2.0f) / 3.0f;
  if (ui::soft_button((std::string(icons::kSave) + " Save").c_str(),
                      ImVec2(button_w, 40.0f * scl))) {
    save_current_console_target(state);
    mobile_persist_console_targets(state, "Console target updated");
  }
  ImGui::SameLine(0, gap);
  if (ui::primary_button((std::string(icons::kAdd) + " Add").c_str(),
                         ImVec2(button_w, 40.0f * scl))) {
    add_console_target(state);
    mobile_persist_console_targets(state, "Console target added");
  }
  ImGui::SameLine(0, gap);
  if (ui::danger_button((std::string(icons::kTrash) + " Del").c_str(),
                        ImVec2(button_w, 40.0f * scl))) {
    remove_selected_console_target(state);
    mobile_persist_console_targets(state, "Console target removed");
  }
  ImGui::EndDisabled();

  draw_mobile_section_label("Saved");
  for (int i = 0; i < static_cast<int>(state.console_targets.size()); ++i) {
    const ConsoleTarget &target = state.console_targets[static_cast<size_t>(i)];
    const bool selected = i == state.selected_target_index;
    ImGui::PushID(i);
    ImGui::BeginDisabled(locked);
    const std::string label =
        std::string(icons::kTarget) + "  " + (selected ? "* " : "") +
        target.name + "\n" + mobile_target_endpoint(target);
    if (ui::soft_button(label.c_str(),
                        ImVec2(ImGui::GetContentRegionAvail().x,
                               52.0f * scl))) {
      select_console_target(state, i);
    }
    ImGui::EndDisabled();
    ImGui::PopID();
  }

  draw_mobile_section_label("Runtime");
  if (!state.udp_listener.running()) {
    if (mobile_action_button("Start UDP log listener", false)) {
      std::string error;
      if (ensure_udp_listener(state, error)) set_status(state, "UDP started");
      else set_status(state, error);
    }
  } else {
    if (mobile_action_button("Restart UDP log listener", false)) {
      state.udp_listener.stop();
      std::string error;
      if (ensure_udp_listener(state, error)) set_status(state, "UDP restarted");
      else set_status(state, error);
    }
    if (mobile_action_button("Stop UDP log listener", false)) {
      state.udp_listener.stop();
      set_status(state, "UDP stopped");
    }
  }

  draw_mobile_section_label("Discovery");
  ImGui::BeginDisabled(state.discovery_pending);
  if (mobile_action_button(std::string(icons::kRefresh) +
                           (state.discovery_pending ? "  Searching" :
                            "  Discover payloads"), false)) {
    start_mobile_discovery(state);
  }
  ImGui::EndDisabled();

  if (!state.discovered_consoles.empty()) {
    for (int i = 0; i < static_cast<int>(state.discovered_consoles.size()); ++i) {
      const DiscoveryConsole &console =
          state.discovered_consoles[static_cast<size_t>(i)];
      const std::string name = !console.name.empty() ? console.name : console.ip;
      const std::string endpoint =
          console.ip + ":" + std::to_string(console.debug_port) +
          " / UDP " + std::to_string(console.udp_log_port);
      ImGui::PushID(1000 + i);
      ImGui::BeginChild("MobileDiscoveredPayload", ImVec2(0, 86.0f * scl),
                        true, ImGuiWindowFlags_NoScrollbar);
      text_ellipsis(name.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.text);
      text_ellipsis(endpoint.c_str(), ImGui::GetContentRegionAvail().x,
                    palette.muted);
      const float half = (ImGui::GetContentRegionAvail().x - gap) * 0.5f;
      ImGui::BeginDisabled(locked);
      if (ui::soft_button("Use", ImVec2(half, 32.0f * scl))) {
        mobile_use_discovered_console(state, console);
        set_status(state, "Selected discovered target " + console.ip);
      }
      ImGui::SameLine(0, gap);
      if (ui::primary_button("Save", ImVec2(half, 32.0f * scl))) {
        mobile_use_discovered_console(state, console);
        add_console_target(state);
        mobile_persist_console_targets(state, "Discovered target saved");
      }
      ImGui::EndDisabled();
      ImGui::EndChild();
      ImGui::PopID();
    }
  }

  ImGui::Dummy(ImVec2(1.0f, 10.0f * scl));
  ImGui::EndChild();
}


} // namespace memdbg::frontend
