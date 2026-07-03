/*
 * MemDBG - Reusable confirmation modal with "don't show again" checkbox.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_UI_CONFIRM_MODAL_HPP
#define MEMDBG_FRONTEND_UI_CONFIRM_MODAL_HPP

#include "imgui.h"
#include "ui_widgets.hpp"
#include "locale.hpp"

namespace memdbg::frontend::ui {

/**
 * Draw a confirmation modal popup with an optional "don't show again" checkbox.
 *
 * Usage pattern:
 *   static bool skip_confirm = false;
 *   if (danger_button("Delete")) ImGui::OpenPopup("ConfirmDelete");
 *   if (confirm_modal("ConfirmDelete", "Are you sure?", "detail...", &skip_confirm, true)) {
 *       // user confirmed — do the action
 *   }
 *
 * @param popupId      Unique ImGui popup ID (string literal or stable buffer).
 * @param message      Main confirmation message (locale key recommended).
 * @param detail       Optional detail line (nullptr for none). Shown in dim color.
 * @param skipConfirm  Pointer to a persistent bool. If *skipConfirm is true,
 *                     the function returns true immediately without showing
 *                     the popup.  If the user checks the box in the popup,
 *                     *skipConfirm is set to true AND the action is confirmed.
 * @param dangerYes    If true, the Yes button is styled as danger (red).
 *                     If false, it's styled as primary (green).
 * @return             true only for the frame where the user confirmed, or
 *                     where the popup was opened with skipConfirm already set.
 */
inline bool confirm_modal(const char *popupId, const char *message,
                          const char *detail, bool *skipConfirm,
                          bool dangerYes = true) {
  /* Not open yet — caller must have called OpenPopup. */
  if (!ImGui::BeginPopupModal(popupId, nullptr,
                              ImGuiWindowFlags_AlwaysAutoResize))
    return false;

  /* Auto-confirm only in response to an explicit popup open. */
  if (skipConfirm != nullptr && *skipConfirm) {
    ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
    return true;
  }

  ImGui::TextWrapped("%s", message);

  if (detail != nullptr && detail[0] != '\0') {
    ImGui::Spacing();
    ImGui::TextColored(colors().dim, "%s", detail);
  }

  ImGui::Spacing();

  /* "Don't show again" checkbox (only when caller provides a skip pointer). */
  if (skipConfirm != nullptr) {
    ImGui::Checkbox(locale::tr("common.dont_show_again"), skipConfirm);
    ImGui::Spacing();
  }

  bool confirmed = false;
  if (dangerYes) {
    if (danger_button(locale::tr("common.yes"), ImVec2(80, 0))) {
      confirmed = true;
      ImGui::CloseCurrentPopup();
    }
  } else {
    if (primary_button(locale::tr("common.yes"), ImVec2(80, 0))) {
      confirmed = true;
      ImGui::CloseCurrentPopup();
    }
  }
  ImGui::SameLine();
  if (soft_button(locale::tr("common.no"), ImVec2(80, 0))) {
    ImGui::CloseCurrentPopup();
  }

  ImGui::EndPopup();
  return confirmed;
}

} // namespace memdbg::frontend::ui

#endif /* MEMDBG_FRONTEND_UI_CONFIRM_MODAL_HPP */
