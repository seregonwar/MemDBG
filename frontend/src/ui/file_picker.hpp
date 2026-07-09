/*
 * MemDBG - Cross-platform native file picker.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Provides a platform-native file-open dialog.
 *   - Windows:  GetOpenFileNameA (commdlg)
 *   - macOS:    AppleScript osascript choose-file
 *   - PS4/PS5:  Returns empty (no native picker available)
 *   - Other:    Returns empty
 */

#ifndef MEMDBG_FRONTEND_UI_FILE_PICKER_HPP
#define MEMDBG_FRONTEND_UI_FILE_PICKER_HPP

#include <string>

namespace memdbg::frontend::ui {

std::string pickFile(const std::string &title = "Select File",
                     const std::string &filter_desc = "All Files",
                     const std::string &filter_ext = "*.*");

std::string pickSaveFile(const std::string &title = "Save File",
                         const std::string &default_name = "",
                         const std::string &filter_desc = "All Files",
                         const std::string &filter_ext = "*.*");

std::string pickFolder(const std::string &title = "Select Folder");

} // namespace memdbg::frontend::ui

#endif /* MEMDBG_FRONTEND_UI_FILE_PICKER_HPP */
