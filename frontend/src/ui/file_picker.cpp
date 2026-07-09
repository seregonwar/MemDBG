/*
 * MemDBG - Cross-platform native file picker implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "file_picker.hpp"

#include <array>
#include <cstdio>
#include <memory>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commdlg.h>
#else
#include <cstdlib>
#endif

namespace memdbg::frontend::ui {

#if !defined(_WIN32)
static std::string execCommand(const char *cmd) {
  std::array<char, 128> buffer;
  std::string result;
  FILE *pipe = popen(cmd, "r");
  if (!pipe) return "";
  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) !=
         nullptr) {
    result += buffer.data();
  }
  (void)pclose(pipe);
  if (!result.empty() && result.back() == '\n') result.pop_back();
  return result;
}
#endif

std::string pickFile(const std::string &title, const std::string &filter_desc,
                     const std::string &filter_ext) {
#if defined(_WIN32)
  OPENFILENAMEA ofn;
  char szFile[260] = {0};

  ZeroMemory(&ofn, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = nullptr;
  ofn.lpstrFile = szFile;
  ofn.nMaxFile = sizeof(szFile);

  std::string filter_str =
      filter_desc + " (" + filter_ext + ")\0" + filter_ext +
      "\0All Files (*.*)\0*.*\0";
  ofn.lpstrFilter = filter_str.c_str();
  ofn.nFilterIndex = 1;
  ofn.lpstrFileTitle = nullptr;
  ofn.nMaxFileTitle = 0;
  ofn.lpstrInitialDir = nullptr;
  ofn.lpstrTitle = title.c_str();
  ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

  if (GetOpenFileNameA(&ofn) == TRUE) return ofn.lpstrFile;
  return "";

#elif defined(__APPLE__)
  (void)filter_desc;
  (void)filter_ext;
  std::string cmd =
      "osascript -e 'POSIX path of (choose file with prompt \""
      + title + "\")' 2>/dev/null";
  return execCommand(cmd.c_str());

#elif defined(__ORBIS__) || defined(__PROSPERO__)
  (void)title;
  (void)filter_desc;
  (void)filter_ext;
  return "";

#else
  (void)filter_desc;
  (void)filter_ext;
  std::string cmd_zen =
      "zenity --file-selection --title=\"" + title + "\" 2>/dev/null";
  std::string result = execCommand(cmd_zen.c_str());
  if (!result.empty()) return result;

  std::string cmd_kde =
      "kdialog --getopenfilename --title \"" + title + "\" 2>/dev/null";
  result = execCommand(cmd_kde.c_str());
  return result;
#endif
}

std::string pickSaveFile(const std::string &title,
                         const std::string &default_name,
                         const std::string &filter_desc,
                         const std::string &filter_ext) {
#if defined(_WIN32)
  OPENFILENAMEA ofn;
  char szFile[260] = {0};
  if (!default_name.empty())
    std::snprintf(szFile, sizeof(szFile), "%s", default_name.c_str());

  ZeroMemory(&ofn, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = nullptr;
  ofn.lpstrFile = szFile;
  ofn.nMaxFile = sizeof(szFile);

  std::string filter_str =
      filter_desc + " (" + filter_ext + ")\0" + filter_ext +
      "\0All Files (*.*)\0*.*\0";
  ofn.lpstrFilter = filter_str.c_str();
  ofn.nFilterIndex = 1;
  ofn.lpstrFileTitle = nullptr;
  ofn.nMaxFileTitle = 0;
  ofn.lpstrInitialDir = nullptr;
  ofn.lpstrTitle = title.c_str();
  ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

  if (GetSaveFileNameA(&ofn) == TRUE) return ofn.lpstrFile;
  return "";

#elif defined(__APPLE__)
  (void)filter_desc;
  (void)filter_ext;
  std::string cmd =
      "osascript -e 'POSIX path of (choose file name"
      " with prompt \""
      + title + "\"";
  if (!default_name.empty())
    cmd += " default name \"" + default_name + "\"";
  cmd += ")' 2>/dev/null";
  return execCommand(cmd.c_str());

#elif defined(__ORBIS__) || defined(__PROSPERO__)
  (void)title;
  (void)default_name;
  (void)filter_desc;
  (void)filter_ext;
  return "";

#else
  (void)filter_desc;
  (void)filter_ext;
  std::string cmd_zen =
      "zenity --file-selection --save --confirm-overwrite"
      " --title=\""
      + title + "\"";
  if (!default_name.empty())
    cmd_zen += " --filename=\"" + default_name + "\"";
  cmd_zen += " 2>/dev/null";
  std::string result = execCommand(cmd_zen.c_str());
  if (!result.empty()) return result;

  std::string cmd_kde =
      "kdialog --getsavefilename";
  if (!default_name.empty())
    cmd_kde += " \"" + default_name + "\"";
  cmd_kde += " --title \"" + title + "\" 2>/dev/null";
  result = execCommand(cmd_kde.c_str());
  return result;
#endif
}

std::string pickFolder(const std::string &title) {
#if defined(_WIN32)
  BROWSEINFOA bi;
  char path[MAX_PATH] = {0};
  ZeroMemory(&bi, sizeof(bi));
  bi.hwndOwner = nullptr;
  bi.lpszTitle = title.c_str();
  bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX;
  LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
  if (pidl != nullptr) {
    SHGetPathFromIDListA(pidl, path);
    CoTaskMemFree(pidl);
    return path;
  }
  return "";

#elif defined(__APPLE__)
  std::string cmd =
      "osascript -e 'POSIX path of (choose folder with prompt \""
      + title + "\")' 2>/dev/null";
  return execCommand(cmd.c_str());

#elif defined(__ORBIS__) || defined(__PROSPERO__)
  (void)title;
  return "";

#else
  std::string cmd_zen =
      "zenity --file-selection --directory --title=\"" + title + "\" 2>/dev/null";
  std::string result = execCommand(cmd_zen.c_str());
  if (!result.empty()) return result;

  std::string cmd_kde =
      "kdialog --getexistingdirectory --title \"" + title + "\" 2>/dev/null";
  result = execCommand(cmd_kde.c_str());
  return result;
#endif
}

} // namespace memdbg::frontend::ui
