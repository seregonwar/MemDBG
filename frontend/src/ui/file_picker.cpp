/*
 * MemDBG - Cross-platform native file picker implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "file_picker.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cwchar>
#include <memory>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#else
#include <cstdlib>
#endif

namespace memdbg::frontend::ui {

#if defined(_WIN32)
namespace {

std::wstring utf8ToWide(const std::string &text) {
  if (text.empty()) return {};
  const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                       text.data(),
                                       static_cast<int>(text.size()), nullptr, 0);
  if (size <= 0) return {};
  std::wstring wide(static_cast<size_t>(size), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                          static_cast<int>(text.size()), wide.data(), size) <= 0) {
    return {};
  }
  return wide;
}

std::string wideToUtf8(const wchar_t *text) {
  if (text == nullptr || text[0] == L'\0') return {};
  const int length = static_cast<int>(std::wcslen(text));
  const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text,
                                       length, nullptr, 0, nullptr, nullptr);
  if (size <= 0) return {};
  std::string utf8(static_cast<size_t>(size), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, length,
                          utf8.data(), size, nullptr, nullptr) <= 0) {
    return {};
  }
  return utf8;
}

std::wstring makeFilter(const std::string &description,
                        const std::string &extension) {
  const std::wstring wide_description = utf8ToWide(description);
  const std::wstring wide_extension = utf8ToWide(extension);
  std::wstring filter = wide_description + L" (" + wide_extension + L")";
  filter.push_back(L'\0');
  filter += wide_extension;
  filter.push_back(L'\0');
  filter += L"All Files (*.*)";
  filter.push_back(L'\0');
  filter += L"*.*";
  filter.push_back(L'\0');
  filter.push_back(L'\0');
  return filter;
}

} // namespace
#endif

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
  OPENFILENAMEW ofn;
  std::vector<wchar_t> file_buffer(32768U, L'\0');
  const std::wstring wide_title = utf8ToWide(title);
  const std::wstring filter = makeFilter(filter_desc, filter_ext);

  ZeroMemory(&ofn, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = nullptr;
  ofn.lpstrFile = file_buffer.data();
  ofn.nMaxFile = static_cast<DWORD>(file_buffer.size());
  ofn.lpstrFilter = filter.c_str();
  ofn.nFilterIndex = 1;
  ofn.lpstrFileTitle = nullptr;
  ofn.nMaxFileTitle = 0;
  ofn.lpstrInitialDir = nullptr;
  ofn.lpstrTitle = wide_title.c_str();
  ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

  if (GetOpenFileNameW(&ofn) == TRUE) return wideToUtf8(ofn.lpstrFile);
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
  OPENFILENAMEW ofn;
  std::vector<wchar_t> file_buffer(32768U, L'\0');
  const std::wstring wide_default_name = utf8ToWide(default_name);
  const size_t copy_size =
      std::min(wide_default_name.size(), file_buffer.size() - 1U);
  std::copy_n(wide_default_name.begin(), copy_size, file_buffer.begin());
  const std::wstring wide_title = utf8ToWide(title);
  const std::wstring filter = makeFilter(filter_desc, filter_ext);

  ZeroMemory(&ofn, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = nullptr;
  ofn.lpstrFile = file_buffer.data();
  ofn.nMaxFile = static_cast<DWORD>(file_buffer.size());
  ofn.lpstrFilter = filter.c_str();
  ofn.nFilterIndex = 1;
  ofn.lpstrFileTitle = nullptr;
  ofn.nMaxFileTitle = 0;
  ofn.lpstrInitialDir = nullptr;
  ofn.lpstrTitle = wide_title.c_str();
  ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

  if (GetSaveFileNameW(&ofn) == TRUE) return wideToUtf8(ofn.lpstrFile);
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
  BROWSEINFOW bi;
  wchar_t path[MAX_PATH] = {0};
  const std::wstring wide_title = utf8ToWide(title);
  ZeroMemory(&bi, sizeof(bi));
  bi.hwndOwner = nullptr;
  bi.lpszTitle = wide_title.c_str();
  bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX;
  LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
  if (pidl != nullptr) {
    const BOOL converted = SHGetPathFromIDListW(pidl, path);
    CoTaskMemFree(pidl);
    return converted == TRUE ? wideToUtf8(path) : std::string{};
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
