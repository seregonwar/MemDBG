/*
 * memDBG - UI icon codepoints (FontAwesome 6 Free Solid).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * These are UTF-8 encoded strings for FontAwesome 6 Free Solid icons.
 * The font must be loaded via AddFontFromMemoryTTF with the PUA glyph range.
 */

#ifndef MEMDBG_FRONTEND_UI_ICONS_HPP
#define MEMDBG_FRONTEND_UI_ICONS_HPP

namespace memdbg::frontend::icons {

/* Navigation — FontAwesome 6 Free Solid */
constexpr const char *kHome      = "\xef\x80\x95";  /* U+F015 house */
constexpr const char *kConsole   = "\xef\x84\x9b";  /* U+F11B gamepad */
constexpr const char *kProcess   = "\xef\x82\xae";  /* U+F0AE tasks */
constexpr const char *kMemory    = "\xef\x8b\x99";  /* U+F2DB microchip */
constexpr const char *kScanner   = "\xef\x80\x82";  /* U+F002 magnifying-glass */
constexpr const char *kTrainer   = "\xef\x91\x8b";  /* U+F44B dumbbell */
constexpr const char *kLogs      = "\xef\x80\xba";  /* U+F03A list */
constexpr const char *kSettings  = "\xef\x80\x93";  /* U+F013 gear */
constexpr const char *kCredits   = "\xef\x81\x9a";  /* U+F05A info-circle */

/* Actions */
constexpr const char *kConnect    = "\xef\x83\x81"; /* U+F0C1 plug */
constexpr const char *kDisconnect = "\xef\x80\x91"; /* U+F011 power-off */
constexpr const char *kRefresh    = "\xef\x80\xa1"; /* U+F021 arrows-rotate */
constexpr const char *kSearch     = "\xef\x80\x82"; /* U+F002 magnifying-glass */
constexpr const char *kPlay       = "\xef\x81\x8b"; /* U+F04B play */
constexpr const char *kStop       = "\xef\x81\x8d"; /* U+F04D stop */
constexpr const char *kAdd        = "\xef\x81\xa7"; /* U+F067 circle-plus */
constexpr const char *kRemove     = "\xef\x81\xa8"; /* U+F068 circle-minus */
constexpr const char *kSave       = "\xef\x83\x87"; /* U+F0C7 floppy-disk */
constexpr const char *kLoad       = "\xef\x81\x95"; /* U+F055 folder-open */
constexpr const char *kLock       = "\xef\x80\xa3"; /* U+F023 lock */
constexpr const char *kUnlock     = "\xef\x82\x9c"; /* U+F09C unlock */
constexpr const char *kDump       = "\xef\x80\x99"; /* U+F0ED download */
constexpr const char *kImport     = "\xef\x81\xae"; /* U+F06E file-import */
constexpr const char *kExport     = "\xef\x95\xae"; /* U+F56E file-export */
constexpr const char *kBug        = "\xef\x86\x88"; /* U+F188 bug (debug) */

/* Status */
constexpr const char *kSuccess    = "\xef\x81\x98"; /* U+F058 circle-check */
constexpr const char *kWarning    = "\xef\x81\xb1"; /* U+F071 triangle-exclamation */
constexpr const char *kError      = "\xef\x81\x97"; /* U+F057 circle-xmark */
constexpr const char *kInfo       = "\xef\x81\x9a"; /* U+F05A info-circle */
constexpr const char *kOnline     = "\xef\x83\xa6"; /* U+F0E6 signal */
constexpr const char *kOffline    = "\xef\x87\xab"; /* U+F1EB wifi-slash */
constexpr const char *kPointer   = "\xef\x81\x9c"; /* U+F05C crosshairs */
constexpr const char *kTarget     = "\xef\x85\x82"; /* U+F142 bullseye */
constexpr const char *kCode       = "\xef\x84\xa1"; /* U+F121 code */
constexpr const char *kHex        = "\xef\x87\x9c"; /* U+F1DC hashtag */
constexpr const char *kShield     = "\xef\x8f\x91"; /* U+F3D1 shield */
constexpr const char *kTerminal   = "\xef\x84\xa0"; /* U+F120 terminal */
constexpr const char *kFilter     = "\xef\x82\xb0"; /* U+F0B0 filter */
constexpr const char *kCopy       = "\xef\x83\x85"; /* U+F0C5 copy */
constexpr const char *kPaste      = "\xef\x83\xaa"; /* U+F0EA paste */
constexpr const char *kEdit       = "\xef\x81\x84"; /* U+F044 pen-to-square */
constexpr const char *kTrash      = "\xef\x8b\xb8"; /* U+F2ED trash-can */

/* Metrics */
constexpr const char *kTelemetry  = "\xef\x88\x81"; /* U+F201 chart-line */
constexpr const char *kNotify    = "\xef\x83\xaa"; /* U+F0EA bell */
constexpr const char *kGauge      = "\xef\x99\xa4"; /* U+F664 gauge-high */

} // namespace memdbg::frontend::icons

#endif /* MEMDBG_FRONTEND_UI_ICONS_HPP */
