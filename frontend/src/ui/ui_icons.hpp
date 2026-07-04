/*
 * MemDBG - UI icon codepoints (FontAwesome 6 Free Solid).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * These are UTF-8 encoded strings for FontAwesome 6 Free Solid icons.
 * The font must be loaded via AddFontFromMemoryTTF with the PUA glyph range.
 */

#ifndef MEMDBG_FRONTEND_UI_ICONS_HPP
#define MEMDBG_FRONTEND_UI_ICONS_HPP

namespace memdbg::frontend::icons {

/* Navigation - FontAwesome 6 Free Solid private-use codepoints. */
constexpr const char *kHome      = u8"\uf015"; /* house */
constexpr const char *kConsole   = u8"\uf11b"; /* gamepad */
constexpr const char *kProcess   = u8"\uf0ae"; /* list-check */
constexpr const char *kMemory    = u8"\uf2db"; /* microchip */
constexpr const char *kScanner   = u8"\uf002"; /* magnifying-glass */
constexpr const char *kTrainer   = u8"\uf44b"; /* dumbbell */
constexpr const char *kPlugins   = u8"\uf12e"; /* puzzle-piece */
constexpr const char *kLogs      = u8"\uf03a"; /* list */
constexpr const char *kSettings  = u8"\uf013"; /* gear */
constexpr const char *kCredits   = u8"\uf05a"; /* circle-info */

/* Actions */
constexpr const char *kConnect    = u8"\uf1e6"; /* plug */
constexpr const char *kDisconnect = u8"\uf011"; /* power-off */
constexpr const char *kRefresh    = u8"\uf021"; /* arrows-rotate */
constexpr const char *kSearch     = u8"\uf002"; /* magnifying-glass */
constexpr const char *kPlay       = u8"\uf04b"; /* play */
constexpr const char *kStop       = u8"\uf04d"; /* stop */
constexpr const char *kAdd        = u8"\uf055"; /* circle-plus */
constexpr const char *kRemove     = u8"\uf056"; /* circle-minus */
constexpr const char *kSave       = u8"\uf0c7"; /* floppy-disk */
constexpr const char *kLoad       = u8"\uf07c"; /* folder-open */
constexpr const char *kLock       = u8"\uf023"; /* lock */
constexpr const char *kUnlock     = u8"\uf09c"; /* unlock */
constexpr const char *kDump       = u8"\uf019"; /* download */
constexpr const char *kImport     = u8"\uf56f"; /* file-import */
constexpr const char *kExport     = u8"\uf56e"; /* file-export */
constexpr const char *kBug        = u8"\uf188"; /* bug */

/* Status */
constexpr const char *kSuccess    = u8"\uf058"; /* circle-check */
constexpr const char *kWarning    = u8"\uf071"; /* triangle-exclamation */
constexpr const char *kError      = u8"\uf057"; /* circle-xmark */
constexpr const char *kInfo       = u8"\uf05a"; /* circle-info */
constexpr const char *kOnline     = u8"\uf012"; /* signal */
constexpr const char *kOffline    = u8"\uf1eb"; /* wifi */
constexpr const char *kPointer    = u8"\uf05b"; /* crosshairs */
constexpr const char *kTarget     = u8"\uf140"; /* bullseye */
constexpr const char *kCode       = u8"\uf121"; /* code */
constexpr const char *kHex        = u8"\uf292"; /* hashtag */
constexpr const char *kShield     = u8"\uf132"; /* shield */
constexpr const char *kTerminal   = u8"\uf120"; /* terminal */
constexpr const char *kFilter     = u8"\uf0b0"; /* filter */
constexpr const char *kCopy       = u8"\uf0c5"; /* copy */
constexpr const char *kPaste      = u8"\uf0ea"; /* paste */
constexpr const char *kEdit       = u8"\uf044"; /* pen-to-square */
constexpr const char *kTrash      = u8"\uf2ed"; /* trash-can */
constexpr const char *kLink       = u8"\uf0c1"; /* link */

/* Metrics */
constexpr const char *kTelemetry  = u8"\uf201"; /* chart-line */
constexpr const char *kNotify     = u8"\uf0f3"; /* bell */
constexpr const char *kGauge      = u8"\uf3fd"; /* gauge-high */
constexpr const char *kMore       = u8"\uf142"; /* ellipsis-vertical */

} // namespace memdbg::frontend::icons

#endif /* MEMDBG_FRONTEND_UI_ICONS_HPP */
