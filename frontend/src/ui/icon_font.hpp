/*
 * MemDBG - Embedded icon font (FontAwesome 6 Free Solid).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The font data is embedded at compile time.
 * Font Awesome Free is licensed under SIL OFL 1.1.
 */

#ifndef MEMDBG_FRONTEND_ICON_FONT_HPP
#define MEMDBG_FRONTEND_ICON_FONT_HPP

#include <cstddef>

namespace memdbg::frontend {

/* Binary TrueType font data (generated with xxd -i). */
extern unsigned char fa_solid_900[];
extern unsigned int  fa_solid_900_len;

/*
 * The FontAwesome PUA glyph range (0xF000-0xF8FF) must be passed to
 * AddFontFromMemoryTTF via its glyph_ranges parameter:
 *
 *   static const ImWchar icon_ranges[] = { 0xF000, 0xF8FF, 0 };
 *   ImFontConfig cfg = {}; cfg.MergeMode = true;
 *   io.Fonts->AddFontFromMemoryTTF(fa_solid_900, fa_solid_900_len,
 *                                  font_size, &cfg, icon_ranges);
 */

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_ICON_FONT_HPP */
