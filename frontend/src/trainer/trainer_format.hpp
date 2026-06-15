/*
 * MemDBG - Multi-format trainer file support.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Supported formats:
 *   .cht     — MemDBG native pipe-delimited (load + save)
 *   .shn     — Reaper Software Suite / MultiTrainer II (load + save, same as .cht)
 *   .json    — GoldHEN cheat JSON (load + save)
 *   .mc4     — Reaper encrypted format (detection only)
 *   .shnext  — Reaper advanced AOB format (detection only)
 */

#ifndef MEMDBG_FRONTEND_TRAINER_FORMAT_HPP
#define MEMDBG_FRONTEND_TRAINER_FORMAT_HPP

#include <string>
#include <vector>

namespace memdbg::frontend {

enum class TrainerFormat {
  CHT,       /* MemDBG native .cht */
  SHN,       /* Reaper MultiTrainer .shn (pipe-delimited, same structure) */
  JSON,      /* GoldHEN JSON cheat format */
  MC4,       /* Reaper encrypted .mc4 (read-only by Reaper Studio) */
  SHNEXT,    /* Reaper advanced AOB .shnext (proprietary binary) */
  Unknown,
};

/* Auto-detect format from filename extension or file magic bytes. */
TrainerFormat detect_trainer_format(const std::string &path);

/* Human-readable name for a format. */
const char *trainer_format_name(TrainerFormat fmt);
const char *trainer_format_ext(TrainerFormat fmt);
bool trainer_format_supports_save(TrainerFormat fmt);

struct CheatEntry;
struct AppState;

/* Load trainer entries from a file into the state's cheat list.
   Returns number of entries imported, or -1 on file error.
   Uses the file extension to auto-detect format. */
int load_trainer_file(AppState &state, const std::string &path);

/* Save trainer entries to a file.
   Uses the file extension to choose format. */
bool save_trainer_file(AppState &state, const std::string &path);

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_TRAINER_FORMAT_HPP */
