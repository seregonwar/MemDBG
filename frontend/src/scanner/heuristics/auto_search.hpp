/*
 * MemDBG - Auto-search heuristic engine for game value discovery.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Types (AutoSearchCandidate, AutoSearchTarget, etc.) are in app_state.hpp.
 */

#ifndef MEMDBG_FRONTEND_SCANNER_AUTO_SEARCH_HPP
#define MEMDBG_FRONTEND_SCANNER_AUTO_SEARCH_HPP

#include "app_state.hpp"

#include <cstdint>
#include <vector>

namespace memdbg::frontend {

class AutoSearchEngine {
public:
  AutoSearchEngine() = default;

  void set_target(AutoSearchTarget target);
  AutoSearchTarget target() const { return target_; }

  void set_baseline(const std::vector<ScanSnapshotEntry> &snapshot,
                    int value_type, uint32_t value_length);

  bool has_baseline() const { return !baseline_.empty(); }
  size_t baseline_size() const { return baseline_.size(); }

  std::vector<AutoSearchCandidate>
  score_candidates(const std::vector<ScanSnapshotEntry> &current,
                   size_t max_results = 100);

  void reset();

private:
  struct BaselineEntry {
    uint64_t             address;
    std::vector<uint8_t> bytes;
    int                  value_type;
  };

  std::vector<BaselineEntry> baseline_;
  AutoSearchTarget target_ = AutoSearchTarget::Health;

  float score_single(const BaselineEntry &base,
                     const std::vector<uint8_t> &curr_bytes,
                     int eval_type,
                     uint32_t &flags_out,
                     double &old_out, double &new_out) const;

  float score_health(const double old_val, const double new_val,
                     int eval_type, uint32_t &flags) const;
  float score_ammo(const double old_val, const double new_val,
                   int eval_type, uint32_t &flags) const;
  float score_resources(const double old_val, const double new_val,
                        int eval_type, uint32_t &flags) const;
};

} // namespace memdbg::frontend

#endif
