/*
 * MemDBG - Auto-search heuristic engine implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Types (AutoSearchCandidate, etc.) are defined inline in app_state.hpp.
 */

#include "auto_search.hpp"

#include <algorithm>
#include <cmath>

namespace memdbg::frontend {

/* ---- Engine ---- */

void AutoSearchEngine::set_target(AutoSearchTarget target) {
  target_ = target;
  reset();
}

void AutoSearchEngine::set_baseline(const std::vector<ScanSnapshotEntry> &snapshot,
                                    int value_type, uint32_t /*value_length*/) {
  baseline_.clear();
  baseline_.reserve(snapshot.size());
  for (const auto &s : snapshot) {
    BaselineEntry e;
    e.address    = s.address;
    e.bytes      = s.bytes;
    e.value_type = value_type;
    baseline_.push_back(std::move(e));
  }
}

void AutoSearchEngine::reset() {
  baseline_.clear();
}

/* ---- Core scoring: evaluate one entry against multiple types ---- */

float AutoSearchEngine::score_single(const BaselineEntry &base,
                                     const std::vector<uint8_t> &curr_bytes,
                                     int eval_type,
                                     uint32_t &flags_out,
                                     double &old_out, double &new_out) const {
  flags_out = 0U;
  old_out = 0.0;
  new_out = 0.0;

  /* Aligned address check */
  uint32_t align = 1U;
  switch (eval_type) {
  case MEMDBG_VALUE_U8:  align = 1U; break;
  case MEMDBG_VALUE_U16: align = 2U; break;
  case MEMDBG_VALUE_U32: case MEMDBG_VALUE_F32: align = 4U; break;
  case MEMDBG_VALUE_U64: case MEMDBG_VALUE_F64: align = 8U; break;
  }
  if ((base.address & (align - 1U)) != 0U) return 0.0f;
  flags_out |= kFlagAlignedAddr;

  size_t need = 0;
  switch (eval_type) {
  case MEMDBG_VALUE_U8:  need = 1; break;
  case MEMDBG_VALUE_U16: need = 2; break;
  case MEMDBG_VALUE_U32: case MEMDBG_VALUE_F32: need = 4; break;
  case MEMDBG_VALUE_U64: case MEMDBG_VALUE_F64: need = 8; break;
  default: return 0.0f;
  }

  if (base.bytes.size() < need || curr_bytes.size() < need) return 0.0f;

  switch (eval_type) {
  case MEMDBG_VALUE_U8:
    old_out = (double)read_scalar<uint8_t>(base.bytes);
    new_out = (double)read_scalar<uint8_t>(curr_bytes);
    flags_out |= kFlagIntegerType;
    break;
  case MEMDBG_VALUE_U16:
    old_out = (double)read_scalar<uint16_t>(base.bytes);
    new_out = (double)read_scalar<uint16_t>(curr_bytes);
    flags_out |= kFlagIntegerType;
    break;
  case MEMDBG_VALUE_U32:
    old_out = (double)read_scalar<uint32_t>(base.bytes);
    new_out = (double)read_scalar<uint32_t>(curr_bytes);
    flags_out |= kFlagIntegerType;
    break;
  case MEMDBG_VALUE_U64:
    old_out = (double)read_scalar<uint64_t>(base.bytes);
    new_out = (double)read_scalar<uint64_t>(curr_bytes);
    flags_out |= kFlagIntegerType;
    break;
  case MEMDBG_VALUE_F32:
    old_out = (double)read_scalar<float>(base.bytes);
    new_out = (double)read_scalar<float>(curr_bytes);
    {
      double frac = std::fmod(new_out, 1.0);
      if (frac < 0.001 || frac > 0.999)
        flags_out |= kFlagFloatRepr;
    }
    break;
  case MEMDBG_VALUE_F64:
    old_out = (double)read_scalar<double>(base.bytes);
    new_out = (double)read_scalar<double>(curr_bytes);
    break;
  default: return 0.0f;
  }

  /* Kill float evaluations where the value is clearly bogus (subnormal).
   * Example: u32 100 (0x64) interpreted as f32 → ~1.4e-43, which sets
   * kFlagFloatRepr because fmod(1.4e-43, 1.0) < 0.001.  Real float game
   * values (85.0f, 10.5f) are >= 0.01 so the gate won't fire for them. */
  if (!(flags_out & kFlagIntegerType) && (flags_out & kFlagFloatRepr) &&
      new_out < 0.01 && old_out < 0.01)
    return 0.0f;

  switch (target_) {
  case AutoSearchTarget::Health:
    return score_health(old_out, new_out, eval_type, flags_out);
  case AutoSearchTarget::Ammo:
    return score_ammo(old_out, new_out, eval_type, flags_out);
  case AutoSearchTarget::Resources:
    return score_resources(old_out, new_out, eval_type, flags_out);
  }
  return 0.0f;
}

/* ---- Health heuristics ---- */

float AutoSearchEngine::score_health(const double old_val, const double new_val,
                                     int eval_type, uint32_t &flags) const {
  float s = 0.0f;
  int hits = 0;

  if (new_val < old_val) { s += 1.0f; hits++; flags |= kFlagDecreased; }
  if (new_val > 0.0)     { s += 0.8f; hits++; flags |= kFlagNonZero; }

  bool in_range = false;
  switch (eval_type) {
  case MEMDBG_VALUE_U8:  in_range = (new_val >= 1.0 && new_val <= 200.0); break;
  case MEMDBG_VALUE_U16: in_range = (new_val >= 1.0 && new_val <= 4000.0); break;
  case MEMDBG_VALUE_U32: in_range = (new_val >= 1.0 && new_val <= 9999.0); break;
  case MEMDBG_VALUE_F32: in_range = (new_val >= 0.1 && new_val <= 9999.0); break;
  default:               in_range = (new_val >= 1.0 && new_val <= 99999.0); break;
  }
  if (in_range) { s += 0.6f; hits++; flags |= kFlagReasonableRange; }

  if (old_val > 0.0) {
    double delta = std::fabs(old_val - new_val);
    if (delta > 0.0 && delta / old_val < 0.5) {
      s += 0.5f; hits++; flags |= kFlagSmallDelta;
    }
  }

  if (flags & kFlagIntegerType) { s += 0.4f; hits++; }

  if (old_val == new_val) return 0.0f;
  return hits > 0 ? s / (float)hits : 0.0f;
}

/* ---- Ammo heuristics ---- */

float AutoSearchEngine::score_ammo(const double old_val, const double new_val,
                                   int eval_type, uint32_t &flags) const {
  float s = 0.0f;
  int hits = 0;

  double delta = std::fabs(old_val - new_val);
  if (new_val < old_val && delta >= 1.0 && delta <= 30.0) {
    s += 1.0f; hits++; flags |= kFlagDecreased | kFlagSmallDelta;
  }

  bool small = false;
  switch (eval_type) {
  case MEMDBG_VALUE_U8:  small = (new_val <= 200.0 && old_val <= 200.0); break;
  case MEMDBG_VALUE_U16: small = (new_val <= 999.0 && old_val <= 999.0); break;
  default:               small = (new_val <= 999.0 && old_val <= 999.0); break;
  }
  if (small) { s += 0.7f; hits++; flags |= kFlagReasonableRange; }

  if (flags & kFlagIntegerType) { s += 0.5f; hits++; }

  if (old_val > 0.0) { s += 0.3f; hits++; flags |= kFlagNonZero; }

  if (old_val == new_val) return 0.0f;
  return hits > 0 ? s / (float)hits : 0.0f;
}

/* ---- Resources heuristics ---- */

float AutoSearchEngine::score_resources(const double old_val, const double new_val,
                                        int /*eval_type*/, uint32_t &flags) const {
  float s = 0.0f;
  int hits = 0;

  double delta = std::fabs(old_val - new_val);

  if (delta > 0.0) {
    s += 1.0f; hits++;
    if (new_val > old_val) flags |= kFlagIncreased;
    else                   flags |= kFlagDecreased;
  }

  if (old_val > 0.0 && delta > 0.0) {
    double ratio = delta / old_val;
    if (ratio > 0.01 && ratio < 50.0) { s += 0.6f; hits++; flags |= kFlagSmallDelta; }
  }

  if (new_val >= 1.0 && new_val <= 999999.0) { s += 0.5f; hits++; flags |= kFlagReasonableRange; }
  if (new_val >= 0.0)                        { s += 0.4f; hits++; flags |= kFlagNonZero; }

  if (old_val == new_val) return 0.0f;
  return hits > 0 ? s / (float)hits : 0.0f;
}

/* ---- Main scoring ---- */

std::vector<AutoSearchCandidate>
AutoSearchEngine::score_candidates(const std::vector<ScanSnapshotEntry> &current,
                                   size_t max_results) {
  std::vector<AutoSearchCandidate> results;
  if (baseline_.empty() || current.size() != baseline_.size()) return results;
  results.reserve(baseline_.size());

  static const int eval_types[] = {
    MEMDBG_VALUE_U32, MEMDBG_VALUE_F32, MEMDBG_VALUE_U16, MEMDBG_VALUE_U8
  };

  for (size_t i = 0U; i < baseline_.size(); ++i) {
    const auto &base = baseline_[i];
    const auto &curr = current[i];
    AutoSearchCandidate best;
    best.address = base.address;
    best.score   = -1.0f;

    for (int et : eval_types) {
      uint32_t flags = 0U;
      double old_val = 0.0, new_val = 0.0;
      float s = score_single(base, curr.bytes, et, flags, old_val, new_val);
      if (s > best.score) {
        best.score        = s;
        best.value_type   = et;
        best.old_value    = old_val;
        best.new_value    = new_val;
        best.matched_flags = flags;
      }
    }

    if (best.score > 0.0f)
      results.push_back(best);
  }

  std::sort(results.begin(), results.end(),
            [](const AutoSearchCandidate &a, const AutoSearchCandidate &b) {
              if (a.score != b.score) return a.score > b.score;
              return a.address < b.address;
            });

  if (results.size() > max_results)
    results.resize(max_results);

  return results;
}

} // namespace memdbg::frontend
