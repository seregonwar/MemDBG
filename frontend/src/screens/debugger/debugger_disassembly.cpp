#include "debugger_disassembly.hpp"

#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>

namespace memdbg::frontend::debugger {
namespace {

/* ---- x86-64 disassembler (compact, focused on common instructions) ---- */

static const char *kRegNames64[] = {
  "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
  "r8","r9","r10","r11","r12","r13","r14","r15"
};
static const char *kRegNames32[] = {
  "eax","ecx","edx","ebx","esp","ebp","esi","edi",
  "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
};
static const char *kRegNames16[] = {
  "ax","cx","dx","bx","sp","bp","si","di",
  "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
};
static const char *kRegNames8[] = {
  "al","cl","dl","bl","ah","ch","dh","bh",
  "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
};

enum class OpSize { k8, k16, k32, k64 };

struct DecodedOp {
  enum Kind { kReg, kMem, kImm, kNone } kind = kNone;
  int reg = 0;       /* register index 0-15 */
  int base_reg = 0;
  int index_reg = -1;
  int scale = 1;
  int64_t disp = 0;
  uint64_t imm = 0;
  OpSize size = OpSize::k64;
};

struct DecodedInsn {
  const char *mnemonic = "???";
  DecodedOp dst, src;
  uint8_t length = 1;
  bool is_jump = false;
  bool is_call = false;
  bool is_ret = false;
};

static uint8_t modrm_mod(uint8_t b) { return (b >> 6) & 3; }
static uint8_t modrm_reg(uint8_t b) { return (b >> 3) & 7; }
static uint8_t modrm_rm(uint8_t b) { return b & 7; }

static int rex_b(uint8_t r) { return (r & 1) ? 8 : 0; }
static int rex_x(uint8_t r) { return (r & 2) ? 8 : 0; }
static int rex_r(uint8_t r) { return (r & 4) ? 8 : 0; }
static int rex_w(uint8_t r) { return (r & 8); }

static size_t decode_modrm_sib(const uint8_t *bytes, size_t pos, size_t len,
                                uint8_t rex, OpSize size, DecodedOp &op) {
  if (pos >= len) return pos;
  uint8_t modrm = bytes[pos++];
  uint8_t mod = modrm_mod(modrm);
  uint8_t rm  = modrm_rm(modrm);
  op.reg = modrm_reg(modrm) + rex_r(rex);

  if (mod == 3) {
    /* register direct */
    op.kind = DecodedOp::kReg;
    op.reg = rm + rex_b(rex);
    return pos;
  }

  /* memory operand */
  op.kind = DecodedOp::kMem;
  op.size = size;

  bool has_sib = (rm == 4);
  if (rm == 5 && mod == 0) {
    /* RIP-relative: disp32 follows */
    if (pos + 4 > len) return pos;
    memcpy(&op.disp, bytes + pos, 4);
    op.disp = (int32_t)op.disp;
    pos += 4;
    return pos;
  }

  if (has_sib) {
    if (pos >= len) return pos;
    uint8_t sib = bytes[pos++];
    op.scale = 1 << ((sib >> 6) & 3);
    op.index_reg = (int)((sib >> 3) & 7) + rex_x(rex);
    op.base_reg = (int)(sib & 7) + rex_b(rex);
    if (op.index_reg == 4 && ((sib >> 6) & 3) == 0) op.index_reg = -1;
    if (op.base_reg == 5 && mod == 0) {
      if (pos + 4 > len) return pos;
      memcpy(&op.disp, bytes + pos, 4);
      op.disp = (int32_t)op.disp;
      pos += 4;
      op.base_reg = -1;
      return pos;
    }
  } else {
    op.base_reg = (int)rm + rex_b(rex);
    op.index_reg = -1;
  }

  if (mod == 1) { if (pos < len) { op.disp = (int8_t)bytes[pos++]; } }
  else if (mod == 2) { if (pos + 4 <= len) { memcpy(&op.disp, bytes + pos, 4); op.disp = (int32_t)op.disp; pos += 4; } }
  return pos;
}

static void format_operand(const DecodedOp &op, std::string &out) {
  char buf[64];
  switch (op.kind) {
  case DecodedOp::kReg:
    switch (op.size) {
    case OpSize::k8:  snprintf(buf, sizeof(buf), "%s", kRegNames8[op.reg & 15]); break;
    case OpSize::k16: snprintf(buf, sizeof(buf), "%s", kRegNames16[op.reg & 15]); break;
    case OpSize::k32: snprintf(buf, sizeof(buf), "%s", kRegNames32[op.reg & 15]); break;
    default:          snprintf(buf, sizeof(buf), "%s", kRegNames64[op.reg & 15]); break;
    }
    out += buf;
    break;
  case DecodedOp::kMem: {
    bool need_plus = false;
    out += "[";
    if (op.base_reg >= 0) { out += kRegNames64[op.base_reg & 15]; need_plus = true; }
    if (op.index_reg >= 0) {
      if (need_plus) out += "+";
      out += kRegNames64[op.index_reg & 15];
      if (op.scale > 1) { snprintf(buf, sizeof(buf), "*%d", op.scale); out += buf; }
      need_plus = true;
    }
    if (op.disp != 0 || (!need_plus)) {
      if (need_plus && op.disp >= 0) out += "+";
      snprintf(buf, sizeof(buf), "0x%" PRIX64, (uint64_t)op.disp);
      out += buf;
    }
    out += "]";
    break;
  }
  case DecodedOp::kImm:
    snprintf(buf, sizeof(buf), "0x%" PRIX64, op.imm);
    out += buf;
    break;
  default: break;
  }
}

enum class InsnKind {
  /* opcode patterns */
  kRet, kCall, kJmp, kJcc, kSyscall, kInt3, kNop,
  kPush, kPop,
  kMovRR, kMovRM, kMovMR, kMovRI,
  kAdd, kSub, kCmp, kTest, kAnd, kOr, kXor,
  kLea, kXchg,
  kInc, kDec, kNot, kNeg,
  kShl, kShr, kSar,
  kMovsx, kMovzx,
  kUnknown
};

struct OpcodeEntry {
  uint16_t mask;   /* which bytes must match */
  uint16_t pattern; /* expected byte values */
  InsnKind kind;
  const char *mnemonic;
  OpSize size;
  uint8_t flags; /* bit0=swap operands, bit1=dst is rm, bit2=src is rm */
};

static const OpcodeEntry kOpcodeTable[] = {
  /* 1-byte opcodes */
  {0xFFFF, 0x00C3, InsnKind::kRet,     "ret",     OpSize::k64, 0},
  {0xFFFF, 0x00E8, InsnKind::kCall,    "call",    OpSize::k64, 0},
  {0xFFFF, 0x00E9, InsnKind::kJmp,     "jmp",     OpSize::k64, 0},
  {0xFFFF, 0x00EB, InsnKind::kJmp,     "jmp",     OpSize::k64, 0},
  {0xFFFF, 0x0005, InsnKind::kSyscall, "syscall", OpSize::k64, 0},
  {0xFFFF, 0x00CC, InsnKind::kInt3,    "int3",    OpSize::k64, 0},
  {0xFFFF, 0x0090, InsnKind::kNop,     "nop",     OpSize::k64, 0},
  {0xFF00, 0x7000, InsnKind::kJcc,     "j",       OpSize::k64, 0}, /* 70-7F */
  {0xFFF8, 0x0050, InsnKind::kPush,    "push",    OpSize::k64, 0}, /* 50-57 push */
  {0xFFF8, 0x0058, InsnKind::kPop,     "pop",     OpSize::k64, 0}, /* 58-5F pop */
  /* mov variants */
  {0xFFFE, 0x008A, InsnKind::kMovRR,   "mov",     OpSize::k8,  0},
  {0xFFFE, 0x008B, InsnKind::kMovRR,   "mov",     OpSize::k64, 0},
  {0xFFF0, 0xB000, InsnKind::kMovRI,   "mov",     OpSize::k8,  0}, /* B0-B7 */
  {0xFFF0, 0xB800, InsnKind::kMovRI,   "mov",     OpSize::k64, 0}, /* B8-BF */
  {0xFFFE, 0x00C6, InsnKind::kMovRM,   "mov",     OpSize::k8,  2}, /* C6 /0 ib */
  {0xFFFE, 0x00C7, InsnKind::kMovRM,   "mov",     OpSize::k64, 2}, /* C7 /0 id */
  /* ALU */
  {0xFFFE, 0x0001, InsnKind::kAdd,     "add",     OpSize::k64, 0},
  {0xFFFE, 0x0029, InsnKind::kSub,     "sub",     OpSize::k64, 0},
  {0xFFFE, 0x0039, InsnKind::kCmp,     "cmp",     OpSize::k64, 0},
  {0xFFFE, 0x0085, InsnKind::kTest,    "test",    OpSize::k64, 0},
  {0xFFFE, 0x0021, InsnKind::kAnd,     "and",     OpSize::k64, 0},
  {0xFFFE, 0x0009, InsnKind::kOr,      "or",      OpSize::k64, 0},
  {0xFFFE, 0x0031, InsnKind::kXor,     "xor",     OpSize::k64, 0},
  /* 0x83 group 1 (add/sub/cmp/and/or/xor with imm8) */
  {0xFFFF, 0x0083, InsnKind::kAdd,     "add",     OpSize::k64, 2}, /* /0 */
  {0xFFFF, 0x008D, InsnKind::kLea,     "lea",     OpSize::k64, 0},
  {0xFFFF, 0x0087, InsnKind::kXchg,    "xchg",    OpSize::k64, 0},
  /* 0F 2-byte opcodes */
  {0xFFFF, 0x0F84, InsnKind::kJcc,     "je",      OpSize::k64, 0},
  {0xFFFF, 0x0F85, InsnKind::kJcc,     "jne",     OpSize::k64, 0},
  {0xFFF0, 0x0F80, InsnKind::kJcc,     "j",       OpSize::k64, 0}, /* 0F80-0F8F */
  {0xFFFF, 0x0FB6, InsnKind::kMovzx,   "movzx",   OpSize::k64, 0},
  {0xFFFF, 0x0FBE, InsnKind::kMovsx,   "movsx",   OpSize::k64, 0},
  {0, 0, InsnKind::kUnknown, "???", OpSize::k64, 0}
};

static const char *kJccNames[16] = {
  "jo","jno","jb","jnb","jz","jnz","jbe","ja",
  "js","jns","jp","jnp","jl","jge","jle","jg"
};

static DecodedInsn decode_one(const uint8_t *bytes, size_t len) {
  DecodedInsn insn;
  if (len < 1) return insn;

  size_t pos = 0;
  uint8_t rex = 0;
  bool has_66 = false;

  /* prefixes */
  while (pos < len) {
    uint8_t b = bytes[pos];
    if (b >= 0x40 && b <= 0x4F) { rex = b; pos++; }
    else if (b == 0x66) { has_66 = true; pos++; }
    else if (b == 0x67) { pos++; }  /* addr-size override, ignore */
    else break;
  }
  if (pos >= len) { insn.length = (uint8_t)pos; return insn; }

  OpSize def_size = OpSize::k64;
  if (rex_w(rex)) def_size = OpSize::k64;
  else if (has_66) def_size = OpSize::k16;

  /* build 16-bit opcode key: if byte 0 is 0x0F, use 2-byte key */
  uint16_t opkey = bytes[pos];
  size_t op_pos = pos;
  if (bytes[pos] == 0x0F && pos + 1 < len) {
    opkey = (uint16_t)((0x0F00) | bytes[pos + 1]);
    pos++;
  }
  pos++;

  const OpcodeEntry *match = nullptr;
  for (const OpcodeEntry *e = kOpcodeTable; e->mask != 0; ++e) {
    if ((opkey & e->mask) == e->pattern) { match = e; break; }
  }
  if (match == nullptr) {
    insn.length = (uint8_t)pos;
    return insn;
  }

  insn.mnemonic = match->mnemonic;
  OpSize sz = match->size != OpSize::k64 ? match->size : def_size;

  switch (match->kind) {
  case InsnKind::kRet:
  case InsnKind::kNop:
    insn.is_ret = (match->kind == InsnKind::kRet);
    insn.length = (uint8_t)pos;
    return insn;

  case InsnKind::kInt3:
    insn.length = (uint8_t)pos;
    insn.is_ret = true;
    return insn;

  case InsnKind::kSyscall:
    insn.length = (uint8_t)pos;
    return insn;

  case InsnKind::kCall:
  case InsnKind::kJmp:
  case InsnKind::kJcc: {
    insn.is_call = (match->kind == InsnKind::kCall);
    insn.is_jump = (match->kind == InsnKind::kJmp || match->kind == InsnKind::kJcc);
    uint8_t op = bytes[op_pos];
    if (op == 0xEB && pos < len) {
      int8_t rel8 = (int8_t)bytes[pos];
      insn.dst.kind = DecodedOp::kImm;
      insn.dst.imm = (uint64_t)((int64_t)rel8);
      insn.length = (uint8_t)(pos + 1);
    } else if (pos + 4 <= len) {
      int32_t rel32;
      memcpy(&rel32, bytes + pos, 4);
      insn.dst.kind = DecodedOp::kImm;
      insn.dst.imm = (uint64_t)((int64_t)rel32);
      insn.length = (uint8_t)(pos + 4);
    } else {
      insn.length = (uint8_t)pos;
    }
    if (match->kind == InsnKind::kJcc) {
      uint8_t op_low = bytes[op_pos] & 0x0F;
      if (match->pattern == 0x0F80) {
        insn.mnemonic = kJccNames[op_low];
      } else if (match->pattern >= 0x7000 && match->pattern <= 0x7F00) {
        insn.mnemonic = kJccNames[op_low];
      }
    }
    return insn;
  }

  case InsnKind::kPush:
  case InsnKind::kPop: {
    uint8_t reg = (bytes[op_pos] & 7) + rex_b(rex);
    insn.dst.kind = DecodedOp::kReg;
    insn.dst.reg = (int)reg;
    insn.dst.size = OpSize::k64;
    insn.length = (uint8_t)pos;
    return insn;
  }

  case InsnKind::kMovRI: {
    uint8_t reg = (bytes[op_pos] & 7) + rex_b(rex);
    insn.dst.kind = DecodedOp::kReg;
    insn.dst.reg = (int)reg;
    insn.dst.size = (match->pattern >= 0xB800) ? OpSize::k64 : OpSize::k8;
    insn.src.kind = DecodedOp::kImm;
    int imm_len = (match->pattern >= 0xB800) ? 8 : 1;
    if (pos + imm_len <= len) {
      memcpy(&insn.src.imm, bytes + pos, imm_len);
      insn.length = (uint8_t)(pos + imm_len);
    } else {
      insn.length = (uint8_t)pos;
    }
    return insn;
  }

  case InsnKind::kMovRM:  /* mov [rm], imm */
  case InsnKind::kAdd:
  case InsnKind::kSub:
  case InsnKind::kCmp:
  case InsnKind::kTest:
  case InsnKind::kAnd:
  case InsnKind::kOr:
  case InsnKind::kXor:
  case InsnKind::kLea:
  case InsnKind::kXchg:
  case InsnKind::kMovRR:
  case InsnKind::kMovzx:
  case InsnKind::kMovsx: {
    /* Save ModR/M reg field before decode_modrm_sib advances pos */
    uint8_t saved_reg = (pos < len) ? modrm_reg(bytes[pos]) : 0;
    pos = decode_modrm_sib(bytes, pos, len, rex, sz, insn.dst);
    /* for most ALU, dst is reg from modrm.reg, src is modrm.rm */
    if (match->kind == InsnKind::kMovRM) {
      /* mov [rm], imm: dst = memory, src = imm */
      insn.src.kind = DecodedOp::kImm;
      insn.src.size = sz;
      int ilen = (sz == OpSize::k8) ? 1 : (sz == OpSize::k64 ? 4 : (sz == OpSize::k32 ? 4 : 2));
      uint32_t raw = 0;
      if (pos + ilen <= len) { memcpy(&raw, bytes + pos, ilen); pos += ilen; insn.src.imm = raw; }
      /* dst is the memory operand decoded by modrm; reg field is rm */
      insn.dst.kind = DecodedOp::kMem;
      insn.dst.size = sz;
    } else if (match->kind == InsnKind::kLea) {
      insn.src.kind = DecodedOp::kMem;
      insn.src = insn.dst;  /* lea dst, [mem] */
      insn.dst.kind = DecodedOp::kReg;
      insn.dst.reg = modrm_reg(bytes[pos - ((bytes[op_pos] == 0x8D || bytes[op_pos] == 0x48) ? 1 : 0)]) + rex_r(rex);
    } else if (match->kind == InsnKind::kMovzx || match->kind == InsnKind::kMovsx) {
      insn.src = insn.dst;
      insn.dst.kind = DecodedOp::kReg;
      insn.dst.reg = modrm_reg(bytes[pos - 1]) + rex_r(rex);
      insn.dst.size = OpSize::k64;
    } else {
      /* standard: dst = reg, src = rm */
      DecodedOp src_op;
      /* dst was populated by decode_modrm_sib as rm; swap: dst=reg */
      insn.dst.reg = (saved_reg & 7) + rex_r(rex);
      insn.dst.kind = DecodedOp::kReg;
      insn.dst.size = sz;
      /* 0x83 group 1: dispatch mnemonic from ModR/M reg field */
      if (opkey == 0x0083) {
        static const char *grp1[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
        int n = saved_reg & 7;
        insn.mnemonic = grp1[n];
      }
      /* src is the memory/register from modrm */
      size_t pos2 = op_pos + 1;
      src_op = {};
      decode_modrm_sib(bytes, pos2, len, rex, sz, src_op);
      insn.src = src_op;
      if (pos2 > pos) pos = pos2;
    }
    insn.length = (uint8_t)pos;
    return insn;
  }

  case InsnKind::kInc:
  case InsnKind::kDec: {
    uint8_t reg = (bytes[op_pos] & 7) + rex_b(rex);
    insn.dst.kind = DecodedOp::kReg;
    insn.dst.reg = (int)reg;
    insn.dst.size = OpSize::k64;
    insn.length = (uint8_t)pos;
    return insn;
  }

  default:
    insn.length = (uint8_t)pos;
    return insn;
  }
}


} // namespace

std::vector<DisassemblyLine> decode_x86_64_window(const std::vector<uint8_t> &code,
                                                  uint64_t base_address,
                                                  bool cfg_view,
                                                  size_t max_lines) {
  std::vector<DisassemblyLine> lines;
  size_t pos = 0;
  while (pos < code.size() && lines.size() < max_lines) {
    DecodedInsn insn = decode_one(code.data() + pos, code.size() - pos);
    if (insn.length == 0) {
      insn.length = 1;
    }

    char bytes[64];
    bytes[0] = '\0';
    size_t used = 0;
    const size_t count = insn.length < 8 ? insn.length : 8;
    for (size_t i = 0; i < count && used + 4 < sizeof(bytes); ++i) {
      used += std::snprintf(bytes + used, sizeof(bytes) - used, "%02X ", code[pos + i]);
    }
    if (insn.length > count && used + 4 < sizeof(bytes)) {
      std::snprintf(bytes + used, sizeof(bytes) - used, "...");
    }

    std::string mnemonic = insn.mnemonic;
    if (insn.dst.kind != DecodedOp::kNone || insn.src.kind != DecodedOp::kNone) {
      mnemonic += " ";
      format_operand(insn.dst, mnemonic);
      if (insn.src.kind != DecodedOp::kNone) {
        mnemonic += ", ";
        format_operand(insn.src, mnemonic);
      }
    }

    lines.push_back({base_address + pos, bytes, mnemonic});
    pos += insn.length;
    if (insn.is_ret && pos < code.size()) {
      break;
    }
  }

  if (cfg_view && !lines.empty()) {
    std::unordered_set<uint64_t> targets;
    size_t pos2 = 0;
    for (size_t k = 0; k < lines.size() && pos2 < code.size(); ++k) {
      DecodedInsn insn2 = decode_one(code.data() + pos2, code.size() - pos2);
      if (insn2.length == 0) {
        insn2.length = 1;
      }
      const uint64_t line_addr = base_address + pos2;

      if (insn2.is_jump || insn2.is_call) {
        if (insn2.dst.kind == DecodedOp::kImm) {
          const uint64_t target = line_addr + insn2.length + static_cast<int64_t>(insn2.dst.imm);
          targets.insert(target);
        }
        targets.insert(line_addr);
      }
      if (insn2.is_ret) {
        targets.insert(line_addr);
      }
      pos2 += insn2.length;
    }

    std::vector<DisassemblyLine> filtered;
    for (auto &line : lines) {
      if (targets.count(line.address) != 0) {
        filtered.push_back(std::move(line));
      }
    }
    lines = std::move(filtered);
  }

  return lines;
}

} // namespace memdbg::frontend::debugger
