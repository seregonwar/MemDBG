/*
 * MemDBG - Formal batchcode parser implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "batchcode_parser.hpp"

#include "app_state.hpp"

#include <array>
#include <cctype>
#include <cstring>

namespace memdbg::frontend {

namespace {

enum class TokenType : uint8_t {
  End,
  Offset,
  Value,
  Size,
  Colon,
  Equals,
  Comma,
  Semicolon,
  Number,
  HexBytes,
  Unknown,
};

struct Token {
  TokenType type = TokenType::End;
  size_t pos = 0;             /* position in source for error messages */
  uint64_t number = 0;        /* valid if type == Number */
  std::vector<uint8_t> bytes{}; /* valid if type == HexBytes */
  std::string text{};           /* valid if type == Unknown */
};

class Lexer {
public:
  explicit Lexer(const std::string &input) : input_(input), pos_(0) {}

  Token next() {
    skip_ignored();
    if (pos_ >= input_.size()) return {TokenType::End, pos_, 0, {}, {}};

    const size_t start = pos_;
    const char c = input_[pos_];

    if (c == ':') { ++pos_; return {TokenType::Colon, start, 0, {}, {}}; }
    if (c == '=') { ++pos_; return {TokenType::Equals, start, 0, {}, {}}; }
    if (c == ',') { ++pos_; return {TokenType::Comma, start, 0, {}, {}}; }
    if (c == ';') { ++pos_; return {TokenType::Semicolon, start, 0, {}, {}}; }

    if (c == '0' && pos_ + 1 < input_.size() &&
        (input_[pos_ + 1] == 'x' || input_[pos_ + 1] == 'X')) {
      return read_number();
    }

    /* Try to read a byte stream first; if it looks like a lone decimal digit
     * without a hex pair, fall back to a number token. */
    if (std::isxdigit(static_cast<unsigned char>(c)) || c == '?') {
      Token hex = read_hex_bytes();
      if (!hex.bytes.empty()) return hex;
      if (std::isdigit(static_cast<unsigned char>(c))) return read_number();
    }

    if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
      std::string id = read_identifier();
      std::string lower;
      lower.reserve(id.size());
      for (char ch : id) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
      if (lower == "offset") return {TokenType::Offset, start, 0, {}, {}};
      if (lower == "value")  return {TokenType::Value, start, 0, {}, {}};
      if (lower == "size")   return {TokenType::Size, start, 0, {}, {}};
      return {TokenType::Unknown, start, 0, {}, id};
    }


    /* Any other character is treated as an unknown token and skipped. */
    ++pos_;
    return {TokenType::Unknown, start, 0, {}, std::string(1, c)};
  }

  size_t pos() const { return pos_; }

private:
  std::string input_;
  size_t pos_;

  bool is_hex(char ch) const {
    return std::isxdigit(static_cast<unsigned char>(ch)) != 0;
  }

  void skip_ignored() {
    while (pos_ < input_.size()) {
      char c = input_[pos_];
      if (std::isspace(static_cast<unsigned char>(c))) {
        ++pos_;
        continue;
      }
      if (c == '/' && pos_ + 1 < input_.size() && input_[pos_ + 1] == '/') {
        pos_ += 2;
        while (pos_ < input_.size() && input_[pos_] != '\n') ++pos_;
        continue;
      }
      if (c == '#') {
        ++pos_;
        while (pos_ < input_.size() && input_[pos_] != '\n') ++pos_;
        continue;
      }
      break;
    }
  }

  std::string read_identifier() {
    size_t start = pos_;
    while (pos_ < input_.size() &&
           (std::isalnum(static_cast<unsigned char>(input_[pos_])) ||
            input_[pos_] == '_')) {
      ++pos_;
    }
    return input_.substr(start, pos_ - start);
  }

  Token read_number() {
    size_t start = pos_;
    int base = 10;
    if (input_[pos_] == '0' && pos_ + 1 < input_.size() &&
        (input_[pos_ + 1] == 'x' || input_[pos_ + 1] == 'X')) {
      base = 16;
      pos_ += 2;
    }
    size_t digits_start = pos_;
    while (pos_ < input_.size() &&
           ((base == 16 && is_hex(input_[pos_])) ||
            (base == 10 && std::isdigit(static_cast<unsigned char>(input_[pos_]))))) {
      ++pos_;
    }
    if (pos_ == digits_start) {
      Token t{TokenType::Unknown, start, 0, {}, input_.substr(start, 2)};
      return t;
    }
    const std::string digits = input_.substr(digits_start, pos_ - digits_start);
    char *end = nullptr;
    errno = 0;
    unsigned long long value = std::strtoull(digits.c_str(), &end, base);
    (void)end; /* digits are validated */
    return {TokenType::Number, start, static_cast<uint64_t>(value), {}, {}};
  }

  Token read_hex_bytes() {
    size_t start = pos_;
    std::vector<uint8_t> bytes;
    while (pos_ < input_.size()) {
      skip_inline_whitespace();
      if (pos_ >= input_.size()) break;
      char c = input_[pos_];
      if (c == '?' && pos_ + 1 < input_.size() && input_[pos_ + 1] == '?') {
        bytes.push_back(0x00); /* wildcard -> placeholder zero byte */
        pos_ += 2;
        continue;
      }
      if (is_hex(c) && pos_ + 1 < input_.size() && is_hex(input_[pos_ + 1])) {
        std::array<char, 3> pair = {c, input_[pos_ + 1], '\0'};
        char *end = nullptr;
        unsigned long v = std::strtoul(pair.data(), &end, 16);
        (void)v;
        bytes.push_back(static_cast<uint8_t>(v));
        pos_ += 2;
        continue;
      }
      if (c == '?' || is_hex(c)) {
        /* Odd / incomplete hex digit: stop parsing the byte stream. */
        break;
      }
      break;
    }
    return {TokenType::HexBytes, start, 0, std::move(bytes), {}};
  }

  void skip_inline_whitespace() {
    while (pos_ < input_.size() &&
           (input_[pos_] == ' ' || input_[pos_] == '\t' || input_[pos_] == '\r')) {
      ++pos_;
    }
  }
};

} // namespace

int parse_batchcode(const std::string &text, std::vector<BatchcodeEntry> &out,
                    std::string &error) {
  out.clear();
  error.clear();

  Lexer lexer(text);
  int imported = 0;
  bool expecting_record = true;

  while (true) {
    Token t = lexer.next();
    if (t.type == TokenType::End) break;

    /* Field separators (also valid between records) */
    if (t.type == TokenType::Semicolon || t.type == TokenType::Comma) {
      continue;
    }

    if (!expecting_record && t.type != TokenType::End) {
      /* Another token without separator: treat as start of a new record if
       * it looks like an offset. */
      if (t.type != TokenType::Offset && t.type != TokenType::Number) {
        continue;
      }
    }

    uint64_t offset = 0;

    /* Offset: either "offset:" number or bare number */
    if (t.type == TokenType::Offset) {
      Token sep = lexer.next();
      if (sep.type != TokenType::Colon && sep.type != TokenType::Equals &&
          sep.type != TokenType::Number && sep.type != TokenType::HexBytes) {
        error = "expected ':' or '=' after 'offset' at position " +
                std::to_string(sep.pos);
        return -1;
      }
      /* If the separator was actually the value (e.g. "offset 123"), we
       * already consumed it.  Put it back by re-lexing from that position. */
      if (sep.type == TokenType::Number) {
        offset = sep.number;
      } else if (sep.type == TokenType::HexBytes) {
        error = "offset must be a number at position " + std::to_string(sep.pos);
        return -1;
      } else {
        Token num = lexer.next();
        if (num.type != TokenType::Number) {
          error = "expected offset number at position " + std::to_string(num.pos);
          return -1;
        }
        offset = num.number;
      }
    } else if (t.type == TokenType::Number) {
      offset = t.number;
    } else {
      continue;
    }

    /* Optional separator between offset and value */
    Token next = lexer.next();
    if (next.type == TokenType::Colon || next.type == TokenType::Equals ||
        next.type == TokenType::Comma || next.type == TokenType::Semicolon) {
      next = lexer.next();
    }

    std::vector<uint8_t> bytes;

    if (next.type == TokenType::Value) {
      Token sep = lexer.next();
      if (sep.type == TokenType::Colon || sep.type == TokenType::Equals) {
        Token val = lexer.next();
        if (val.type != TokenType::HexBytes && val.type != TokenType::Number) {
          error = "expected hex byte value at position " + std::to_string(val.pos);
          return -1;
        }
        bytes = std::move(val.bytes);
        if (bytes.empty() && val.type == TokenType::Number) {
          /* A plain number like 0x90909090 as value: convert to bytes. */
          uint64_t v = val.number;
          for (int i = 56; i >= 0; i -= 8) {
            uint8_t b = static_cast<uint8_t>((v >> i) & 0xFFU);
            if (!bytes.empty() || b != 0) bytes.push_back(b);
          }
          if (bytes.empty()) bytes.push_back(0);
        }
      } else if (sep.type == TokenType::HexBytes || sep.type == TokenType::Number) {
        bytes = std::move(sep.bytes);
        if (bytes.empty() && sep.type == TokenType::Number) {
          uint64_t v = sep.number;
          for (int i = 56; i >= 0; i -= 8) {
            uint8_t b = static_cast<uint8_t>((v >> i) & 0xFFU);
            if (!bytes.empty() || b != 0) bytes.push_back(b);
          }
          if (bytes.empty()) bytes.push_back(0);
        }
      } else {
        error = "expected value after 'value' at position " +
                std::to_string(sep.pos);
        return -1;
      }
    } else if (next.type == TokenType::HexBytes) {
      bytes = std::move(next.bytes);
    } else if (next.type == TokenType::Number) {
      uint64_t v = next.number;
      for (int i = 56; i >= 0; i -= 8) {
        uint8_t b = static_cast<uint8_t>((v >> i) & 0xFFU);
        if (!bytes.empty() || b != 0) bytes.push_back(b);
      }
      if (bytes.empty()) bytes.push_back(0);
    } else {
      error = "expected value at position " + std::to_string(next.pos);
      return -1;
    }

    if (bytes.empty()) {
      error = "empty value at position " + std::to_string(next.pos);
      return -1;
    }

    /* Optional size, possibly preceded by field separators */
    uint64_t size = 0;
    Token peek = lexer.next();
    while (peek.type == TokenType::Semicolon || peek.type == TokenType::Comma) {
      peek = lexer.next();
    }
    if (peek.type == TokenType::Size) {
      Token sep = lexer.next();
      if (sep.type != TokenType::Colon && sep.type != TokenType::Equals) {
        error = "expected ':' or '=' after 'size' at position " +
                std::to_string(sep.pos);
        return -1;
      }
      Token num = lexer.next();
      if (num.type != TokenType::Number) {
        error = "expected size number at position " + std::to_string(num.pos);
        return -1;
      }
      size = num.number;
    } else {
      /* Put the token back if it wasn't a size specifier.  We do this by
       * creating a new lexer that starts at the token position.  This is
       * safe because the lexer is deterministic and we only move forward. */
      if (peek.type != TokenType::End) {
        lexer = Lexer(text.substr(peek.pos));
      }
    }

    BatchcodeEntry entry;
    entry.offset = offset;
    entry.bytes = std::move(bytes);
    entry.size = size;
    if (size > 0 && entry.bytes.size() > size) {
      entry.bytes.resize(static_cast<size_t>(size));
    } else if (size > 0 && entry.bytes.size() < size) {
      entry.bytes.resize(static_cast<size_t>(size), 0);
    }
    out.push_back(std::move(entry));
    imported++;
    expecting_record = false;
  }

  return imported;
}

} // namespace memdbg::frontend
