// RFC 8259 subset JSON parser for evidence/replay round-trips.

#include <loki/json_parse.hpp>

#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace loki::json {
namespace {

constexpr int kMaxDepth = 64;

class Parser {
 public:
  explicit Parser(std::string_view text) : text_(text) {}

  Value parse() {
    skip_ws();
    Value v = parse_value(0);
    skip_ws();
    if (pos_ != text_.size()) fail("trailing garbage");
    return v;
  }

 private:
  [[noreturn]] void fail(const std::string& msg) const {
    throw std::runtime_error("json parse error at line " + std::to_string(line_) + ": " + msg);
  }

  void skip_ws() {
    while (pos_ < text_.size()) {
      char c = text_[pos_];
      if (c == '\n') { ++line_; ++pos_; }
      else if (c == ' ' || c == '\t' || c == '\r') { ++pos_; }
      else break;
    }
  }

  char peek() const {
    if (pos_ >= text_.size()) fail("unexpected end of input");
    return text_[pos_];
  }

  void expect(char c) {
    if (pos_ >= text_.size() || text_[pos_] != c) {
      fail(std::string("expected '") + c + "'");
    }
    ++pos_;
  }

  bool literal(std::string_view lit) {
    if (text_.compare(pos_, lit.size(), lit) == 0) {
      pos_ += lit.size();
      return true;
    }
    return false;
  }

  Value parse_value(int depth) {
    if (depth >= kMaxDepth) fail("nesting too deep");
    switch (peek()) {
      case '{': return parse_object(depth);
      case '[': return parse_array(depth);
      case '"': return Value::str(parse_string());
      case 't':
        if (!literal("true")) fail("bad literal");
        return Value::b(true);
      case 'f':
        if (!literal("false")) fail("bad literal");
        return Value::b(false);
      case 'n':
        if (!literal("null")) fail("bad literal");
        return Value::null();
      default: return parse_number();
    }
  }

  Value parse_object(int depth) {
    expect('{');
    Value obj = Value::object();
    skip_ws();
    if (peek() == '}') { ++pos_; return obj; }
    while (true) {
      skip_ws();
      if (peek() != '"') fail("expected object key");
      std::string key(parse_string());
      // Duplicate keys are errors (strict evidence format).
      if (obj.find(key) != nullptr) fail("duplicate key '" + key + "'");
      skip_ws();
      expect(':');
      skip_ws();
      obj.set(std::move(key), parse_value(depth + 1));
      skip_ws();
      char c = peek();
      if (c == ',') { ++pos_; continue; }
      if (c == '}') { ++pos_; return obj; }
      fail("expected ',' or '}'");
    }
  }

  Value parse_array(int depth) {
    expect('[');
    Value arr = Value::array();
    skip_ws();
    if (peek() == ']') { ++pos_; return arr; }
    while (true) {
      skip_ws();
      arr.push(parse_value(depth + 1));
      skip_ws();
      char c = peek();
      if (c == ',') { ++pos_; continue; }
      if (c == ']') { ++pos_; return arr; }
      fail("expected ',' or ']'");
    }
  }

  static void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7F) {
      out += static_cast<char>(cp);
    } else if (cp <= 0x7FF) {
      out += static_cast<char>(0xC0 | (cp >> 6));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp <= 0xFFFF) {
      out += static_cast<char>(0xE0 | (cp >> 12));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
      out += static_cast<char>(0xF0 | (cp >> 18));
      out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    }
  }

  std::uint32_t parse_hex4() {
    if (text_.size() - pos_ < 4) fail("truncated \\u escape");
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
      char c = text_[pos_++];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= static_cast<std::uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f') v |= static_cast<std::uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= static_cast<std::uint32_t>(c - 'A' + 10);
      else fail("bad hex digit in \\u escape");
    }
    return v;
  }

  std::string parse_string() {
    expect('"');
    std::string out;
    while (true) {
      if (pos_ >= text_.size()) fail("unterminated string");
      char c = text_[pos_++];
      if (c == '"') return out;
      if (c == '\n') fail("raw newline in string");
      if (c != '\\') { out += c; continue; }
      if (pos_ >= text_.size()) fail("unterminated escape");
      char e = text_[pos_++];
      switch (e) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
          std::uint32_t cp = parse_hex4();
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            // High surrogate: require a following \uXXXX low surrogate.
            if (pos_ + 1 < text_.size() && text_[pos_] == '\\' && text_[pos_ + 1] == 'u') {
              pos_ += 2;
              std::uint32_t lo = parse_hex4();
              if (lo < 0xDC00 || lo > 0xDFFF) fail("invalid low surrogate");
              cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else {
              fail("lone high surrogate");
            }
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            fail("lone low surrogate");
          }
          append_utf8(out, cp);
          break;
        }
        default: fail("bad escape character");
      }
    }
  }

  Value parse_number() {
    const std::size_t start = pos_;
    bool is_double = false;
    if (peek() == '-') ++pos_;
    // RFC 8259 grammar: no leading zeros in the integer part.
    if (pos_ >= text_.size() || text_[pos_] < '0' || text_[pos_] > '9') {
      pos_ = start;
      fail("bad number");
    }
    if (text_[pos_] == '0' && pos_ + 1 < text_.size() && text_[pos_ + 1] >= '0' &&
        text_[pos_ + 1] <= '9') {
      pos_ = start;
      fail("leading zero in number");
    }
    while (pos_ < text_.size()) {
      char c = text_[pos_];
      if (c >= '0' && c <= '9') { ++pos_; }
      else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
        if (c == '.' || c == 'e' || c == 'E') is_double = true;
        ++pos_;
      } else break;
    }
    std::string_view tok = text_.substr(start, pos_ - start);
    if (tok.empty() || tok == "-") fail("bad number");
    // Reject NaN/Infinity-style literals implicitly: they never lex as numbers.
    if (!is_double) {
      std::int64_t si = 0;
      auto [p, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), si);
      if (ec == std::errc{} && p == tok.data() + tok.size()) return Value::i(si);
      std::uint64_t u = 0;
      auto [p2, ec2] = std::from_chars(tok.data(), tok.data() + tok.size(), u);
      if (ec2 == std::errc{} && p2 == tok.data() + tok.size() && tok[0] != '-') {
        return Value::u(u);  // int64 overflow, non-negative -> UInt
      }
      fail("integer out of range");
    }
    double d = 0.0;
    std::string buf(tok);
    auto [p, ec] = std::from_chars(buf.data(), buf.data() + buf.size(), d);
    if (ec != std::errc{} || p != buf.data() + buf.size() || !std::isfinite(d)) {
      fail("bad number");
    }
    return Value::d(d);
  }

  std::string_view text_;
  std::size_t pos_ = 0;
  int line_ = 1;
};

}  // namespace

Value parse_json(std::string_view text) {
  Parser p(text);
  return p.parse();
}

}  // namespace loki::json
