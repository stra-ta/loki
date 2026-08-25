#pragma once

// Minimal JSON value + emitter. HEADER-ONLY BY CONTRACT.
//
// - Objects preserve insertion order. Canonical output duty (sorted keys) sits
//   with the config compiler, which inserts keys in sorted order.
// - Canonical form uses integers only: durations as microseconds, rates as
//   bytes-per-second integers. Doubles are emitted with %.17g for evidence
//   fields but must never appear in canonical scenario JSON.
// - Strings are escaped per RFC 8259; control characters use \\uXXXX.

#include <cstdint>
#include <cstdio>
#include <cmath>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace loki::json {

inline std::string escape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  out += '"';
  for (const unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[7];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  out += '"';
  return out;
}

class Value {
 public:
  enum class Type : std::uint8_t { Null, Bool, Int, UInt, Double, String, Array, Object };

  Value() = default;

  static Value null() { return Value(); }
  static Value object() { Value v; v.t_ = Type::Object; return v; }
  static Value array() { Value v; v.t_ = Type::Array; return v; }
  static Value b(bool x) { Value v; v.t_ = Type::Bool; v.b_ = x; return v; }
  static Value i(std::int64_t x) { Value v; v.t_ = Type::Int; v.i_ = x; return v; }
  static Value u(std::uint64_t x) { Value v; v.t_ = Type::UInt; v.u_ = x; return v; }
  static Value d(double x) { Value v; v.t_ = Type::Double; v.d_ = x; return v; }
  static Value str(std::string_view s) { Value v; v.t_ = Type::String; v.s_ = s; return v; }

  Type type() const { return t_; }

  // Object members. Insertion order preserved.
  Value& set(const std::string& key, Value v) {
    obj_.emplace_back(key, std::move(v));
    return *this;
  }

  void push(Value v) { arr_.push_back(std::move(v)); }

  const Value* find(std::string_view key) const {
    for (const auto& [k, v] : obj_) {
      if (k == key) return &v;
    }
    return nullptr;
  }

  const std::vector<std::pair<std::string, Value>>& members() const { return obj_; }
  const std::vector<Value>& items() const { return arr_; }

  bool is_null() const { return t_ == Type::Null; }
  bool as_bool() const { return b_; }
  std::int64_t as_int() const {
    if (t_ == Type::UInt) return static_cast<std::int64_t>(u_);
    return i_;
  }
  std::uint64_t as_uint() const {
    if (t_ == Type::Int) return static_cast<std::uint64_t>(i_);
    return u_;
  }
  double as_double() const {
    if (t_ == Type::Int) return static_cast<double>(i_);
    if (t_ == Type::UInt) return static_cast<double>(u_);
    return d_;
  }
  const std::string& as_str() const { return s_; }

  std::string dump() const {
    std::string out;
    write(out);
    return out;
  }

 private:
  void write(std::string& out) const {
    switch (t_) {
      case Type::Null: out += "null"; break;
      case Type::Bool: out += b_ ? "true" : "false"; break;
      case Type::Int: {
        char buf[24];
        std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(i_));
        out += buf;
        break;
      }
      case Type::UInt: {
        char buf[24];
        std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(u_));
        out += buf;
        break;
      }
      case Type::Double: {
        if (!std::isfinite(d_)) { out += "null"; break; }
        char buf[40];
        std::snprintf(buf, sizeof buf, "%.17g", d_);
        out += buf;
        break;
      }
      case Type::String: out += escape(s_); break;
      case Type::Array: {
        out += '[';
        bool first = true;
        for (const auto& v : arr_) {
          if (!first) out += ',';
          first = false;
          v.write(out);
        }
        out += ']';
        break;
      }
      case Type::Object: {
        out += '{';
        bool first = true;
        for (const auto& [k, v] : obj_) {
          if (!first) out += ',';
          first = false;
          out += escape(k);
          out += ':';
          v.write(out);
        }
        out += '}';
        break;
      }
    }
  }

  Type t_ = Type::Null;
  bool b_ = false;
  std::int64_t i_ = 0;
  std::uint64_t u_ = 0;
  double d_ = 0.0;
  std::string s_;
  std::vector<std::pair<std::string, Value>> obj_;
  std::vector<Value> arr_;
};

}  // namespace loki::json
