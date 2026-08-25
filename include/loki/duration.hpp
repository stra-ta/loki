#pragma once

// Duration parsing/formatting. HEADER-ONLY BY CONTRACT.
//
// Accepted syntax: "<number><unit>" with no whitespace. Units: us, ms, s, m, h.
// The number may be fractional ("1.5s"). A unit is REQUIRED; a bare number is
// an error. Result rounds to nearest microsecond; a nonzero input that rounds
// to zero stays at 1us. Throws std::invalid_argument with a clear message.

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace loki {

inline std::uint64_t parse_duration_us(std::string_view s) {
  std::size_t i = 0;
  while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
  const std::size_t num_begin = i;
  bool seen_dot = false, seen_digit = false;
  while (i < s.size() && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.')) {
    if (s[i] == '.') {
      if (seen_dot) throw std::invalid_argument("duration: multiple decimal points in '" + std::string(s) + "'");
      seen_dot = true;
    } else {
      seen_digit = true;
    }
    ++i;
  }
  if (!seen_digit) throw std::invalid_argument("duration: missing number in '" + std::string(s) + "'");
  const double value = std::stod(std::string(s.substr(num_begin, i - num_begin)));
  const std::string_view unit = s.substr(i);
  double scale = 0;
  if (unit == "us") scale = 1.0;
  else if (unit == "ms") scale = 1'000.0;
  else if (unit == "s") scale = 1'000'000.0;
  else if (unit == "m") scale = 60.0 * 1'000'000.0;
  else if (unit == "h") scale = 3600.0 * 1'000'000.0;
  else throw std::invalid_argument("duration: unknown unit '" + std::string(unit) + "' in '" + std::string(s) + "' (expected us|ms|s|m|h)");

  double us = value * scale;
  if (us < 0) throw std::invalid_argument("duration: negative value '" + std::string(s) + "'");
  auto rounded = static_cast<std::uint64_t>(us + 0.5);
  if (rounded == 0 && us > 0) rounded = 1;
  return rounded;
}

inline std::string format_duration_us(std::uint64_t us) {
  char buf[32];
  if (us % 1'000'000 == 0)      std::snprintf(buf, sizeof buf, "%llus", static_cast<unsigned long long>(us / 1'000'000));
  else if (us % 1'000 == 0)     std::snprintf(buf, sizeof buf, "%llums", static_cast<unsigned long long>(us / 1'000));
  else                          std::snprintf(buf, sizeof buf, "%lluus", static_cast<unsigned long long>(us));
  return buf;
}

}  // namespace loki
