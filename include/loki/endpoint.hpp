#pragma once

// Endpoint model + syntax validation. HEADER-ONLY for parsing so the config
// compiler can validate addresses without linking socket code. DNS resolution
// and connect helpers live in src/util/endpoint.cpp (config-and-util package).
//
// Accepted forms: "127.0.0.1:9000", "[::1]:9000", "example.com:80", ":9000".
// ":port" binds loopback (IPv4). Port must be 1..65535.

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace loki {

struct Endpoint {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  bool ipv6 = false;

  std::string to_string() const {
    if (ipv6) return "[" + host + "]:" + std::to_string(port);
    return host + ":" + std::to_string(port);
  }
};

inline Endpoint parse_endpoint(std::string_view s) {
  Endpoint ep;
  if (s.empty()) throw std::invalid_argument("endpoint: empty address");
  if (s[0] == '[') {  // [v6]:port
    const auto close = s.find(']');
    if (close == std::string_view::npos || close + 1 >= s.size() || s[close + 1] != ':') {
      throw std::invalid_argument("endpoint: expected '[host]:port' in '" + std::string(s) + "'");
    }
    ep.host = std::string(s.substr(1, close - 1));
    ep.ipv6 = true;
    const auto port_part = s.substr(close + 2);
    const int port = std::stoi(std::string(port_part));
    if (port < 1 || port > 65535) throw std::invalid_argument("endpoint: port out of range in '" + std::string(s) + "'");
    ep.port = static_cast<std::uint16_t>(port);
    return ep;
  }
  const auto colon = s.rfind(':');
  if (colon == std::string_view::npos) {
    throw std::invalid_argument("endpoint: missing ':port' in '" + std::string(s) + "'");
  }
  std::string_view host = s.substr(0, colon);
  if (host.empty()) host = "127.0.0.1";  // ":9000"
  // Bare IPv6 without brackets would contain multiple colons; reject it.
  if (host.find(':') != std::string_view::npos) {
    throw std::invalid_argument("endpoint: bracket IPv6 addresses required in '" + std::string(s) + "'");
  }
  ep.host = std::string(host);
  const int port = std::stoi(std::string(s.substr(colon + 1)));
  if (port < 1 || port > 65535) throw std::invalid_argument("endpoint: port out of range in '" + std::string(s) + "'");
  ep.port = static_cast<std::uint16_t>(port);
  return ep;
}

}  // namespace loki
