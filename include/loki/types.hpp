#pragma once

// Core shared types: identifiers, directions, poller tokens, lifecycle reasons.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace loki {

using ConnId = std::uint64_t;   // connection ordinal, assigned at accept, starts at 1
using SeqNo = std::uint64_t;    // scheduler sequence number
using TimeUs = std::int64_t;    // steady-clock microseconds relative to process start
using WallUs = std::int64_t;    // unix epoch microseconds, evidence only

enum class Dir : std::uint8_t { AtoB = 0, BtoA = 1 };

// Identifies one unidirectional stream of a connection.
struct StreamKey {
  ConnId conn = 0;
  Dir dir = Dir::AtoB;
};

inline bool operator==(const StreamKey& a, const StreamKey& b) {
  return a.conn == b.conn && a.dir == b.dir;
}

inline const char* dir_name(Dir d) { return d == Dir::AtoB ? "a_to_b" : "b_to_a"; }

// Accepts canonical names (a_to_b, b_to_a) and YAML aliases
// (client_to_server/c2s -> AtoB, server_to_client/s2c -> BtoA).
inline std::optional<Dir> dir_from_string(std::string_view s) {
  if (s == "a_to_b" || s == "client_to_server" || s == "client" || s == "c2s") return Dir::AtoB;
  if (s == "b_to_a" || s == "server_to_client" || s == "server" || s == "s2c") return Dir::BtoA;
  return std::nullopt;
}

// Which socket leg of a proxied connection. Down faces the client, Up faces the server.
enum class LegSide : std::uint8_t { Down = 0, Up = 1 };

enum class FdKind : std::uint8_t { Listener = 0, Downstream = 1, Upstream = 2, Control = 3 };

// Opaque token registered with the poller. Encoded to a single uint64.
struct Token {
  FdKind kind = FdKind::Listener;
  ConnId conn = 0;

  std::uint64_t raw() const {
    return (static_cast<std::uint64_t>(kind) << 56) | (conn & ((1ull << 56) - 1));
  }
  static Token from_raw(std::uint64_t v) {
    return Token{static_cast<FdKind>(v >> 56), v & ((1ull << 56) - 1)};
  }
};

enum class ClosedReason : std::uint8_t {
  ClientClosed,     // downstream peer closed the leg
  ServerClosed,     // upstream peer closed the leg
  ConnectFailed,    // upstream connect error or refusal fault
  FaultReset,       // reset fault or idle timeout with reset action
  IdleTimeout,
  ShutdownRequested // operator stop / control shutdown
};

inline const char* closed_reason_name(ClosedReason r) {
  switch (r) {
    case ClosedReason::ClientClosed: return "client_closed";
    case ClosedReason::ServerClosed: return "server_closed";
    case ClosedReason::ConnectFailed: return "connect_failed";
    case ClosedReason::FaultReset: return "fault_reset";
    case ClosedReason::IdleTimeout: return "idle_timeout";
    case ClosedReason::ShutdownRequested: return "shutdown_requested";
  }
  return "unknown";
}

}  // namespace loki
