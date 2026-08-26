#pragma once

// Scenario model: fault parameters, match conditions, compiled plan.
//
// The YAML text is parsed and validated into a CompiledScenario exactly once.
// The runtime never re-reads scenario strings. The canonical normalized JSON
// (integers only, keys sorted at every level) is hashed with SHA-256; that
// hash appears in every artifact a run produces.
//
// Composition order (INVARIANT, enforced by the fault engine):
//   Rules are evaluated in ascending rule index against each freshly read
//   chunk. Shape faults (corrupt, duplicate, fragment, coalesce, reorder)
//   transform the current piece list. Timing faults (latency, bandwidth)
//   stamp send deadlines on pieces; when several stamp the same piece the
//   LATER deadline wins (never accelerates traffic). Lifecycle/silence faults
//   (blackhole, reset, half_close, refuse, accept_stall, connect_delay,
//   idle_timeout) queue side effects immediately.
//
// Offset invariant (INVARIANT):
//   stream_offset values always refer to the PRISTINE logical byte stream of
//   a direction, before any mutation. Matching sees pristine positions;
//   transforms apply downstream of the decision point.

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include <loki/endpoint.hpp>
#include <loki/sha256.hpp>
#include <loki/types.hpp>

namespace loki {

// ---------------------------------------------------------------------------
// Fault kinds and parameters
// ---------------------------------------------------------------------------

enum class FaultKind : std::uint8_t {
  Latency,        // delay + jitter per piece
  Bandwidth,      // token-bucket throttle per direction
  Fragment,       // split pieces into random sizes, order preserved
  Coalesce,       // accumulate pieces until size or max_delay trigger
  Reorder,        // buffer up to depth pieces, release permuted
  Duplicate,      // emit extra copies of every piece
  Corrupt,        // xor or overwrite one byte at an absolute stream offset
  Blackhole,      // silence a direction: discard chunks or freeze reads
  Reset,          // RST both legs after optional delay
  Fin,            // graceful FIN toward one side (half_close tx sugar)
  HalfClose,      // shutdown read or write side of one leg
  ConnectDelay,   // defer upstream connect after accept
  Refuse,         // close downstream without establishing upstream
  AcceptStall,    // stop accepting for a duration
  IdleTimeout     // reset or fin a connection idle for a duration
};

const char* kind_name(FaultKind k);   // "latency", "bandwidth", ...

struct LatencyParams {
  std::uint64_t mean_us = 0;
  std::uint64_t jitter_us = 0;       // uniform +/- jitter unless normal below
  bool normal = false;               // use normal distribution instead
  double stddev_us = 0.0;            // only when normal == true
};

struct BandwidthParams {
  std::uint64_t rate_bytes_per_sec = 0;  // > 0
  std::uint64_t burst_bytes = 0;         // bucket capacity, >= 1
};

struct FragmentParams {
  std::uint64_t min_bytes = 1;       // >= 1
  std::uint64_t max_bytes = 1;       // >= min_bytes
};

struct CoalesceParams {
  std::uint64_t size_bytes = 1;      // flush trigger
  std::uint64_t max_delay_us = 0;    // safety flush deadline from first held byte
};

struct ReorderParams {
  std::uint32_t depth = 2;           // >= 2; window size in pieces
  std::uint64_t max_hold_us = 1000;  // flush deadline from first held piece
};

struct DuplicateParams {
  std::uint32_t count = 1;           // extra copies, >= 1
};

struct CorruptParams {
  enum class Mode : std::uint8_t { XorByte, OverwriteByte };
  Mode mode = Mode::XorByte;
  std::uint64_t stream_offset = 0;   // absolute pristine logical offset
  std::uint8_t value = 0;            // mask for xor / replacement byte for overwrite
};

struct BlackholeParams {
  Dir dir = Dir::AtoB;               // which FLOW is silenced (direction of travel)
  enum class Mode : std::uint8_t { Discard, Freeze } mode = Mode::Discard;
  std::uint64_t duration_us = 0;     // 0 = rest of the run
};

struct ResetParams {
  std::uint64_t after_us = 0;        // 0 = immediate
};

struct HalfCloseParams {
  LegSide leg = LegSide::Up;         // whose write/read side closes
  enum class Mode : std::uint8_t { Tx, Rx } mode = Mode::Tx;  // Tx peer sees FIN
};

struct ConnectDelayParams {
  std::uint64_t delay_us = 0;
};

struct RefuseParams {
  std::uint64_t after_us = 0;
};

struct AcceptStallParams {
  std::uint64_t stall_us = 0;
};

struct IdleTimeoutParams {
  std::uint64_t idle_us = 0;
  enum class Action : std::uint8_t { Reset, Fin } action = Action::Reset;
};

using FaultParams = std::variant<LatencyParams, BandwidthParams, FragmentParams,
                                 CoalesceParams, ReorderParams, DuplicateParams,
                                 CorruptParams, BlackholeParams, ResetParams,
                                 HalfCloseParams, ConnectDelayParams, RefuseParams,
                                 AcceptStallParams, IdleTimeoutParams>;

FaultKind kind_of(const FaultParams& p);

// `fin` is schema sugar for half_close tx and maps to HalfCloseParams.

// ---------------------------------------------------------------------------
// Match conditions
// ---------------------------------------------------------------------------

struct ConnectionMatch {
  std::uint64_t every = 0;           // > 0: fire when conn % every == equals
  std::uint64_t equals = 0;
};

struct MatchSpec {
  std::optional<Dir> direction;      // nullopt = any direction
  TimeUs after_us = 0;               // elapsed run time guard
  std::uint64_t every_bytes = 0;     // fire once per new multiple crossed
  std::uint64_t every_events = 0;    // fire once per new multiple of chunk events
  ConnectionMatch connection;        // ordinal selector
  double probability = 1.0;          // [0,1]
  std::uint64_t max_occurrences = ~std::uint64_t{0};
  std::uint64_t min_stream_offset = 0;  // stream_offset >= guard
  std::string sni;                   // TLS SNI (server_name) exact match; "" = any
};

// ---------------------------------------------------------------------------
// Evidence policy
// ---------------------------------------------------------------------------

enum class LedgerMode : std::uint8_t { Full, Counts, SampleN };

inline const char* ledger_mode_name(LedgerMode m) {
  switch (m) {
    case LedgerMode::Full: return "full";
    case LedgerMode::Counts: return "counts";
    case LedgerMode::SampleN: return "sample";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Compiled plan
// ---------------------------------------------------------------------------

struct CompiledRule {
  std::uint32_t index = 0;           // 0-based evaluation order
  std::string name;                  // defaults to "rule-N" (N = index + 1)
  MatchSpec when;
  FaultKind kind{};
  FaultParams params;
  LedgerMode ledger = LedgerMode::Full;
  std::uint32_t sample_n = 1;        // for LedgerMode::SampleN
};

struct ProxyLimits {
  std::uint64_t pending_bytes_per_direction = 1u << 20;  // backpressure bound
  std::uint32_t max_connections = 1024;
};

struct CompiledScenario {
  Endpoint listen{};
  Endpoint upstream{};
  std::uint64_t seed = 0;
  ProxyLimits limits;
  std::vector<CompiledRule> rules;
  std::array<std::uint8_t, 32> scenario_hash{};

  std::string scenario_hash_hex() const { return to_hex(scenario_hash); }
};

// ---------------------------------------------------------------------------
// Config pipeline entry points (implemented by the config package)
// ---------------------------------------------------------------------------

class ScenarioError : public std::runtime_error {
 public:
  ScenarioError(std::string msg, int line) : std::runtime_error(std::move(msg)), line(line) {}
  int line = 0;  // 0 = not tied to a line
};

// Parses strict-subset YAML, validates against the V1 schema, normalizes.
// Throws ScenarioError on any problem. Unknown keys are errors everywhere.
CompiledScenario compile_scenario(const std::string& yaml_text);

// Canonical normalized JSON: integers only, object keys sorted recursively.
// This exact string is hashed and archived as scenario.normalized.json.
std::string normalized_json(const CompiledScenario& sc);

}  // namespace loki
