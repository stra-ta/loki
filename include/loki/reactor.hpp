#pragma once

// Reactor: the single-threaded event loop that owns sockets, the scheduler,
// the mutator, evidence, and the control plane.
//
// Loop shape (INVARIANT, deterministic ordering):
//   1. Poller wait with timeout = time until next scheduler deadline.
//   2. Sort ready events by (conn ordinal, fd kind); process each:
//      accept / read / write-drain / close handling.
//   3. Freshly read chunks go to the mutator; returned pieces are written
//      immediately when immediate, else enqueued and released by scheduled
//      ActDeliver actions.
//   4. Pop all due scheduler actions in (deadline, seq) order and execute.
//   5. Backpressure: a direction with pending bytes >= limits stops reading
//      its source socket (read arming off) until it drains below the bound.
//   6. Control requests drain between steps 4 and 5.

#include <functional>
#include <map>
#include <string>

#include <loki/engine.hpp>
#include <loki/evidence.hpp>
#include <loki/scenario.hpp>

namespace loki {

enum class RunMode : std::uint8_t { Live, SeedReplay, LedgerReplay };

// Transport family the proxy speaks. TCP is the V1 baseline; UDP reuses the
// same fault engine by modeling each client endpoint as a ConnId and each
// datagram as a chunk (cumulative logical offset). The fault engine is
// transport-agnostic; only the read/write layer differs.
enum class TransportMode : std::uint8_t { Tcp = 0, Udp = 1 };

struct ReactorConfig {
  CompiledScenario scenario;
  std::string runs_root = "runs";
  std::string git_sha = "unknown";
  RunMode mode = RunMode::Live;
  TransportMode transport = TransportMode::Tcp;
  std::string ledger_replay_dir;          // required for LedgerReplay
};

struct ReactorSummary {
  std::uint64_t connections_total = 0;
  std::uint64_t refused_total = 0;
  std::uint64_t bytes_a_to_b = 0;
  std::uint64_t bytes_b_to_a = 0;
  std::uint64_t decisions_logged = 0;
  TimeUs wall_us = 0;
};

// Blocks until SIGINT/SIGTERM or a fatal error. Writes all artifacts before
// returning. Throws std::runtime_error on fatal failures (bind errors etc).
ReactorSummary run_proxy(const ReactorConfig& config, MutatorFactory factory);

// UDP transport variant: same contract as run_proxy, dispatched when
// config.transport == TransportMode::Udp. Declared here so run_proxy can call
// it without leaking the UDP implementation into the public surface.
ReactorSummary run_proxy_udp(const ReactorConfig& config, MutatorFactory factory);

}  // namespace loki
