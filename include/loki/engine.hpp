#pragma once

// Fault engine contract. The mutator is the ONLY component that decides how
// bytes are maimed; it never touches a socket. The reactor feeds it freshly
// read chunks and executes the pieces and scheduled actions that come back.
//
// Two implementations exist:
//   - LiveFaultEngine (src/faults/live_engine.cpp): matches rules, draws from
//     the run RNG, records decisions.
//   - LedgerEngine (src/replay/ledger_engine.cpp): re-applies recorded
//     decisions at their recorded logical positions without drawing RNG.
//
// Connect initiation (INVARIANT): implementations MUST schedule exactly one
// of ActConnectUpstream (immediate or delayed) or ActRefuseDownstream per
// accepted connection from on_connection_accepted(). The reactor never opens
// the upstream socket on its own initiative.
//
// Deterministic draw order (INVARIANT): within one process_read call, rules
// evaluate in ascending index; each rule consumes RNG only when its match
// succeeds and in the documented order of its own parameters.

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <loki/json.hpp>
#include <loki/scheduler.hpp>
#include <loki/scenario.hpp>
#include <loki/types.hpp>

namespace loki {

// Per-direction counters maintained by the reactor (pristine logical stream).
struct StreamStats {
  std::uint64_t bytes_seen = 0;   // including this chunk? NO: excluding this chunk,
                                  // i.e., offset of this chunk's first byte.
  std::uint64_t chunks_seen = 0;  // prior chunk count for this direction
};

struct DecisionInputs {
  std::uint64_t bytes_seen = 0;
  std::uint64_t elapsed_us = 0;
};

struct FaultDecision {
  std::uint64_t event_index = 0;      // global monotonic decision counter, starts at 1
  ConnId conn = 0;
  Dir dir = Dir::AtoB;
  std::uint64_t stream_offset = 0;    // pristine logical offset of triggering chunk
  std::uint32_t rule_index = 0;
  std::string rule_name;
  FaultKind kind{};
  json::Value resolved{json::Value::object()};  // resolved parameters incl. sampled values
  DecisionInputs inputs;
  bool applied = true;                // false when a no-op (e.g., corrupt target missed)
};

struct OutPiece {
  std::vector<std::byte> payload;
  std::uint64_t logical_offset = 0;   // pristine offset of first payload byte
  TimeUs send_at_us = 0;              // earliest allowed send time
  bool immediate = true;              // true => send_at_us ignored
};

struct ProcessResult {
  std::vector<OutPiece> pieces;       // may be empty (discarded/blackholed)
  std::vector<FaultDecision> decisions;
};

enum class ManualAction : std::uint8_t { Pause, Resume, InjectReset };

class INetworkMutator {
 public:
  virtual ~INetworkMutator() = default;

  // Binds the shared scheduler and reports the run's time epoch.
  virtual void bind(Scheduler* scheduler, TimeUs epoch) = 0;

  // A fresh chunk was read from the source leg of `key`.
  // chunk_logical_offset == stats.bytes_seen of this chunk's first byte.
  virtual ProcessResult process_read(const StreamKey& key,
                                     std::uint64_t chunk_logical_offset,
                                     std::span<const std::byte> data,
                                     const StreamStats& stats,
                                     TimeUs now) = 0;

  virtual void on_connection_accepted(ConnId conn, TimeUs now) = 0;
  virtual void on_connection_established(ConnId conn, TimeUs now) = 0;
  virtual void on_connection_closed(ConnId conn, TimeUs now, ClosedReason reason) = 0;

  // Bytes actually hit the wire on the far leg (used by token bucket).
  virtual void on_data_flushed(const StreamKey& key, std::uint64_t bytes, TimeUs now) = 0;

  // Flow-control queries consulted by the reactor before arming reads.
  virtual bool read_enabled(const StreamKey& key, TimeUs now) = 0;    // freeze support
  virtual bool listener_enabled(TimeUs now) = 0;                      // accept_stall / pause

  // Lifecycle event sink for evidence; set by the reactor before use.
  // Decisions produced via process_read are collected by the reactor from
  // ProcessResult; lifecycle decisions go through this sink as they happen.
  using DecisionSink = std::function<void(FaultDecision)>;
  virtual void set_decision_sink(DecisionSink sink) = 0;

  // Summary aggregation for evidence (fault counts by kind name).
  virtual const std::vector<FaultDecision>& lifecycle_decisions() const = 0;

  // Operator/manual action hook (control socket). Returns true when handled.
  virtual bool manual_action(ManualAction action, ConnId conn, TimeUs now) = 0;

  // A scheduler action originated by this mutator surfaced (engine-internal
  // timers: ActFlushReorder, ActFlushCoalesce, ActIdleFire). The reactor
  // forwards these here instead of executing them mechanically. Returns any
  // pieces released (e.g., flushed reorder/coalesce buffers).
  virtual ProcessResult on_engine_timer(const ScheduledAction& origin, TimeUs now) = 0;

  // Whether the engine still expects to make progress. Consulted only by
  // replay-style runs: a ledger replay terminates once no connections remain
  // and no recorded work is left, instead of waiting for a signal. Live
  // engines keep the default (always pending; stopped externally).
  virtual bool has_pending_work() const { return true; }
};

using MutatorFactory =
    std::function<std::unique_ptr<INetworkMutator>(const CompiledScenario&, Scheduler&, TimeUs)>;

// Temporary pass-through mutator: echoes chunks unmodified, no decisions.
// Lives until the faults package replaces it; kept for reactor bring-up tests.
std::unique_ptr<INetworkMutator> make_pass_through_engine();

// The real V1 fault engine (implemented by the faults package).
std::unique_ptr<INetworkMutator> make_live_fault_engine(const CompiledScenario& scenario);

}  // namespace loki
