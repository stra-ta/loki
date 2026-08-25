#pragma once

// Replay: re-apply a recorded fault schedule without drawing RNG.
//
// Two modes exist in the CLI:
//   seed replay   - run the scenario again with the same seed. Identical
//                   schedules arise only if observed event order repeats.
//   ledger replay - load events.jsonl from a prior run and re-apply recorded
//                   RESOLVED decisions at their recorded logical positions
//                   (conn ordinal, direction, stream_offset). Stronger than
//                   seed replay but assumes the workload reproduces positions.

#include <memory>
#include <string>
#include <vector>

#include <loki/evidence.hpp>
#include <loki/scenario.hpp>

namespace loki {

struct LoadedLedger {
  std::vector<FaultDecision> decisions;
  std::string scenario_hash_hex;
  std::uint64_t seed = 0;
};

// Loads and validates a prior run's events.jsonl (detail lines only).
// Throws std::runtime_error on malformed records or hash mismatch when
// expected_hash_hex is non-empty and differs.
LoadedLedger load_events_jsonl(const std::string& events_path,
                               const std::string& expected_hash_hex,
                               bool strict_hash);

// INetworkMutator that replays a loaded ledger mechanically.
class LedgerEngine {
 public:
  struct Stats {
    std::uint64_t reapplied = 0;              // decisions re-applied successfully
    std::uint64_t unconsumed = 0;             // recorded but never matched positions
    std::uint64_t position_misses = 0;        // chunks arriving where ledger had none
  };
  virtual ~LedgerEngine() = default;
  virtual const Stats& stats() const = 0;
};

struct LedgerEngineOptions {
  bool strict_positions = true;  // fail loudly when input positions diverge
};

std::unique_ptr<INetworkMutator> make_ledger_engine(const CompiledScenario& scenario,
                                                    LoadedLedger ledger,
                                                    LedgerEngineOptions options);

}  // namespace loki
