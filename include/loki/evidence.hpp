#pragma once

// Evidence: run directory creation, streaming event log, connection records,
// final metrics/summary artifacts.
//
// Layout (INVARIANT):
//   <runs_root>/<run-id>/
//     manifest.json
//     scenario.yaml            (verbatim copy)
//     scenario.normalized.json (canonical form; hashed into the manifest)
//     events.jsonl             (decision ledger, append-only, line-buffered)
//     connections.jsonl        (lifecycle records per connection)
//     metrics.json             (counters snapshot at finish)
//     summary.json             (final aggregates)
//     control.sock             (unix domain socket, removed on clean exit)

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <loki/engine.hpp>
#include <loki/json.hpp>
#include <loki/scenario.hpp>
#include <loki/types.hpp>
#include <loki/version.hpp>

namespace loki {

struct ManifestInfo {
  std::string loki_version;
  int rng_version = LOKI_RNG_VERSION;
  int ledger_format_version = LOKI_LEDGER_FORMAT_VERSION;
  std::string git_sha;
  std::string scenario_hash_hex;
  std::uint64_t seed = 0;
  WallUs started_at = 0;
  std::string platform;    // e.g. "Darwin arm64"
  std::string kernel;      // uname release
  std::string backend;     // poller backend name
  std::string mode;        // "live" | "seed-replay" | "ledger-replay"
};

json::Value decision_to_json(const FaultDecision& d);
FaultDecision decision_from_json(const json::Value& v);  // throws std::runtime_error on malformed

class RunStore {
 public:
  // Creates the run directory and writes manifest + scenario copies.
  // Throws std::runtime_error when the run cannot be created.
  static RunStore create(const std::string& runs_root,
                         const ManifestInfo& info,
                         const std::string& scenario_yaml_text,
                         const std::string& normalized_json_text);

  ~RunStore();  // closes files; move-only

  RunStore(RunStore&&) noexcept;
  RunStore& operator=(RunStore&&) noexcept;
  RunStore(const RunStore&) = delete;
  RunStore& operator=(const RunStore&) = delete;

 private:
  // Only create() constructs an empty shell; it populates impl_ before returning.
  RunStore() = default;

 public:

  const std::string& run_dir() const;
  std::string control_socket_path() const;

  // Streaming decision ledger. Sampling policy is applied by callers
  // (the engine knows each rule's LedgerMode); this writer records everything
  // it is given plus count-only notes for sampled-out decisions.
  class EventLog {
   public:
    void append(const FaultDecision& d);
    void note_counts(FaultKind kind, std::uint64_t n);  // aggregated, no detail lines
    std::uint64_t written() const { return written_; }
    void flush();
   private:
    friend class RunStore;
    std::FILE* f_ = nullptr;
    std::uint64_t written_ = 0;
    std::uint64_t counts_by_kind_[16]{};  // indexed by FaultKind
  };

  EventLog& events();

  // One JSON object per connection lifecycle completion (open, close, bytes).
  void log_connection(const json::Value& record);

  // Writes metrics.json and summary.json, flushes and closes all logs.
  void finish(const json::Value& metrics, const json::Value& summary);

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
  EventLog event_log_;
};

}  // namespace loki
