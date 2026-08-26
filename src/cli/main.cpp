// loki CLI: run / validate / replay / inspect / ctl.
//
// Exit codes (INVARIANT): 0 ok, 2 usage error, 3 scenario validation failure,
// 4 runtime failure, 5 replay mismatch.

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <loki/control.hpp>
#include <loki/engine.hpp>
#include <loki/evidence.hpp>
#include <loki/json.hpp>
#include <loki/json_parse.hpp>
#include <loki/reactor.hpp>
#include <loki/replay.hpp>
#include <loki/scenario.hpp>
#include <loki/version.hpp>
#include "../config/validate_transport.hpp"

namespace fs = std::filesystem;

namespace loki {
namespace {

constexpr int kExitOk = 0;
constexpr int kExitUsage = 2;
constexpr int kExitValidation = 3;
constexpr int kExitRuntime = 4;
constexpr int kExitReplayMismatch = 5;

void print_usage(std::FILE* out) {
  std::fprintf(out,
      "loki %s - deterministic hostile-network engine\n"
      "\n"
      "Usage:\n"
      "  loki run SCENARIO.yaml [--seed N] [--listen ADDR] [--upstream ADDR]\n"
      "      [--runs-dir DIR] [--full-ledger | --ledger-counts | --ledger-sample N]\n"
      "  loki validate SCENARIO.yaml\n"
      "  loki replay RUN_DIR [--check-only]\n"
      "  loki inspect RUN_DIR [--summary | --connections | --events --tail N]\n"
      "  loki ctl RUN_DIR_OR_SOCK CMD [CONN]\n"
      "\n"
      "Commands for ctl: pause, resume, status, inject [CONN]\n"
      "\n"
      "Examples:\n"
      "  loki run scenarios/basic.yaml --seed 123\n"
      "  loki validate scenarios/basic.yaml\n"
      "  loki replay runs/run-20260101-000000-123\n"
      "  loki inspect runs/run-20260101-000000-123 --events --tail 50\n"
      "  loki ctl runs/run-20260101-000000-123 status\n"
      "  loki ctl runs/run-20260101-000000-123 inject 17\n",
      LOKI_VERSION_STRING);
}

// Expand "--flag=value" into "--flag value" before verb-specific parsing.
std::vector<std::string> expand_equals(const std::vector<std::string>& args) {
  std::vector<std::string> out;
  out.reserve(args.size() + 2);
  for (const auto& a : args) {
    if (a.rfind("--", 0) == 0) {
      const auto eq = a.find('=');
      if (eq != std::string::npos && eq + 1 < a.size()) {
        out.push_back(a.substr(0, eq));
        out.push_back(a.substr(eq + 1));
        continue;
      }
    }
    out.push_back(a);
  }
  return out;
}

[[noreturn]] void usage_error(const std::string& msg) {
  std::fprintf(stderr, "loki: usage error: %s\n", msg.c_str());
  print_usage(stderr);
  std::exit(kExitUsage);
}

bool parse_u64(const std::string& s, std::uint64_t* out) {
  if (s.empty()) return false;
  std::uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    if (v > (~std::uint64_t{0} - static_cast<std::uint64_t>(c - '0')) / 10) return false;
    v = v * 10 + static_cast<std::uint64_t>(c - '0');
  }
  *out = v;
  return true;
}

std::string read_file_or_exit(const fs::path& p, int exit_code) {
  std::ifstream in(p, std::ios::binary);
  if (!in) {
    std::fprintf(stderr, "loki: cannot read %s\n", p.string().c_str());
    std::exit(exit_code);
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

std::string trim(const std::string& s) {
  const auto b = s.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) return "";
  const auto e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

std::vector<std::string> read_lines_trimmed(const fs::path& p) {
  std::vector<std::string> lines;
  std::ifstream in(p);
  if (!in) return lines;
  std::string line;
  while (std::getline(in, line)) {
    std::string t = trim(line);
    if (!t.empty()) lines.push_back(std::move(t));
  }
  return lines;
}

const json::Value& manifest_member_or_exit(const json::Value& m, const char* key) {
  const json::Value* v = m.find(key);
  if (!v) {
    std::fprintf(stderr, "loki: manifest.json missing '%s'\n", key);
    std::exit(kExitRuntime);
  }
  return *v;
}

json::Value load_manifest_or_exit(const fs::path& dir) {
  const fs::path mp = dir / "manifest.json";
  if (!fs::exists(mp)) {
    std::fprintf(stderr, "loki: not a loki run directory (missing %s)\n", mp.string().c_str());
    std::exit(kExitRuntime);
  }
  try {
    return json::parse_json(read_file_or_exit(mp, kExitRuntime));
  } catch (const std::exception& e) {
    std::fprintf(stderr, "loki: malformed manifest.json: %s\n", e.what());
    std::exit(kExitRuntime);
  }
}

// Newest run directory under root (name-sorted; run ids sort chronologically).
std::string newest_run_dir(const std::string& runs_root) {
  std::string best;
  std::error_code ec;
  for (const auto& e : fs::directory_iterator(runs_root, ec)) {
    if (!e.is_directory(ec)) continue;
    if (!fs::exists(e.path() / "manifest.json", ec)) continue;
    const std::string name = e.path().filename().string();
    if (best.empty() || name > best) best = name;
  }
  return best.empty() ? runs_root : (fs::path(runs_root) / best).string();
}

CompiledScenario compile_from_text(const std::string& yaml_text, const std::string& origin) {
  try {
    return compile_scenario(yaml_text);
  } catch (const ScenarioError& e) {
    std::fprintf(stderr, "loki: %s: validation error%s%s: %s\n", origin.c_str(),
                 e.line > 0 ? " at line " : "", e.line > 0 ? std::to_string(e.line).c_str() : "",
                 e.what());
    std::exit(kExitValidation);
  }
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

int cmd_validate(const std::string& path) {
  const std::string text = read_file_or_exit(path, kExitValidation);
  const CompiledScenario sc = compile_from_text(text, path);
  std::printf("ok %s\n", sc.scenario_hash_hex().c_str());
  std::printf("seed=%llu rules=%zu listen=%s upstream=%s\n",
              static_cast<unsigned long long>(sc.seed), sc.rules.size(),
              sc.listen.to_string().c_str(), sc.upstream.to_string().c_str());
  return kExitOk;
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

int cmd_run(const std::vector<std::string>& args) {
  std::string scenario_path;
  bool have_seed = false;
  std::uint64_t seed = 0;
  bool have_listen = false, have_upstream = false;
  std::string listen_addr, upstream_addr, runs_dir = "runs";
  TransportMode transport = TransportMode::Tcp;
  enum class LedgerOverride { None, Full, Counts, SampleN };
  LedgerOverride ledger_override = LedgerOverride::None;
  std::uint64_t sample_n = 1;

  bool positional_seen = false;
  for (size_t i = 0; i < args.size(); ++i) {
    const std::string& a = args[i];
    auto value = [&](const char* flag) -> std::string {
      if (i + 1 >= args.size()) usage_error(std::string(flag) + " requires a value");
      return args[++i];
    };
    if (a == "--seed") {
      if (!parse_u64(value("--seed"), &seed)) usage_error("--seed requires an unsigned integer");
      have_seed = true;
    } else if (a == "--listen") {
      listen_addr = value("--listen");
      have_listen = true;
    } else if (a == "--upstream") {
      upstream_addr = value("--upstream");
      have_upstream = true;
    } else if (a == "--runs-dir") {
      runs_dir = value("--runs-dir");
    } else if (a == "--full-ledger") {
      ledger_override = LedgerOverride::Full;
    } else if (a == "--ledger-counts") {
      ledger_override = LedgerOverride::Counts;
    } else if (a == "--ledger-sample") {
      if (!parse_u64(value("--ledger-sample"), &sample_n) || sample_n == 0) {
        usage_error("--ledger-sample requires a positive integer");
      }
      ledger_override = LedgerOverride::SampleN;
    } else if (a == "--transport") {
      const std::string v = value("--transport");
      if (v == "tcp") {
        transport = TransportMode::Tcp;
      } else if (v == "udp") {
        transport = TransportMode::Udp;
      } else {
        usage_error("--transport must be tcp or udp");
      }
    } else if (!a.empty() && a[0] == '-') {
      usage_error("unknown flag '" + a + "'");
    } else if (!positional_seen) {
      scenario_path = a;
      positional_seen = true;
    } else {
      usage_error("unexpected argument '" + a + "'");
    }
  }
  if (!positional_seen) usage_error("run requires SCENARIO.yaml");

  const std::string yaml_text = read_file_or_exit(scenario_path, kExitValidation);
  CompiledScenario sc = compile_from_text(yaml_text, scenario_path);
  try {
    check_transport_compat(sc, transport);
  } catch (const ScenarioError& e) {
    std::fprintf(stderr, "loki: %s: validation error%s%s: %s\n", scenario_path.c_str(),
                 e.line > 0 ? " at line " : "",
                 e.line > 0 ? std::to_string(e.line).c_str() : "", e.what());
    return kExitValidation;
  }

  // Overrides are applied to the compiled plan, then the canonical normalized
  // JSON and its hash are recomputed so evidence reflects what actually ran.
  try {
    if (have_seed) sc.seed = seed;
    if (have_listen) sc.listen = parse_endpoint(listen_addr);
    if (have_upstream) sc.upstream = parse_endpoint(upstream_addr);
  } catch (const std::invalid_argument& e) {
    std::fprintf(stderr, "loki: %s\n", e.what());
    std::exit(kExitUsage);
  }
  switch (ledger_override) {
    case LedgerOverride::None: break;
    case LedgerOverride::Full:
      for (auto& r : sc.rules) r.ledger = LedgerMode::Full;
      break;
    case LedgerOverride::Counts:
      for (auto& r : sc.rules) r.ledger = LedgerMode::Counts;
      break;
    case LedgerOverride::SampleN:
      for (auto& r : sc.rules) {
        r.ledger = LedgerMode::SampleN;
        r.sample_n = static_cast<std::uint32_t>(sample_n);
      }
      break;
  }

  ReactorConfig cfg;
  cfg.scenario = sc;
  cfg.runs_root = runs_dir;
  cfg.git_sha = LOKI_GIT_SHA;
  cfg.mode = RunMode::Live;
  cfg.transport = transport;

  MutatorFactory factory = [](const CompiledScenario& scenario, Scheduler& sched,
                              TimeUs epoch) -> std::unique_ptr<INetworkMutator> {
    auto engine = make_live_fault_engine(scenario);
    engine->bind(&sched, epoch);
    return engine;
  };

  ReactorSummary summary;
  try {
    summary = run_proxy(cfg, factory);
  } catch (const ScenarioError& e) {
    std::fprintf(stderr, "loki: scenario validation error: %s\n", e.what());
    return kExitValidation;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "loki: runtime failure: %s\n", e.what());
    return kExitRuntime;
  }

  const std::string run_dir = newest_run_dir(runs_dir);

  // Backfill: ReactorConfig has no field for the verbatim YAML text, so the
  // reactor cannot archive scenario.yaml itself. The CLI owns that text;
  // write it when the archived copy came out empty.
  const fs::path archived = fs::path(run_dir) / "scenario.yaml";
  std::error_code ec;
  if (fs::exists(archived, ec) && fs::file_size(archived, ec) == 0 && !ec) {
    std::ofstream out(archived, std::ios::binary | std::ios::trunc);
    out << yaml_text;
  }

  std::printf("run complete: %s\n", run_dir.c_str());
  std::printf("connections=%llu refused=%llu bytes_a_to_b=%llu bytes_b_to_a=%llu decisions=%llu wall_us=%lld\n",
              static_cast<unsigned long long>(summary.connections_total),
              static_cast<unsigned long long>(summary.refused_total),
              static_cast<unsigned long long>(summary.bytes_a_to_b),
              static_cast<unsigned long long>(summary.bytes_b_to_a),
              static_cast<unsigned long long>(summary.decisions_logged),
              static_cast<long long>(summary.wall_us));
  return kExitOk;
}

// ---------------------------------------------------------------------------
// replay
// ---------------------------------------------------------------------------

int cmd_replay(const std::vector<std::string>& args) {
  std::string run_dir;
  bool check_only = false;
  TransportMode transport = TransportMode::Tcp;
  bool positional_seen = false;
  for (size_t i = 0; i < args.size(); ++i) {
    const std::string& a = args[i];
    auto value = [&](const char* flag) -> std::string {
      if (i + 1 >= args.size()) usage_error(std::string(flag) + " requires a value");
      return args[++i];
    };
    if (a == "--check-only") {
      check_only = true;
    } else if (a == "--transport") {
      const std::string v = value("--transport");
      if (v == "tcp") {
        transport = TransportMode::Tcp;
      } else if (v == "udp") {
        transport = TransportMode::Udp;
      } else {
        usage_error("--transport must be tcp or udp");
      }
    } else if (!a.empty() && a[0] == '-') {
      usage_error("unknown flag '" + a + "'");
    } else if (!positional_seen) {
      run_dir = a;
      positional_seen = true;
    } else {
      usage_error("unexpected argument '" + a + "'");
    }
  }
  if (!positional_seen) usage_error("replay requires RUN_DIR");

  const json::Value manifest = load_manifest_or_exit(run_dir);
  const std::string expected_hash =
      manifest_member_or_exit(manifest, "scenario_hash_hex").as_str();

  const std::string yaml_text =
      read_file_or_exit(fs::path(run_dir) / "scenario.yaml", kExitRuntime);
  CompiledScenario sc = compile_from_text(yaml_text, fs::path(run_dir) / "scenario.yaml");
  try {
    check_transport_compat(sc, transport);
  } catch (const ScenarioError& e) {
    std::fprintf(stderr, "loki: replay: validation error%s%s: %s\n",
                 e.line > 0 ? " at line " : "",
                 e.line > 0 ? std::to_string(e.line).c_str() : "", e.what());
    return kExitValidation;
  }

  // The archived scenario must be exactly what produced this ledger.
  // Note: CLI overrides (--seed etc.) apply on top of the archived YAML, so
  // only the canonical hash is authoritative here.
  if (sc.scenario_hash_hex() != expected_hash) {
    std::fprintf(stderr,
                 "loki: replay mismatch: scenario.yaml (hash %s) does not match "
                 "manifest (hash %s)\n",
                 sc.scenario_hash_hex().c_str(), expected_hash.c_str());
    return kExitReplayMismatch;
  }

  LoadedLedger ledger;
  try {
    ledger = load_events_jsonl(fs::path(run_dir) / "events.jsonl", expected_hash, true);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "loki: replay failed loading ledger: %s\n", e.what());
    return kExitReplayMismatch;
  }

  if (check_only) {
    std::printf("check ok: %s\n", run_dir.c_str());
    std::printf("scenario_hash=%s seed=%llu decisions=%zu\n", expected_hash.c_str(),
                static_cast<unsigned long long>(ledger.seed), ledger.decisions.size());
    return kExitOk;
  }

  // Full ledger replay: re-apply recorded decisions through the reactor.
  ReactorConfig cfg;
  cfg.scenario = sc;
  cfg.runs_root = "runs";
  cfg.git_sha = LOKI_GIT_SHA;
  cfg.mode = RunMode::LedgerReplay;
  cfg.transport = transport;
  cfg.ledger_replay_dir = run_dir;

  LoadedLedger shared_ledger = std::move(ledger);
  std::shared_ptr<INetworkMutator> engine(
      make_ledger_engine(sc, std::move(shared_ledger), LedgerEngineOptions{}));

  // Non-owning forwarding shim: the factory must hand back a unique_ptr, but
  // we keep the real engine alive here to read LedgerEngine::stats() after
  // run_proxy returns.
  class AliasMutator : public INetworkMutator {
   public:
    explicit AliasMutator(INetworkMutator* inner) : inner_(inner) {}
    void bind(Scheduler* s, TimeUs e) override { inner_->bind(s, e); }
    ProcessResult process_read(const StreamKey& k, std::uint64_t off,
                               std::span<const std::byte> data, const StreamStats& st,
                               TimeUs now) override {
      return inner_->process_read(k, off, data, st, now);
    }
    void on_connection_accepted(ConnId c, TimeUs now) override {
      inner_->on_connection_accepted(c, now);
    }
    void on_connection_established(ConnId c, TimeUs now) override {
      inner_->on_connection_established(c, now);
    }
    void on_connection_closed(ConnId c, TimeUs now, ClosedReason r) override {
      inner_->on_connection_closed(c, now, r);
    }
    void on_data_flushed(const StreamKey& k, std::uint64_t b, TimeUs now) override {
      inner_->on_data_flushed(k, b, now);
    }
    bool read_enabled(const StreamKey& k, TimeUs now) override {
      return inner_->read_enabled(k, now);
    }
    bool listener_enabled(TimeUs now) override { return inner_->listener_enabled(now); }
    void set_decision_sink(DecisionSink sink) override { inner_->set_decision_sink(std::move(sink)); }
    const std::vector<FaultDecision>& lifecycle_decisions() const override {
      return inner_->lifecycle_decisions();
    }
    bool manual_action(ManualAction a, ConnId c, TimeUs now) override {
      return inner_->manual_action(a, c, now);
    }
    ProcessResult on_engine_timer(const ScheduledAction& origin, TimeUs now) override {
      return inner_->on_engine_timer(origin, now);
    }
    bool has_pending_work() const override { return inner_->has_pending_work(); }

   private:
    INetworkMutator* inner_;
  };

  MutatorFactory factory = [&engine](const CompiledScenario&, Scheduler& sched,
                                     TimeUs epoch) -> std::unique_ptr<INetworkMutator> {
    auto alias = std::make_unique<AliasMutator>(engine.get());
    alias->bind(&sched, epoch);
    return alias;
  };

  try {
    run_proxy(cfg, factory);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "loki: runtime failure during replay: %s\n", e.what());
    return kExitRuntime;
  }

  const auto* ledger_engine = dynamic_cast<const LedgerEngine*>(engine.get());
  std::uint64_t reapplied = 0, unconsumed = 0, position_misses = 0;
  if (ledger_engine) {
    reapplied = ledger_engine->stats().reapplied;
    unconsumed = ledger_engine->stats().unconsumed;
    position_misses = ledger_engine->stats().position_misses;
  } else {
    std::fprintf(stderr, "loki: warning: ledger stats unavailable\n");
  }

  std::printf("replay: reapplied=%llu unconsumed=%llu position_misses=%llu\n",
              static_cast<unsigned long long>(reapplied),
              static_cast<unsigned long long>(unconsumed),
              static_cast<unsigned long long>(position_misses));
  // A mismatch means recorded decisions never met their positions.
  // Position misses only count chunks the ledger never instrumented
  // (e.g., the opposite direction or differently-split reads); those pass
  // through untouched by design, so they are reported but not fatal.
  if (unconsumed > 0) {
    std::fprintf(stderr,
                 "loki: replay mismatch: workload did not reproduce recorded positions "
                 "(unconsumed=%llu)\n",
                 static_cast<unsigned long long>(unconsumed));
    return kExitReplayMismatch;
  }
  return kExitOk;
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

int cmd_inspect(const std::vector<std::string>& args) {
  std::string run_dir;
  std::string view = "summary";
  bool have_tail = false;
  std::uint64_t tail = 20;
  bool positional_seen = false;
  for (size_t i = 0; i < args.size(); ++i) {
    const std::string& a = args[i];
    if (a == "--summary") {
      view = "summary";
    } else if (a == "--connections") {
      view = "connections";
    } else if (a == "--events") {
      view = "events";
    } else if (a == "--tail") {
      if (i + 1 >= args.size() || !parse_u64(args[++i], &tail)) {
        usage_error("--tail requires an unsigned integer");
      }
      have_tail = true;
    } else if (!a.empty() && a[0] == '-') {
      usage_error("unknown flag '" + a + "'");
    } else if (!positional_seen) {
      run_dir = a;
      positional_seen = true;
    } else {
      usage_error("unexpected argument '" + a + "'");
    }
  }
  if (!positional_seen) usage_error("inspect requires RUN_DIR");
  if (view != "events" && have_tail) usage_error("--tail is only valid with --events");

  if (view == "summary") {
    const json::Value manifest = load_manifest_or_exit(run_dir);
    std::printf("run:        %s\n", run_dir.c_str());
    std::printf("version:    %s\n", manifest.find("loki_version")
                                          ? manifest.find("loki_version")->as_str().c_str()
                                          : "?");
    std::printf("mode:       %s\n", manifest.find("mode")
                                          ? manifest.find("mode")->as_str().c_str()
                                          : "?");
    std::printf("seed:       %llu\n",
                static_cast<unsigned long long>(
                    manifest.find("seed") ? manifest.find("seed")->as_uint() : 0));
    std::printf("started_at: %s\n", manifest.find("started_at_iso")
                                          ? manifest.find("started_at_iso")->as_str().c_str()
                                          : "?");
    std::printf("scenario:   %s\n",
                manifest.find("scenario_hash_hex")
                    ? manifest.find("scenario_hash_hex")->as_str().c_str()
                    : "?");
    const fs::path summary_path = fs::path(run_dir) / "summary.json";
    if (fs::exists(summary_path)) {
      std::printf("\n%s\n", trim(read_file_or_exit(summary_path, kExitRuntime)).c_str());
    } else {
      std::printf("\n(no summary.json; run did not finish cleanly)\n");
    }
    return kExitOk;
  }

  if (view == "connections") {
    const fs::path p = fs::path(run_dir) / "connections.jsonl";
    if (!fs::exists(p)) {
      std::fprintf(stderr, "loki: missing %s\n", p.string().c_str());
      return kExitRuntime;
    }
    for (const auto& line : read_lines_trimmed(p)) std::printf("%s\n", line.c_str());
    return kExitOk;
  }

  // events --tail N
  const fs::path p = fs::path(run_dir) / "events.jsonl";
  if (!fs::exists(p)) {
    std::fprintf(stderr, "loki: missing %s\n", p.string().c_str());
    return kExitRuntime;
  }
  const auto lines = read_lines_trimmed(p);
  const std::uint64_t total = lines.size();
  const std::uint64_t start = tail >= total ? 0 : total - tail;
  for (std::uint64_t i = start; i < total; ++i) std::printf("%s\n", lines[i].c_str());
  std::fprintf(stderr, "[%llu of %llu ledger events]\n",
               static_cast<unsigned long long>(total - start),
               static_cast<unsigned long long>(total));
  return kExitOk;
}

// ---------------------------------------------------------------------------
// ctl
// ---------------------------------------------------------------------------

int cmd_ctl(const std::vector<std::string>& args) {
  std::string target, cmd_name, conn_arg;
  size_t positionals = 0;
  for (size_t i = 0; i < args.size(); ++i) {
    const std::string& a = args[i];
    if (!a.empty() && a[0] == '-') {
      usage_error("unknown flag '" + a + "'");
    }
    switch (positionals++) {
      case 0: target = a; break;
      case 1: cmd_name = a; break;
      case 2: conn_arg = a; break;
      default: usage_error("unexpected argument '" + a + "'");
    }
  }
  if (target.empty()) usage_error("ctl requires RUN_DIR_OR_SOCK");
  if (cmd_name.empty()) usage_error("ctl requires CMD");
  if (!conn_arg.empty()) {
    std::uint64_t c = 0;
    if (!parse_u64(conn_arg, &c)) usage_error("CONN must be a connection ordinal");
  }

  std::string request;
  if (cmd_name == "pause") {
request = "{\"cmd\":\"pause\"}";
  } else if (cmd_name == "resume") {
request = "{\"cmd\":\"resume\"}";
  } else if (cmd_name == "status") {
request = "{\"cmd\":\"status\"}";
  } else if (cmd_name == "inject" || cmd_name == "reset" || cmd_name == "inject-reset") {
request = conn_arg.empty() ? "{\"cmd\":\"inject\",\"fault\":\"reset\"}"
                               : "{\"cmd\":\"inject\",\"fault\":\"reset\",\"connection\":" +
                                     conn_arg + "}";
  } else {
    usage_error("unknown ctl command '" + cmd_name + "' (expected pause|resume|status|inject)");
  }

  // Accept either the run directory or an explicit socket path.
  fs::path sock_path(target);
  std::error_code ec;
  if (fs::is_directory(target, ec)) sock_path /= "control.sock";

  // Validate locally before touching the socket.
  try {
    (void)parse_control_request(request);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "loki: internal control request error: %s\n", e.what());
    return kExitRuntime;
  }

  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    std::perror("loki: socket");
    return kExitRuntime;
  }
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  const std::string sp = sock_path.string();
  if (sp.size() >= sizeof(addr.sun_path)) {
    std::fprintf(stderr, "loki: socket path too long: %s\n", sp.c_str());
    ::close(fd);
    return kExitRuntime;
  }
  std::strncpy(addr.sun_path, sp.c_str(), sizeof(addr.sun_path) - 1);

  if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
    std::fprintf(stderr, "loki: cannot connect to control socket %s: %s\n", sp.c_str(),
                 std::strerror(errno));
    ::close(fd);
    return kExitRuntime;
  }

  const std::string line = request + "\n";
  ssize_t off = 0;
  while (off < static_cast<ssize_t>(line.size())) {
    const ssize_t n = ::write(fd, line.data() + off, line.size() - static_cast<size_t>(off));
    if (n <= 0) {
      std::fprintf(stderr, "loki: control socket write failed: %s\n", std::strerror(errno));
      ::close(fd);
      return kExitRuntime;
    }
    off += n;
  }
  ::shutdown(fd, SHUT_WR);

  std::string response;
  char buf[4096];
  ssize_t n;
  while ((n = ::read(fd, buf, sizeof buf)) > 0) response.append(buf, static_cast<size_t>(n));
  ::close(fd);

  if (response.empty()) {
    std::fprintf(stderr, "loki: no response from control socket %s\n", sp.c_str());
    return kExitRuntime;
  }
  std::printf("%s\n", trim(response).c_str());

  // Surface server-side errors via the runtime exit code.
  try {
    const json::Value v = json::parse_json(response);
    if (const json::Value* ok = v.find("ok"); ok && !ok->as_bool()) {
      if (const json::Value* err = v.find("error")) {
        std::fprintf(stderr, "loki: ctl error: %s\n", err->as_str().c_str());
      }
      return kExitRuntime;
    }
  } catch (const std::exception&) {
    // Non-JSON response still printed above; treat as success of transport.
  }
  return kExitOk;
}

}  // namespace
}  // namespace loki

using namespace loki;

int main(int argc, char** argv) {
  if (argc < 2) {
    print_usage(stderr);
    return kExitUsage;
  }
  const std::string verb = argv[1];
  const std::vector<std::string> args(argv + 2, argv + argc);

  if (verb == "-h" || verb == "--help" || verb == "help") {
    print_usage(stdout);
    return kExitOk;
  }
  if (verb == "--version" || verb == "version") {
    std::printf("loki %s\n", LOKI_VERSION_STRING);
    return kExitOk;
  }
  if (verb == "run") return cmd_run(expand_equals(args));
  if (verb == "validate") {
    if (args.size() != 1 || (!args[0].empty() && args[0][0] == '-')) {
      usage_error("validate requires exactly one SCENARIO.yaml");
    }
    return cmd_validate(args[0]);
  }
  if (verb == "replay") return cmd_replay(expand_equals(args));
  if (verb == "inspect") return cmd_inspect(expand_equals(args));
  if (verb == "ctl") return cmd_ctl(expand_equals(args));

  usage_error("unknown verb '" + verb + "' (expected run|validate|replay|inspect|ctl)");
}
