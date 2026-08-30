// Integration tests for the loki CLI verbs. These spawn the real binary and
// assert on exit codes and output, per the AGENTS.md contract:
//   0 ok, 2 usage, 3 validation error, 4 runtime failure, 5 replay mismatch.
//
// The full `loki run` blocks until SIGINT by design, so live-run assertions
// use short-lived runs signaled with SIGINT and check artifact completeness;
// everything else uses fabricated or minimal run directories.

#include <mach-o/dyld.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <loki/evidence.hpp>
#include <loki/scenario.hpp>

using namespace loki;

namespace fs = std::filesystem;

namespace {

// Locate the loki executable relative to this test binary:
// <build>/tests/integration/<test> lives next to <build>/src/cli/loki.
std::string find_loki_binary() {
  const std::vector<fs::path> candidates = {
      fs::path("/proc/self/exe"),  // placeholder replaced below
  };
  (void)candidates;

  char buf[4096];
  std::string self;
#if defined(__APPLE__)
  uint32_t size = sizeof buf;
  if (_NSGetExecutablePath(buf, &size) == 0) self = buf;
#else
  const ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
  if (n > 0) self.assign(buf, static_cast<size_t>(n));
#endif
  const fs::path dir = fs::path(self).parent_path();
  for (const auto& p : {dir / ".." / ".." / "src" / "cli" / "loki",
                        dir / ".." / "src" / "cli" / "loki", dir / "loki"}) {
    std::error_code ec;
    if (fs::exists(p, ec) && !ec) return fs::weakly_canonical(p).string();
  }
  FAIL("cannot locate loki binary next to " << self);
  return "";
}

// Repo root, found by walking up from this test binary until AGENTS.md and
// scenarios/ both exist.
fs::path repo_root() {
#ifdef LOKI_SOURCE_DIR
  return fs::path(LOKI_SOURCE_DIR);
#endif
  char buf[4096];
  std::string self;
#if defined(__APPLE__)
  uint32_t size = sizeof buf;
  if (_NSGetExecutablePath(buf, &size) == 0) self = buf;
#else
  const ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
  if (n > 0) self.assign(buf, static_cast<size_t>(n));
#endif
  fs::path dir = fs::path(self).parent_path();
  for (int i = 0; i < 6; ++i) {
    std::error_code ec;
    if (fs::exists(dir / "AGENTS.md", ec) && fs::exists(dir / "scenarios", ec)) {
      return fs::weakly_canonical(dir);
    }
    dir = dir / "..";
  }
  FAIL("cannot locate repo root from " << self);
  return "";
}

struct CliResult {
  int exit_code = -1;
  std::string output;
};

CliResult run_cli(const std::vector<std::string>& args) {
  const std::string bin = find_loki_binary();
  std::string cmd = "'" + bin + "'";
  for (const auto& a : args) cmd += " '" + a + "'";
  cmd += " 2>&1";

  FILE* pipe = ::popen(cmd.c_str(), "r");
  REQUIRE(pipe != nullptr);

  // Watchdog so a hung verb cannot stall the whole suite.
  pid_t child = -1;
  struct Kill {
    pid_t pid = -1;
    ~Kill() {
      if (pid > 0 && ::kill(pid, 0) == 0) ::kill(pid, SIGKILL);
    }
  } watchdog{child};

  std::string out;
  char buf[4096];
  while (std::fgets(buf, sizeof buf, pipe)) out += buf;

  const int rc = ::pclose(pipe);
  watchdog.pid = -1;
  CliResult r;
  r.exit_code = WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
  r.output = out;
  return r;
}

std::string write_file(const fs::path& p, const std::string& content) {
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  out << content;
  return p.string();
}

bool output_contains(const CliResult& r, const std::string& needle) {
  return r.output.find(needle) != std::string::npos;
}

const char* kGoodScenario = R"(version: 1
seed: 7
listen: 127.0.0.1:19321
upstream: 127.0.0.1:19320
rules:
  - name: lat
    when:
      every_bytes: 32
    inject:
      latency:
        mean: 1ms
)";

// Fabricates a complete, internally consistent run directory using the same
// core library the reactor/evidence packages use.
std::string fabricate_run_dir(const fs::path& root, bool corrupt_ledger = false) {
  fs::create_directories(root);
  const CompiledScenario sc = compile_scenario(kGoodScenario);

  json::Value m = json::Value::object();
  m.set("loki_version", json::Value::str(LOKI_VERSION_STRING));
  m.set("rng_version", json::Value::i(LOKI_RNG_VERSION));
  m.set("ledger_format_version", json::Value::i(LOKI_LEDGER_FORMAT_VERSION));
  m.set("git_sha", json::Value::str("test"));
  m.set("scenario_hash_hex", json::Value::str(sc.scenario_hash_hex()));
  m.set("seed", json::Value::u(sc.seed));
  m.set("started_at", json::Value::i(0));
  m.set("started_at_iso", json::Value::str("1970-01-01T00:00:00Z"));
  m.set("platform", json::Value::str("test"));
  m.set("kernel", json::Value::str("test"));
  m.set("backend", json::Value::str("test"));
  m.set("mode", json::Value::str("live"));
  write_file(root / "manifest.json", m.dump());

  write_file(root / "scenario.yaml", kGoodScenario);

  FaultDecision d;
  d.event_index = 1;
  d.conn = 1;
  d.dir = Dir::AtoB;
  d.stream_offset = 0;
  d.rule_index = 0;
  d.rule_name = "lat";
  d.kind = FaultKind::Latency;
  d.resolved.set("delay_us", json::Value::u(1000));
  const std::string line = decision_to_json(d).dump();
  write_file(root / "events.jsonl",
             corrupt_ledger ? "{\"event_index\":not-json}\n" : line + "\n");

  write_file(root / "connections.jsonl",
             R"({"conn":1,"bytes_a_to_b":10,"bytes_b_to_a":10})" "\n");

  json::Value s = json::Value::object();
  s.set("connections_total", json::Value::u(1));
  write_file(root / "summary.json", s.dump());
  return root.string();
}

}  // namespace

TEST_CASE("usage errors exit 2", "[cli]") {
  CHECK(run_cli({}).exit_code == 2);
  CHECK(run_cli({"frobnicate"}).exit_code == 2);
  CHECK(run_cli({"validate"}).exit_code == 2);
  CHECK(run_cli({"run", "--bogus-flag", "x"}).exit_code == 2);
  CHECK(run_cli({"inspect"}).exit_code == 2);
  CHECK(run_cli({"replay"}).exit_code == 2);
  CHECK(run_cli({"ctl", "/tmp/x"}).exit_code == 2);          // missing CMD
  CHECK(run_cli({"ctl", "/tmp/x", "teleport"}).exit_code == 2);  // unknown CMD
}

TEST_CASE("help and version exit 0", "[cli]") {
  const CliResult h = run_cli({"--help"});
  CHECK(h.exit_code == 0);
  CHECK(output_contains(h, "loki run SCENARIO.yaml"));
  CHECK(run_cli({"--version"}).exit_code == 0);
}

TEST_CASE("validate accepts a good scenario with exit 0", "[cli]") {
  const fs::path dir = fs::temp_directory_path() / "loki-cli-test" / "validate";
  fs::create_directories(dir);
  const std::string path = write_file(dir / "good.yaml", kGoodScenario);
  const CliResult r = run_cli({"validate", path});
  CHECK(r.exit_code == 0);
  CHECK(output_contains(r, "ok "));
}

TEST_CASE("validate rejects invalid scenarios with exit 3", "[cli]") {
  const fs::path dir = fs::temp_directory_path() / "loki-cli-test" / "validate-bad";
  fs::create_directories(dir);

  SECTION("unknown key") {
    const std::string path =
        write_file(dir / "unknown.yaml", std::string(kGoodScenario) + "surprise: yes\n");
    CHECK(run_cli({"validate", path}).exit_code == 3);
  }
  SECTION("missing inject") {
    const std::string path = write_file(dir / "noinject.yaml",
                                        "version: 1\nseed: 1\nlisten: \":9\"\n"
                                        "upstream: \":9\"\nrules:\n  - name: x\n");
    CHECK(run_cli({"validate", path}).exit_code == 3);
  }
  SECTION("unreadable file") {
    CHECK(run_cli({"validate", (dir / "does-not-exist.yaml").string()}).exit_code == 3);
  }
}

TEST_CASE("live run writes all evidence artifacts then exits 0 on SIGINT", "[cli][slow]") {
  // Short path on purpose: unix socket names cap around 104 chars on macOS,
  // and the control socket lives under the runs root.
  const fs::path runs = "/tmp/loki-cli-runs-live";
  fs::remove_all(runs);

  const std::string bin = find_loki_binary();
  const std::string scenario = (repo_root() / "scenarios" / "basic.yaml").string();

  const pid_t pid = ::fork();
  REQUIRE(pid >= 0);
  if (pid == 0) {
    const std::string runs_arg = runs.string();
    (void)::execl(bin.c_str(), bin.c_str(), "run", scenario.c_str(), "--runs-dir",
                  runs_arg.c_str(), "--full-ledger", static_cast<char*>(nullptr));
    _exit(127);
  }

  // Wait for the run directory to appear, then stop the proxy cleanly.
  fs::path run_dir;
  for (int i = 0; i < 100 && run_dir.empty(); ++i) {
    ::usleep(100000);
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(runs, ec)) {
      if (e.is_directory(ec)) run_dir = e.path();
    }
  }
  REQUIRE(!run_dir.empty());
  ::kill(pid, SIGINT);

  int status = -1;
  for (int i = 0; i < 100; ++i) {
    if (::waitpid(pid, &status, WNOHANG) == pid) break;
    ::usleep(100000);
  }
  REQUIRE(WIFEXITED(status));
  CHECK(WEXITSTATUS(status) == 0);

  for (const char* artifact : {"manifest.json", "scenario.yaml", "scenario.normalized.json",
                               "events.jsonl", "connections.jsonl", "metrics.json",
                               "summary.json"}) {
    INFO("artifact: " << artifact);
    CHECK(fs::exists(run_dir / artifact));
  }
  CHECK(fs::file_size(run_dir / "scenario.yaml") > 0);
}

TEST_CASE("replay check-only validates a consistent run directory", "[cli]") {
  const fs::path root = fs::temp_directory_path() / "loki-cli-test" / "replay-ok";
  fs::remove_all(root);
  const std::string dir = fabricate_run_dir(root / "run-x");
  const CliResult r = run_cli({"replay", dir, "--check-only"});
  CHECK(r.exit_code == 0);
  CHECK(output_contains(r, "check ok"));
}

TEST_CASE("replay detects ledger corruption with exit 5", "[cli]") {
  const fs::path root = fs::temp_directory_path() / "loki-cli-test" / "replay-bad";
  fs::remove_all(root);
  const std::string dir = fabricate_run_dir(root / "run-y", /*corrupt_ledger=*/true);
  const CliResult r = run_cli({"replay", dir, "--check-only"});
  CHECK(r.exit_code == 5);
}

TEST_CASE("replay fails at runtime for non-run directories with exit 4", "[cli]") {
  const fs::path empty = fs::temp_directory_path() / "loki-cli-test" / "empty-dir";
  fs::create_directories(empty);
  CHECK(run_cli({"replay", empty.string(), "--check-only"}).exit_code == 4);
}

TEST_CASE("inspect reports summaries, connections, and event tails", "[cli]") {
  const fs::path root = fs::temp_directory_path() / "loki-cli-test" / "inspect";
  fs::remove_all(root);
  const std::string dir = fabricate_run_dir(root / "run-z");

  const CliResult s = run_cli({"inspect", dir});
  CHECK(s.exit_code == 0);
  CHECK(output_contains(s, "seed:"));

  const CliResult c = run_cli({"inspect", dir, "--connections"});
  CHECK(c.exit_code == 0);
  CHECK(output_contains(c, "\"conn\":1"));

  const CliResult e = run_cli({"inspect", dir, "--events", "--tail", "5"});
  CHECK(e.exit_code == 0);
  CHECK(output_contains(e, "\"lat\""));

  // Missing artifacts are runtime failures.
  const fs::path bare = root / "bare";
  fs::create_directories(bare);
  CHECK(run_cli({"inspect", bare.string()}).exit_code == 4);

  // --tail without --events is a usage error.
  CHECK(run_cli({"inspect", dir, "--tail", "5"}).exit_code == 2);
}

TEST_CASE("ctl against a dead socket exits 4", "[cli]") {
  const fs::path dead = fs::temp_directory_path() / "loki-cli-test" / "dead.sock";
  std::error_code ec;
  fs::remove(dead, ec);
  CHECK(run_cli({"ctl", dead.string(), "status"}).exit_code == 4);

  const fs::path dir = fs::temp_directory_path() / "loki-cli-test" / "ctl-dir";
  fs::create_directories(dir);
  CHECK(run_cli({"ctl", dir.string(), "status"}).exit_code == 4);
}
