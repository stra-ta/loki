// End-to-end integration tests: exercise the loki binary against a real
// echo server over loopback and verify the evidence artifacts.
//
// Assumptions about the CLI (per AGENTS.md exit codes and evidence layout):
//   loki run <scenario.yaml> [--seed N]
//       Runs in the foreground until SIGTERM/SIGINT. Evidence lands under
//       ./runs/<run-id>/ relative to the process working directory.
//   loki replay <run-dir>
//       Ledger replay of a prior run; exit 0 on success, 5 on mismatch.
//
// If the binary is still the scaffold stub, every test SKIPs so ctest stays
// green until the CLI verbs land.

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_predicate.hpp>

#include <cstdint>
#include <cctype>
#include <cstring>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <mach-o/dyld.h>
#include <random>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace std::chrono;
using clk = steady_clock;

namespace {

constexpr int kExitOk = 0;
constexpr auto kWaitTimeout = seconds(15);

std::string self_path() {
  uint32_t size = 0;
  _NSGetExecutablePath(nullptr, &size);
  std::string buf(size, '\0');
  _NSGetExecutablePath(buf.data(), &size);
  buf.resize(std::strlen(buf.c_str()));
  return buf;
}

// Locate the loki binary relative to this test binary
// (build/<preset>/tests/integration/loki_test_integration).
std::string find_loki_bin() {
  if (const char* env = std::getenv("LOKI_BIN"); env && *env) return env;
  std::string p = self_path();
  auto slash = p.find_last_of('/');
  REQUIRE(slash != std::string::npos);
  return p.substr(0, slash) + "/../src/cli/loki";
}

struct RunResult {
  int status = 0;
  std::string out;
  bool signaled() const { return WIFSIGNALED(status); }
  int exit_code() const { return WIFEXITED(status) ? WEXITSTATUS(status) : -1; }
};

RunResult run_capture(const std::string& bin,
                      const std::vector<std::string>& args,
                      const std::string& cwd) {
  RunResult res;
  int out_pipe[2];
  REQUIRE(pipe(out_pipe) == 0);
  pid_t pid = fork();
  REQUIRE(pid >= 0);
  if (pid == 0) {
    dup2(out_pipe[1], STDOUT_FILENO);
    dup2(out_pipe[1], STDERR_FILENO);
    close(out_pipe[0]);
    close(out_pipe[1]);
    if (chdir(cwd.c_str()) != 0) _exit(127);
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(bin.c_str()));
    for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    execv(bin.c_str(), argv.data());
    _exit(127);
  }
  close(out_pipe[1]);
  // Drain child output while it runs.
  char buf[4096];
  ssize_t n;
  while ((n = read(out_pipe[0], buf, sizeof(buf))) > 0) res.out.append(buf, n);
  close(out_pipe[0]);
  int st = 0;
  waitpid(pid, &st, 0);
  res.status = st;
  return res;
}

// A blocking TCP echo server bound to an ephemeral loopback port.
class EchoServer {
 public:
  EchoServer() {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd_ >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    REQUIRE(bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    REQUIRE(getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
    port_ = ntohs(addr.sin_port);
    REQUIRE(listen(fd_, 16) == 0);
    stop_ = false;
    thread_ = std::thread([this] { accept_loop(); });
  }
  ~EchoServer() {
    stop_ = true;
    ::shutdown(fd_, SHUT_RDWR);
    ::close(fd_);
    thread_.join();
  }
  int port() const { return port_; }

 private:
  static void echo_conn(int cfd) {
    char buf[8192];
    ssize_t n;
    while ((n = ::read(cfd, buf, sizeof(buf))) > 0) {
      ssize_t off = 0;
      while (off < n) {
        ssize_t w = ::send(cfd, buf + off, n - off, 0);
        if (w <= 0) { ::close(cfd); return; }
        off += w;
      }
    }
    ::close(cfd);
  }
  void accept_loop() {
    while (!stop_) {
      int cfd = ::accept(fd_, nullptr, nullptr);
      if (cfd < 0) break;
      workers_.emplace_back(echo_conn, cfd);
      // Opportunistic reap.
      for (auto it = workers_.begin(); it != workers_.end();) {
        if (it->joinable()) { it->join(); it = workers_.erase(it); }
        else ++it;
      }
    }
  }
  int fd_ = -1;
  int port_ = 0;
  std::atomic<bool> stop_;
  std::thread thread_;
  std::vector<std::thread> workers_;
};

int free_port() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  REQUIRE(bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
  socklen_t len = sizeof(addr);
  REQUIRE(getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
  int port = ntohs(addr.sin_port);
  ::close(fd);
  return port;
}

std::string temp_dir() {
  char tmpl[] = "/tmp/loki-it-XXXXXX";
  REQUIRE(mkdtemp(tmpl) != nullptr);
  return std::string(tmpl);
}

void write_file(const std::string& path, const std::string& text) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  REQUIRE(f.good());
  f << text;
}

void replace_all(std::string& s, const std::string& from, const std::string& to) {
  size_t pos = 0;
  while ((pos = s.find(from, pos)) != std::string::npos) {
    s.replace(pos, from.size(), to);
    pos += to.size();
  }
}

struct LokiRun {
  pid_t pid = -1;
  std::string cwd;

  void start(const std::string& bin, const std::string& scenario_path,
             std::optional<uint64_t> seed = {}) {
    cwd = temp_dir();
    pid = fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
      std::string log_path = cwd + "/loki-run.log";
      int logfd = open(log_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      dup2(logfd, STDOUT_FILENO);
      dup2(logfd, STDERR_FILENO);
      if (chdir(cwd.c_str()) != 0) _exit(127);
      std::vector<char*> argv;
      argv.push_back(const_cast<char*>(bin.c_str()));
      argv.push_back(const_cast<char*>("run"));
      argv.push_back(const_cast<char*>(scenario_path.c_str()));
      std::string seed_arg;
      if (seed) {
        seed_arg = "--seed=" + std::to_string(*seed);
        argv.push_back(seed_arg.data());
      }
      argv.push_back(nullptr);
      execv(bin.c_str(), argv.data());
      _exit(127);
    }
  }

  void stop() {
    if (pid <= 0) return;
    kill(pid, SIGTERM);
    int st = 0;
    waitpid(pid, &st, 0);
    pid = -1;
  }

  ~LokiRun() { stop(); }
};

bool wait_connectable(int port, clk::time_point deadline) {
  while (clk::now() < deadline) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    ::close(fd);
    if (rc == 0) return true;
    std::this_thread::sleep_for(milliseconds(20));
  }
  return false;
}

// Newest run directory under <cwd>/runs.
std::string newest_run_dir(const std::string& cwd) {
  std::string runs = cwd + "/runs";
  DIR* d = opendir(runs.c_str());
  REQUIRE(d != nullptr);
  std::string best;
  struct dirent* e;
  while ((e = readdir(d)) != nullptr) {
    if (e->d_name[0] == '.') continue;
    std::string full = runs + "/" + e->d_name;
    struct stat st{};
    if (stat(full.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) best = full;
  }
  closedir(d);
  REQUIRE(!best.empty());
  return best;
}

std::string slurp(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  REQUIRE(f.good());
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// Removes the wall-clock field from a decision ledger line. elapsed_us
// records real scheduling time (invariant 1 says wall-clock never affects
// decisions), so two deterministic runs differ in it by construction.
std::string scrub_elapsed(std::string line) {
  const std::string key = "\"elapsed_us\":";
  for (auto pos = line.find(key); pos != std::string::npos;
       pos = line.find(key, pos)) {
    auto digit = pos + key.size();
    while (digit < line.size() &&
           (std::isdigit(static_cast<unsigned char>(line[digit])) ||
            line[digit] == '-')) {
      ++digit;
    }
    if (digit < line.size() && line[digit] == ',') ++digit;
    line.erase(pos, digit - pos);
  }
  return line;
}

bool send_all(int fd, const uint8_t* data, size_t len) {  size_t off = 0;
  while (off < len) {
    ssize_t w = ::send(fd, data + off, len - off, 0);
    if (w <= 0) return false;
    off += static_cast<size_t>(w);
  }
  return true;
}

// Reads exactly len bytes or fails with timeout.
bool recv_all(int fd, uint8_t* dst, size_t len, clk::time_point deadline) {
  size_t got = 0;
  while (got < len) {
    auto now = clk::now();
    if (now >= deadline) return false;
    auto left = duration_cast<milliseconds>(deadline - now);
    timeval tv{left.count() / 1000, static_cast<suseconds_t>((left.count() % 1000) * 1000)};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t r = ::recv(fd, dst + got, len - got, 0);
    if (r <= 0) return false;
    got += static_cast<size_t>(r);
  }
  return true;
}

std::vector<uint8_t> random_bytes(uint64_t seed, size_t len) {
  std::mt19937_64 rng(seed);
  std::vector<uint8_t> v(len);
  size_t i = 0;
  while (i < len) {
    auto word = rng();
    auto* p = reinterpret_cast<const uint8_t*>(&word);
    for (size_t j = 0; j < sizeof(word) && i < len; ++j) v[i++] = p[j];
  }
  return v;
}

// True once the binary supports the run verb; false when still the stub.
bool binary_is_real(const std::string& bin) {
  auto res = run_capture(bin, {}, temp_dir());
  return !(res.out.find("scaffold stub") != std::string::npos ||
           (!res.signaled() && res.exit_code() == 127));
}

}  // namespace

TEST_CASE("e2e: basic passthrough is byte-identical", "[integration][e2e]") {
  auto bin = find_loki_bin();
  if (!binary_is_real(bin)) { SKIP("loki CLI not implemented yet"); }

  EchoServer server;
  int listen_port = free_port();
  std::string dir = temp_dir();
  std::string scenario = dir + "/basic.yaml";
  auto text = slurp("/Users/nguyenhuyvu/Projects/loki/scenarios/basic.yaml");
  replace_all(text, "17601", std::to_string(listen_port));
  replace_all(text, "17600", std::to_string(server.port()));
  write_file(scenario, text);

  LokiRun loki;
  loki.start(bin, scenario, /*seed=*/1);
  REQUIRE(wait_connectable(listen_port, clk::now() + kWaitTimeout));

  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(listen_port);
  REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  auto payload = random_bytes(0xAB1E, 64 * 1024);
  auto deadline = clk::now() + kWaitTimeout;
  REQUIRE(send_all(fd, payload.data(), payload.size()));
  std::vector<uint8_t> echoed(payload.size());
  REQUIRE(recv_all(fd, echoed.data(), echoed.size(), deadline));
  REQUIRE(memcmp(payload.data(), echoed.data(), payload.size()) == 0);

  ::close(fd);
  loki.stop();

  // Evidence completeness (invariant 10): every artifact exists under the
  // run directory. All carry content except events.jsonl, which is empty
  // for a rule-free scenario because no fault decisions were made.
  auto run_dir = newest_run_dir(loki.cwd);
  for (const char* f : {"manifest.json", "scenario.yaml",
                        "scenario.normalized.json", "events.jsonl",
                        "connections.jsonl", "metrics.json", "summary.json"}) {
    INFO("checking " << f);
    REQUIRE((!slurp(run_dir + "/" + f).empty() ||
             std::string(f) == "events.jsonl"));
  }
}

TEST_CASE("e2e: fragment preserves byte stream", "[integration][e2e]") {
  auto bin = find_loki_bin();
  if (!binary_is_real(bin)) { SKIP("loki CLI not implemented yet"); }

  EchoServer server;
  int listen_port = free_port();
  std::string dir = temp_dir();
  std::string scenario = dir + "/fragment.yaml";
  auto text = slurp("/Users/nguyenhuyvu/Projects/loki/scenarios/fragment.yaml");
  replace_all(text, "17611", std::to_string(listen_port));
  replace_all(text, "17610", std::to_string(server.port()));
  write_file(scenario, text);

  LokiRun loki;
  loki.start(bin, scenario, /*seed=*/7);
  REQUIRE(wait_connectable(listen_port, clk::now() + kWaitTimeout));

  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(listen_port);
  REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  auto payload = random_bytes(0xFACE, 64 * 1024);
  auto deadline = clk::now() + kWaitTimeout;
  REQUIRE(send_all(fd, payload.data(), payload.size()));
  std::vector<uint8_t> echoed(payload.size());
  REQUIRE(recv_all(fd, echoed.data(), echoed.size(), deadline));
  // Fragmentation must reshape chunks without altering any byte.
  REQUIRE(memcmp(payload.data(), echoed.data(), payload.size()) == 0);

  ::close(fd);
  loki.stop();
}

TEST_CASE("e2e: latency delays delivery within expected bounds", "[integration][e2e]") {
  auto bin = find_loki_bin();
  if (!binary_is_real(bin)) { SKIP("loki CLI not implemented yet"); }

  EchoServer server;
  int listen_port = free_port();
  std::string dir = temp_dir();
  std::string scenario = dir + "/latency.yaml";
  auto text = slurp("/Users/nguyenhuyvu/Projects/loki/scenarios/latency.yaml");
  replace_all(text, "17621", std::to_string(listen_port));
  replace_all(text, "17620", std::to_string(server.port()));
  write_file(scenario, text);

  LokiRun loki;
  loki.start(bin, scenario, /*seed=*/11);
  REQUIRE(wait_connectable(listen_port, clk::now() + kWaitTimeout));

  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(listen_port);
  REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  // One small message: RTT = sum of both directions, each 50ms +/- 20ms,
  // so [60ms, 140ms] theoretically; bounds are padded for scheduling slack.
  const uint8_t msg[] = "ping";
  auto t0 = clk::now();
  REQUIRE(send_all(fd, msg, 4));
  uint8_t back[4];
  REQUIRE(recv_all(fd, back, 4, t0 + seconds(5)));
  auto elapsed = duration_cast<milliseconds>(clk::now() - t0);
  REQUIRE(elapsed >= milliseconds(45));
  REQUIRE(elapsed <= milliseconds(600));

  ::close(fd);
  loki.stop();
}

TEST_CASE("e2e: throttle caps throughput", "[integration][e2e]") {
  auto bin = find_loki_bin();
  if (!binary_is_real(bin)) { SKIP("loki CLI not implemented yet"); }

  EchoServer server;
  int listen_port = free_port();
  std::string dir = temp_dir();
  std::string scenario = dir + "/throttle.yaml";
  auto text = slurp("/Users/nguyenhuyvu/Projects/loki/scenarios/throttle.yaml");
  replace_all(text, "17631", std::to_string(listen_port));
  replace_all(text, "17630", std::to_string(server.port()));
  write_file(scenario, text);

  LokiRun loki;
  loki.start(bin, scenario, /*seed=*/13);
  REQUIRE(wait_connectable(listen_port, clk::now() + kWaitTimeout));

  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(listen_port);
  REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  // 64 KiB at 50 KiB/s minus the 8 KiB burst takes >= ~1.12s.
  constexpr size_t kLen = 64 * 1024;
  auto payload = random_bytes(0x7E00, kLen);
  auto t0 = clk::now();
  REQUIRE(send_all(fd, payload.data(), payload.size()));
  std::vector<uint8_t> echoed(kLen);
  REQUIRE(recv_all(fd, echoed.data(), kLen, t0 + seconds(30)));
  auto elapsed = duration_cast<milliseconds>(clk::now() - t0);
  REQUIRE(memcmp(payload.data(), echoed.data(), kLen) == 0);
  REQUIRE(elapsed >= milliseconds(800));   // clearly throttled
  REQUIRE(elapsed <= seconds(25));         // not stalled

  ::close(fd);
  loki.stop();
}

TEST_CASE("e2e: blackhole discards traffic then recovers", "[integration][e2e]") {
  auto bin = find_loki_bin();
  if (!binary_is_real(bin)) { SKIP("loki CLI not implemented yet"); }

  EchoServer server;
  int listen_port = free_port();
  std::string dir = temp_dir();
  std::string scenario = dir + "/blackhole.yaml";
  auto text = slurp("/Users/nguyenhuyvu/Projects/loki/scenarios/blackhole.yaml");
  replace_all(text, "17651", std::to_string(listen_port));
  replace_all(text, "17650", std::to_string(server.port()));
  write_file(scenario, text);

  LokiRun loki;
  loki.start(bin, scenario, /*seed=*/19);
  REQUIRE(wait_connectable(listen_port, clk::now() + kWaitTimeout));

  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(listen_port);
  REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  // During the 1s discard window the echo never comes back.
  const uint8_t lost[] = "swallowed";
  REQUIRE(send_all(fd, lost, sizeof(lost) - 1));
  uint8_t sink[16];
  auto t0 = clk::now();
  bool got_something = recv_all(fd, sink, sizeof(lost) - 1, t0 + seconds(2));
  REQUIRE_FALSE(got_something);

  // After the window expires fresh traffic flows normally.
  std::this_thread::sleep_for(seconds(2));
  const uint8_t alive[] = "recovered";
  auto t1 = clk::now();
  REQUIRE(send_all(fd, alive, sizeof(alive) - 1));
  uint8_t back[sizeof(alive) - 1];
  REQUIRE(recv_all(fd, back, sizeof(back), t1 + seconds(5)));
  REQUIRE(memcmp(back, alive, sizeof(back)) == 0);

  ::close(fd);
  loki.stop();
}

TEST_CASE("e2e: deterministic replay produces identical ledger", "[integration][e2e][replay]") {
  auto bin = find_loki_bin();
  if (!binary_is_real(bin)) { SKIP("loki CLI not implemented yet"); }

  auto make_run = [&](const std::string& tag) {
    EchoServer server;
    int listen_port = free_port();
    std::string dir = temp_dir();
    std::string scenario = dir + "/fragment.yaml";
    auto text = slurp("/Users/nguyenhuyvu/Projects/loki/scenarios/fragment.yaml");
    replace_all(text, "17611", std::to_string(listen_port));
    replace_all(text, "17610", std::to_string(server.port()));
    write_file(scenario, text);

    LokiRun loki;
    loki.start(bin, scenario, /*seed=*/7);
    REQUIRE(wait_connectable(listen_port, clk::now() + kWaitTimeout));

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(listen_port);
    REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    // Identical workload in both runs so observed event order repeats.
    auto payload = random_bytes(0xFACE, 16 * 1024);
    REQUIRE(send_all(fd, payload.data(), payload.size()));
    std::vector<uint8_t> echoed(payload.size());
    REQUIRE(recv_all(fd, echoed.data(), echoed.size(),
                     clk::now() + kWaitTimeout));
    REQUIRE(memcmp(payload.data(), echoed.data(), payload.size()) == 0);
    ::close(fd);

    // Let the engine settle before SIGTERM so both ledgers are complete.
    std::this_thread::sleep_for(milliseconds(200));
    loki.stop();

    auto run_dir = newest_run_dir(loki.cwd);
    auto events = slurp(run_dir + "/events.jsonl");
    INFO(tag << " events bytes: " << events.size());
    REQUIRE(!events.empty());
    // Scrub wall-clock fields before comparing: identical seeds and
    // workloads must yield identical decision ledgers modulo timing.
    std::string scrubbed;
    size_t start = 0;
    while (start < events.size()) {
      auto nl = events.find('\n', start);
      if (nl == std::string::npos) nl = events.size();
      scrubbed += scrub_elapsed(events.substr(start, nl - start));
      scrubbed += '\n';
      start = nl + 1;
    }
    return scrubbed;
  };

  auto a = make_run("run-A");
  auto b = make_run("run-B");
  // Same seed + same workload => byte-identical decision ledgers.
  REQUIRE(a == b);
}

TEST_CASE("e2e: ledger replay re-applies recorded decisions", "[integration][e2e][replay]") {
  auto bin = find_loki_bin();
  if (!binary_is_real(bin)) { SKIP("loki CLI not implemented yet"); }

  // Produce one recorded run.
  EchoServer server;
  int listen_port = free_port();
  std::string dir = temp_dir();
  std::string scenario = dir + "/fragment.yaml";
  auto text = slurp("/Users/nguyenhuyvu/Projects/loki/scenarios/fragment.yaml");
  replace_all(text, "17611", std::to_string(listen_port));
  replace_all(text, "17610", std::to_string(server.port()));
  write_file(scenario, text);

  LokiRun loki;
  loki.start(bin, scenario, /*seed=*/7);
  REQUIRE(wait_connectable(listen_port, clk::now() + kWaitTimeout));

  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(listen_port);
  REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  auto payload = random_bytes(0xFACE, 16 * 1024);
  REQUIRE(send_all(fd, payload.data(), payload.size()));
  std::vector<uint8_t> echoed(payload.size());
  REQUIRE(recv_all(fd, echoed.data(), echoed.size(), clk::now() + kWaitTimeout));
  ::close(fd);
  std::this_thread::sleep_for(milliseconds(200));
  loki.stop();

  auto run_dir = newest_run_dir(loki.cwd);

  // Ledger replay re-enacts the recorded scenario live on the recorded
  // listen endpoint (the scenario hash pins it). Positions are consumed
  // only by real traffic, so the identical workload must be replayed
  // against it. The proxy terminates itself once every decision is
  // consumed and all connections drain.
  LokiRun replayer;
  replayer.cwd = temp_dir();
  {
    pid_t pid = fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
      std::string log_path = replayer.cwd + "/loki-run.log";
      int logfd = open(log_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      dup2(logfd, STDOUT_FILENO);
      dup2(logfd, STDERR_FILENO);
      if (chdir(replayer.cwd.c_str()) != 0) _exit(127);
      std::vector<char*> argv;
      argv.push_back(const_cast<char*>(bin.c_str()));
      argv.push_back(const_cast<char*>("replay"));
      argv.push_back(const_cast<char*>(run_dir.c_str()));
      argv.push_back(nullptr);
      execv(bin.c_str(), argv.data());
      _exit(127);
    }
    replayer.pid = pid;
  }
  REQUIRE(wait_connectable(listen_port, clk::now() + kWaitTimeout));

  {
    int rfd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(rfd >= 0);
    sockaddr_in raddr{};
    raddr.sin_family = AF_INET;
    raddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    raddr.sin_port = htons(listen_port);
    REQUIRE(::connect(rfd, reinterpret_cast<sockaddr*>(&raddr), sizeof(raddr)) == 0);
    REQUIRE(send_all(rfd, payload.data(), payload.size()));
    std::vector<uint8_t> r_echoed(payload.size());
    REQUIRE(recv_all(rfd, r_echoed.data(), r_echoed.size(),
                     clk::now() + kWaitTimeout));
    REQUIRE(memcmp(payload.data(), r_echoed.data(), payload.size()) == 0);
    ::close(rfd);
  }

  // Self-termination: bounded wait for exit, then check the verdict.
  int replay_status = -1;
  auto replay_deadline = clk::now() + kWaitTimeout;
  while (clk::now() < replay_deadline) {
    pid_t got = waitpid(replayer.pid, &replay_status, WNOHANG);
    if (got == replayer.pid) break;
    std::this_thread::sleep_for(milliseconds(50));
  }
  replayer.pid = -1;  // reaped (or explicitly killed below)
  RunResult replay;
  replay.status = replay_status;
  REQUIRE(!replay.signaled());
  // Exit 0 ok, 5 mismatch; anything else means broken CLI behavior.
  REQUIRE((replay.exit_code() == kExitOk || replay.exit_code() == 5));
  // The workload above reproduces positions exactly, so replay must succeed.
  REQUIRE(replay.exit_code() == kExitOk);
}
