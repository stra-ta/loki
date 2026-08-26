// UDP transport end-to-end test: a datagram proxy with a UDP echo upstream.

#include <catch2/catch_test_macros.hpp>
#include <loki/engine.hpp>
#include <loki/reactor.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <span>
#include <string>
#include <thread>

#include "../src/transport/socket_util.hpp"

using namespace loki;

namespace {

// UDP echo server: bounces every datagram back to its sender. The buffer must
// be large enough for the largest test datagram (the proxy delivers full
// datagrams); a too-small buffer causes EMSGSIZE drops on macOS/BSD.
void run_udp_echo(int fd, std::atomic<bool>* stop) {
  while (!stop->load()) {
    sockaddr_storage from{};
    socklen_t flen = sizeof from;
    char buf[65536];
    sock::IoResult r = sock::recvfrom_some(fd, buf, sizeof buf, &from, &flen);
    if (r.would_block || r.n <= 0) {
      if (r.n < 0) break;
      ::usleep(2000);
      continue;
    }
    if (r.n == 0) continue;
    sock::sendto_some(fd, buf, static_cast<std::size_t>(r.n), from, flen);
  }
}

// Probe a free UDP port by binding then immediately closing.
Endpoint pick_udp_port() {
  for (int port = 47931; port <= 47950; ++port) {
    try {
      const int fd = sock::udp_bind(Endpoint{"127.0.0.1", static_cast<std::uint16_t>(port)});
      ::close(fd);
      return Endpoint{"127.0.0.1", static_cast<std::uint16_t>(port)};
    } catch (const std::exception&) {
      // in use: next candidate
    }
  }
  throw std::runtime_error("no free udp port in 47931..47950");
}

class PassthroughMutator final : public INetworkMutator {
 public:
  void bind(Scheduler* scheduler, TimeUs) override { sched_ = scheduler; }
  ProcessResult process_read(const StreamKey& key, std::uint64_t off,
                             std::span<const std::byte> data, const StreamStats&,
                             TimeUs now) override {
    ProcessResult pr;
    OutPiece p;
    p.payload.assign(data.begin(), data.end());
    p.logical_offset = off;
    p.send_at_us = now;
    p.immediate = true;
    pr.pieces.push_back(std::move(p));
    (void)key;
    return pr;
  }
  void on_connection_accepted(ConnId conn, TimeUs now) override {
    sched_->push(now, ActConnectUpstream{conn});
  }
  void on_connection_established(ConnId, TimeUs) override {}
  void on_connection_closed(ConnId, TimeUs, ClosedReason) override {}
  void on_data_flushed(const StreamKey&, std::uint64_t, TimeUs) override {}
  bool read_enabled(const StreamKey&, TimeUs) override { return true; }
  bool listener_enabled(TimeUs) override { return true; }
  void set_decision_sink(DecisionSink sink) override { sink_ = std::move(sink); }
  const std::vector<FaultDecision>& lifecycle_decisions() const override { return none_; }
  bool manual_action(ManualAction action, ConnId conn, TimeUs now) override {
    if (action == ManualAction::InjectReset) sched_->push(now, ActReset{conn});
    return true;
  }
  ProcessResult on_engine_timer(const ScheduledAction&, TimeUs) override { return {}; }

 private:
  Scheduler* sched_ = nullptr;
  DecisionSink sink_;
  std::vector<FaultDecision> none_;
};

// Read the lone run's events.jsonl produced under runs_root (the test wipes the
// dir first, so exactly one run exists). Used to prove the fault engine
// actually emitted decisions rather than silently passing through.
std::string read_events_jsonl(const std::string& runs_root) {
  namespace fs = std::filesystem;
  for (const auto& e : fs::directory_iterator(runs_root)) {
    if (e.is_directory()) {
      std::ifstream f((e.path() / "events.jsonl").string());
      std::stringstream ss;
      ss << f.rdbuf();
      return ss.str();
    }
  }
  return "";
}

bool events_have_kind(const std::string& runs_root, const std::string& kind) {
  const std::string needle = "\"kind\":\"" + kind + "\"";
  return read_events_jsonl(runs_root).find(needle) != std::string::npos;
}

}  // namespace

TEST_CASE("udp proxies a datagram end to end", "[udp]") {
  const Endpoint listen_ep = pick_udp_port();

  const int echo_fd = sock::udp_bind(Endpoint{"127.0.0.1", 0});
  const std::uint16_t echo_port = sock::local_port(echo_fd);
  REQUIRE(echo_port != 0);
  std::atomic<bool> echo_stop{false};
  std::thread echo_thread(run_udp_echo, echo_fd, &echo_stop);

  CompiledScenario sc;
  sc.listen = listen_ep;
  sc.upstream = Endpoint{"127.0.0.1", echo_port};
  sc.seed = 1;
  sc.limits = ProxyLimits{};

  ReactorConfig cfg;
  cfg.scenario = sc;
  cfg.runs_root = "/tmp/loki-udp-test";
  cfg.transport = TransportMode::Udp;
  std::filesystem::remove_all(cfg.runs_root);

  std::atomic<bool> proxy_failed{false};
  std::thread proxy_thread([&]() {
    MutatorFactory factory = [](const CompiledScenario& scenario, Scheduler& sched,
                                TimeUs epoch) -> std::unique_ptr<INetworkMutator> {
      auto m = std::make_unique<PassthroughMutator>();
      m->bind(&sched, epoch);
      (void)scenario;
      return m;
    };
    try {
      run_proxy(cfg, factory);
    } catch (const std::exception& e) {
      std::fprintf(stderr, "udp run_proxy failed: %s\n", e.what());
      proxy_failed.store(true);
    }
  });

  // Connected UDP client to the proxy's listen endpoint.
  const int cfd = sock::udp_connect(listen_ep);
  REQUIRE(cfd >= 0);

  constexpr std::size_t kLen = 512;
  std::vector<std::byte> sent(kLen);
  for (std::size_t i = 0; i < kLen; ++i) sent[i] = static_cast<std::byte>(i & 0xFF);

  // A connected-UDP send "succeeds" even before the proxy has bound its listen
  // socket, and that early datagram is silently dropped. Resend inside the read
  // loop so the echo eventually arrives once the proxy is listening.
  std::vector<std::byte> got(kLen);
  std::size_t got_n = 0;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (got_n < kLen && std::chrono::steady_clock::now() < deadline) {
    sock::write_some(cfd, sent.data(), kLen);
    struct pollfd pfd{cfd, POLLIN, 0};
    if (::poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
      sock::IoResult r = sock::read_some(cfd, got.data() + got_n, kLen - got_n);
      if (r.n > 0) got_n += static_cast<std::size_t>(r.n);
      // ignore transient hard errors (e.g. ICMP port-unreachable); resend
    }
  }
  REQUIRE(got_n == kLen);
  REQUIRE(std::memcmp(sent.data(), got.data(), kLen) == 0);

  REQUIRE(::kill(::getpid(), SIGINT) == 0);
  proxy_thread.join();
  CHECK(!proxy_failed.load());

  echo_stop.store(true);
  echo_thread.join();
  ::close(echo_fd);
  ::close(cfd);
}

TEST_CASE("udp applies faults with the real live engine", "[udp]") {
  const Endpoint listen_ep = pick_udp_port();

  const int echo_fd = sock::udp_bind(Endpoint{"127.0.0.1", 0});
  const std::uint16_t echo_port = sock::local_port(echo_fd);
  REQUIRE(echo_port != 0);
  std::atomic<bool> echo_stop{false};
  std::thread echo_thread(run_udp_echo, echo_fd, &echo_stop);

  // 20ms one-way latency in both directions via the production fault engine.
  const std::string yaml =
      "version: 1\n"
      "seed: 99\n"
      "listen: " + listen_ep.to_string() + "\n" +
      "upstream: 127.0.0.1:" + std::to_string(echo_port) + "\n" +
      "rules:\n"
      "  - name: slow\n"
      "    inject:\n"
      "      latency:\n"
      "        mean: 20ms\n";
  CompiledScenario sc = compile_scenario(yaml);

  ReactorConfig cfg;
  cfg.scenario = sc;
  cfg.runs_root = "/tmp/loki-udp-test-engine";
  cfg.transport = TransportMode::Udp;
  std::filesystem::remove_all(cfg.runs_root);

  std::atomic<bool> proxy_failed{false};
  std::thread proxy_thread([&]() {
    MutatorFactory factory = [](const CompiledScenario& scenario, Scheduler& sched,
                                TimeUs epoch) -> std::unique_ptr<INetworkMutator> {
      auto engine = make_live_fault_engine(scenario);
      engine->bind(&sched, epoch);
      return engine;
    };
    try {
      run_proxy(cfg, factory);
    } catch (const std::exception& e) {
      std::fprintf(stderr, "udp live run_proxy failed: %s\n", e.what());
      proxy_failed.store(true);
    }
  });

  const int cfd = sock::udp_connect(listen_ep);
  REQUIRE(cfd >= 0);

  constexpr std::size_t kLen = 256;
  std::vector<std::byte> sent(kLen);
  for (std::size_t i = 0; i < kLen; ++i) sent[i] = static_cast<std::byte>((i * 7) & 0xFF);

  // A connected-UDP send "succeeds" even before the proxy has bound its listen
  // socket; that early datagram is silently dropped. Resend inside the read loop
  // so the echo eventually arrives once the proxy is listening.
  std::vector<std::byte> got(kLen);
  std::size_t got_n = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (got_n < kLen && std::chrono::steady_clock::now() < deadline) {
    sock::write_some(cfd, sent.data(), kLen);
    struct pollfd pfd{cfd, POLLIN, 0};
    if (::poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
      sock::IoResult r = sock::read_some(cfd, got.data() + got_n, kLen - got_n);
      if (r.n > 0) got_n += static_cast<std::size_t>(r.n);
      // ignore transient hard errors (e.g. ICMP port-unreachable); resend
    }
  }
  REQUIRE(got_n == kLen);
  REQUIRE(std::memcmp(sent.data(), got.data(), kLen) == 0);

  REQUIRE(::kill(::getpid(), SIGINT) == 0);
  proxy_thread.join();
  CHECK(!proxy_failed.load());
  // Prove the engine actually applied the latency fault (not a no-op passthrough).
  CHECK(events_have_kind(cfg.runs_root, "latency"));

  echo_stop.store(true);
  echo_thread.join();
  ::close(echo_fd);
  ::close(cfd);
}

TEST_CASE("udp corrupt rule transforms the datagram via the live engine", "[udp]") {
  const Endpoint listen_ep = pick_udp_port();
  const int echo_fd = sock::udp_bind(Endpoint{"127.0.0.1", 0});
  const std::uint16_t echo_port = sock::local_port(echo_fd);
  REQUIRE(echo_port != 0);
  std::atomic<bool> echo_stop{false};
  std::thread echo_thread(run_udp_echo, echo_fd, &echo_stop);

  const std::string yaml =
      "version: 1\n"
      "seed: 7\n"
      "listen: " + listen_ep.to_string() + "\n" +
      "upstream: 127.0.0.1:" + std::to_string(echo_port) + "\n" +
      "rules:\n"
      "  - name: scramble\n"
      "    inject:\n"
      "      corrupt:\n"
      "        mode: overwrite\n"
      "        offset: 0\n"
      "        value: 0\n";
  CompiledScenario sc = compile_scenario(yaml);

  ReactorConfig cfg;
  cfg.scenario = sc;
  cfg.runs_root = "/tmp/loki-udp-test-corrupt";
  cfg.transport = TransportMode::Udp;
  std::filesystem::remove_all(cfg.runs_root);

  std::atomic<bool> proxy_failed{false};
  std::thread proxy_thread([&]() {
    MutatorFactory factory = [](const CompiledScenario& scenario, Scheduler& sched,
                                TimeUs epoch) -> std::unique_ptr<INetworkMutator> {
      auto engine = make_live_fault_engine(scenario);
      engine->bind(&sched, epoch);
      return engine;
    };
    try {
      run_proxy(cfg, factory);
    } catch (const std::exception& e) {
      std::fprintf(stderr, "udp corrupt run failed: %s\n", e.what());
      proxy_failed.store(true);
    }
  });

  const int cfd = sock::udp_connect(listen_ep);
  REQUIRE(cfd >= 0);
  constexpr std::size_t kLen = 64;
  std::vector<std::byte> sent(kLen);
  for (std::size_t i = 0; i < kLen; ++i) sent[i] = static_cast<std::byte>(0xAB);

  std::vector<std::byte> got(kLen, static_cast<std::byte>(0xFF));
  std::size_t got_n = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (got_n < kLen && std::chrono::steady_clock::now() < deadline) {
    sock::write_some(cfd, sent.data(), kLen);
    struct pollfd pfd{cfd, POLLIN, 0};
    if (::poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
      sock::IoResult r = sock::read_some(cfd, got.data() + got_n, kLen - got_n);
      if (r.n > 0) got_n += static_cast<std::size_t>(r.n);
    }
  }
  REQUIRE(got_n == kLen);
  // First byte was overwritten to 0; the rest are untouched 0xAB.
  REQUIRE(static_cast<std::uint8_t>(got[0]) == 0);
  bool rest_ok = true;
  for (std::size_t i = 1; i < kLen; ++i)
    if (static_cast<std::uint8_t>(got[i]) != 0xAB) rest_ok = false;
  REQUIRE(rest_ok);

  REQUIRE(::kill(::getpid(), SIGINT) == 0);
  proxy_thread.join();
  CHECK(!proxy_failed.load());
  CHECK(events_have_kind(cfg.runs_root, "corrupt"));

  echo_stop.store(true);
  echo_thread.join();
  ::close(echo_fd);
  ::close(cfd);
}

TEST_CASE("udp echoes a large datagram intact", "[udp]") {
  const Endpoint listen_ep = pick_udp_port();
  const int echo_fd = sock::udp_bind(Endpoint{"127.0.0.1", 0});
  const std::uint16_t echo_port = sock::local_port(echo_fd);
  REQUIRE(echo_port != 0);
  std::atomic<bool> echo_stop{false};
  std::thread echo_thread(run_udp_echo, echo_fd, &echo_stop);

  CompiledScenario sc;
  sc.listen = listen_ep;
  sc.upstream = Endpoint{"127.0.0.1", echo_port};
  sc.seed = 1;
  sc.limits = ProxyLimits{};

  ReactorConfig cfg;
  cfg.scenario = sc;
  cfg.runs_root = "/tmp/loki-udp-test-large";
  cfg.transport = TransportMode::Udp;
  std::filesystem::remove_all(cfg.runs_root);

  std::atomic<bool> proxy_failed{false};
  std::thread proxy_thread([&]() {
    MutatorFactory factory = [](const CompiledScenario& scenario, Scheduler& sched,
                                TimeUs epoch) -> std::unique_ptr<INetworkMutator> {
      auto m = std::make_unique<PassthroughMutator>();
      m->bind(&sched, epoch);
      (void)scenario;
      return m;
    };
    try {
      run_proxy(cfg, factory);
    } catch (const std::exception& e) {
      std::fprintf(stderr, "udp large run failed: %s\n", e.what());
      proxy_failed.store(true);
    }
  });

  const int cfd = sock::udp_connect(listen_ep);
  REQUIRE(cfd >= 0);
  // 8000 bytes sits above the common 1500-byte MTU (exercises IP fragmentation)
  // yet under the OS per-datagram send cap (macOS net.inet.udp.maxdgram ~9216),
  // so the round trip is realistic on every platform the proxy builds on.
  constexpr std::size_t kLen = 8000;
  std::vector<std::byte> sent(kLen);
  for (std::size_t i = 0; i < kLen; ++i) sent[i] = static_cast<std::byte>(i & 0xFF);

  std::vector<std::byte> got(kLen);
  std::size_t got_n = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (got_n < kLen && std::chrono::steady_clock::now() < deadline) {
    sock::write_some(cfd, sent.data(), kLen);
    struct pollfd pfd{cfd, POLLIN, 0};
    if (::poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
      sock::IoResult r = sock::read_some(cfd, got.data() + got_n, kLen - got_n);
      if (r.n > 0) got_n += static_cast<std::size_t>(r.n);
    }
  }
  REQUIRE(got_n == kLen);
  REQUIRE(std::memcmp(sent.data(), got.data(), kLen) == 0);

  REQUIRE(::kill(::getpid(), SIGINT) == 0);
  proxy_thread.join();
  CHECK(!proxy_failed.load());

  echo_stop.store(true);
  echo_thread.join();
  ::close(echo_fd);
  ::close(cfd);
}

TEST_CASE("udp idle_timeout tears down a mapping and logs the decision", "[udp]") {
  const Endpoint listen_ep = pick_udp_port();
  const int echo_fd = sock::udp_bind(Endpoint{"127.0.0.1", 0});
  const std::uint16_t echo_port = sock::local_port(echo_fd);
  REQUIRE(echo_port != 0);
  std::atomic<bool> echo_stop{false};
  std::thread echo_thread(run_udp_echo, echo_fd, &echo_stop);

  const std::string yaml =
      "version: 1\n"
      "seed: 5\n"
      "listen: " + listen_ep.to_string() + "\n" +
      "upstream: 127.0.0.1:" + std::to_string(echo_port) + "\n" +
      "rules:\n"
      "  - name: idle\n"
      "    inject:\n"
      "      idle_timeout:\n"
      "        idle: 10ms\n"
      "        action: reset\n";
  CompiledScenario sc = compile_scenario(yaml);

  ReactorConfig cfg;
  cfg.scenario = sc;
  cfg.runs_root = "/tmp/loki-udp-test-idle";
  cfg.transport = TransportMode::Udp;
  std::filesystem::remove_all(cfg.runs_root);

  std::atomic<bool> proxy_failed{false};
  std::thread proxy_thread([&]() {
    MutatorFactory factory = [](const CompiledScenario& scenario, Scheduler& sched,
                                TimeUs epoch) -> std::unique_ptr<INetworkMutator> {
      auto engine = make_live_fault_engine(scenario);
      engine->bind(&sched, epoch);
      return engine;
    };
    try {
      run_proxy(cfg, factory);
    } catch (const std::exception& e) {
      std::fprintf(stderr, "udp idle run failed: %s\n", e.what());
      proxy_failed.store(true);
    }
  });

  const int cfd = sock::udp_connect(listen_ep);
  REQUIRE(cfd >= 0);
  constexpr std::size_t kLen = 32;
  std::vector<std::byte> sent(kLen, static_cast<std::byte>(0x55));

  // One exchange to open the mapping, then go silent past the idle threshold.
  std::vector<std::byte> got(kLen);
  std::size_t got_n = 0;
  auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (got_n < kLen && std::chrono::steady_clock::now() < dl) {
    sock::write_some(cfd, sent.data(), kLen);
    struct pollfd pfd{cfd, POLLIN, 0};
    if (::poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
      sock::IoResult r = sock::read_some(cfd, got.data() + got_n, kLen - got_n);
      if (r.n > 0) got_n += static_cast<std::size_t>(r.n);
    }
  }
  REQUIRE(got_n == kLen);
  ::usleep(80000);  // > idle threshold; the engine should fire idle_timeout

  REQUIRE(::kill(::getpid(), SIGINT) == 0);
  proxy_thread.join();
  CHECK(!proxy_failed.load());
  CHECK(events_have_kind(cfg.runs_root, "idle_timeout"));

  echo_stop.store(true);
  echo_thread.join();
  ::close(echo_fd);
  ::close(cfd);
}
