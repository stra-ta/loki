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
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
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
// Waits until the proxy's run directory appears. The UDP reactor binds the
// listener before creating the run store, so an existing run directory means
// the first datagram cannot race the bind (a datagram sent before the bind
// is dropped and its ICMP error surfaces later as ECONNREFUSED).
void wait_for_proxy_ready(const std::string& runs_root) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  std::error_code ec;
  for (;;) {
    for (const auto& entry : std::filesystem::directory_iterator(runs_root, ec)) {
      if (entry.is_directory()) return;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      FAIL("proxy run directory never appeared under " << runs_root);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
}

// Sends one datagram, retrying while the kernel reports a pending
// ECONNREFUSED. A connected UDP socket learns about a port that was
// unreachable when an earlier datagram was sent; on Linux the ICMP error
// surfaces on the next send. The tests start the proxy in a thread and send
// immediately, so the very first datagram can race the listener bind.
void send_udp_retry(int fd, const void* data, std::size_t len) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  for (;;) {
    errno = 0;
    const sock::IoResult w = sock::write_some(fd, data, len);
    if (w.n == static_cast<long>(len)) return;
    if (errno == ECONNREFUSED && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      continue;
    }
    FAIL("udp send failed: n=" << w.n << " errno=" << errno);
  }
}

void run_udp_echo_impl(int fd, std::atomic<bool>* stop,
                       std::atomic<std::uint64_t>* received) {
  while (!stop->load()) {
    sockaddr_storage from{};
    socklen_t flen = sizeof from;
    char buf[65536];
    sock::IoResult r = sock::recvfrom_some(fd, buf, sizeof buf, &from, &flen);
    if (r.would_block) {
      ::usleep(2000);
      continue;
    }
    if (r.n < 0) break;
    if (received != nullptr) ++*received;
    sock::sendto_some(fd, buf, static_cast<std::size_t>(r.n), from, flen);
  }
}

void run_udp_echo(int fd, std::atomic<bool>* stop) {
  run_udp_echo_impl(fd, stop, nullptr);
}

void run_udp_echo_counted(int fd, std::atomic<bool>* stop,
                          std::atomic<std::uint64_t>* received) {
  run_udp_echo_impl(fd, stop, received);
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
  ProcessResult on_engine_timer(const ScheduledAction&, TimeUs) override { return {}; }

 private:
  Scheduler* sched_ = nullptr;
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


bool receive_udp_datagram(int fd, std::vector<std::byte>& out,
                          std::chrono::steady_clock::time_point deadline) {
  while (std::chrono::steady_clock::now() < deadline) {
    struct pollfd pfd{fd, POLLIN, 0};
    if (::poll(&pfd, 1, 100) <= 0 || (pfd.revents & POLLIN) == 0) continue;
    std::array<std::byte, 65536> buf{};
    const sock::IoResult r = sock::read_some(fd, buf.data(), buf.size());
    if (r.n < 0) return false;
    out.assign(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(r.n));
    return true;
  }
  return false;
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
  wait_for_proxy_ready(cfg.runs_root);
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
    send_udp_retry(cfd, sent.data(), kLen);
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

TEST_CASE("udp preserves a zero-length datagram", "[udp]") {
  const Endpoint listen_ep = pick_udp_port();
  const int echo_fd = sock::udp_bind(Endpoint{"127.0.0.1", 0});
  const std::uint16_t echo_port = sock::local_port(echo_fd);
  REQUIRE(echo_port != 0);
  std::atomic<bool> echo_stop{false};
  std::atomic<std::uint64_t> received{0};
  std::thread echo_thread(run_udp_echo_counted, echo_fd, &echo_stop, &received);

  CompiledScenario sc;
  sc.listen = listen_ep;
  sc.upstream = Endpoint{"127.0.0.1", echo_port};
  sc.seed = 2;

  ReactorConfig cfg;
  cfg.scenario = sc;
  cfg.runs_root = "/tmp/loki-udp-test-zero";
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
      std::fprintf(stderr, "udp zero-length run failed: %s\n", e.what());
      proxy_failed.store(true);
    }
  });

  wait_for_proxy_ready(cfg.runs_root);
  const int cfd = sock::udp_connect(listen_ep);
  REQUIRE(cfd >= 0);
  bool echoed = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (!echoed && std::chrono::steady_clock::now() < deadline) {
    // A zero-length write is a real zero-length datagram on SOCK_DGRAM.
    send_udp_retry(cfd, "", 0);
    struct pollfd pfd{cfd, POLLIN, 0};
    if (::poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
      char marker = 0;
      const sock::IoResult r = sock::read_some(cfd, &marker, sizeof marker);
      echoed = r.n == 0 && r.closed;
    }
  }
  REQUIRE(echoed);
  CHECK(received.load() >= 1);

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

  wait_for_proxy_ready(cfg.runs_root);
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
    send_udp_retry(cfd, sent.data(), kLen);
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

TEST_CASE("udp duplicate emits two datagrams and records the decision", "[udp]") {
  const Endpoint listen_ep = pick_udp_port();
  const int echo_fd = sock::udp_bind(Endpoint{"127.0.0.1", 0});
  const std::uint16_t echo_port = sock::local_port(echo_fd);
  REQUIRE(echo_port != 0);
  std::atomic<bool> echo_stop{false};
  std::thread echo_thread(run_udp_echo, echo_fd, &echo_stop);

  const std::string yaml =
      "version: 1\n"
      "seed: 101\n"
      "listen: " + listen_ep.to_string() + "\n" +
      "upstream: 127.0.0.1:" + std::to_string(echo_port) + "\n" +
      "rules:\n"
      "  - name: duplicate\n"
      "    inject:\n"
      "      duplicate:\n"
      "        count: 2\n";
  CompiledScenario sc = compile_scenario(yaml);

  ReactorConfig cfg;
  cfg.scenario = sc;
  cfg.runs_root = "/tmp/loki-udp-test-duplicate";
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
      std::fprintf(stderr, "udp duplicate run failed: %s\n", e.what());
      proxy_failed.store(true);
    }
  });

  wait_for_proxy_ready(cfg.runs_root);
  const int cfd = sock::udp_connect(listen_ep);
  REQUIRE(cfd >= 0);
  const std::byte value{0x2a};
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  std::vector<std::byte> first;
  std::vector<std::byte> second;
  while (first.empty() && std::chrono::steady_clock::now() < deadline) {
    send_udp_retry(cfd, &value, 1);
    (void)receive_udp_datagram(cfd, first, deadline);
  }
  REQUIRE(first.size() == 1);
  REQUIRE(first[0] == value);
  REQUIRE(receive_udp_datagram(cfd, second, deadline));
  REQUIRE(second.size() == 1);
  CHECK(second[0] == value);

  REQUIRE(::kill(::getpid(), SIGINT) == 0);
  proxy_thread.join();
  CHECK(!proxy_failed.load());
  CHECK(events_have_kind(cfg.runs_root, "duplicate"));

  echo_stop.store(true);
  echo_thread.join();
  ::close(echo_fd);
  ::close(cfd);
}

TEST_CASE("udp reorder permutes datagrams as a window", "[udp]") {
  const Endpoint listen_ep = pick_udp_port();
  const int echo_fd = sock::udp_bind(Endpoint{"127.0.0.1", 0});
  const std::uint16_t echo_port = sock::local_port(echo_fd);
  REQUIRE(echo_port != 0);
  std::atomic<bool> echo_stop{false};
  std::thread echo_thread(run_udp_echo, echo_fd, &echo_stop);

  const std::string yaml =
      "version: 1\n"
      "seed: 202\n"
      "listen: " + listen_ep.to_string() + "\n" +
      "upstream: 127.0.0.1:" + std::to_string(echo_port) + "\n" +
      "rules:\n"
      "  - name: reorder\n"
      "    inject:\n"
      "      reorder:\n"
      "        depth: 3\n"
      "        max_hold: 100ms\n";
  CompiledScenario sc = compile_scenario(yaml);

  ReactorConfig cfg;
  cfg.scenario = sc;
  cfg.runs_root = "/tmp/loki-udp-test-reorder";
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
      std::fprintf(stderr, "udp reorder run failed: %s\n", e.what());
      proxy_failed.store(true);
    }
  });

  wait_for_proxy_ready(cfg.runs_root);
  const int cfd = sock::udp_connect(listen_ep);
  REQUIRE(cfd >= 0);
  for (std::uint8_t value = 1; value <= 3; ++value) {
    send_udp_retry(cfd, &value, 1);
  }

  std::vector<std::uint8_t> values;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (values.size() < 3 && std::chrono::steady_clock::now() < deadline) {
    std::vector<std::byte> datagram;
    if (!receive_udp_datagram(cfd, datagram, deadline)) break;
    REQUIRE(datagram.size() == 1);
    values.push_back(static_cast<std::uint8_t>(datagram[0]));
  }
  REQUIRE(values.size() == 3);
  std::sort(values.begin(), values.end());
  CHECK(values == std::vector<std::uint8_t>{1, 2, 3});

  REQUIRE(::kill(::getpid(), SIGINT) == 0);
  proxy_thread.join();
  CHECK(!proxy_failed.load());
  CHECK(events_have_kind(cfg.runs_root, "reorder"));

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

  wait_for_proxy_ready(cfg.runs_root);
  const int cfd = sock::udp_connect(listen_ep);
  REQUIRE(cfd >= 0);
  constexpr std::size_t kLen = 64;
  std::vector<std::byte> sent(kLen);
  for (std::size_t i = 0; i < kLen; ++i) sent[i] = static_cast<std::byte>(0xAB);

  std::vector<std::byte> got(kLen, static_cast<std::byte>(0xFF));
  std::size_t got_n = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (got_n < kLen && std::chrono::steady_clock::now() < deadline) {
    send_udp_retry(cfd, sent.data(), kLen);
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

  wait_for_proxy_ready(cfg.runs_root);
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
    send_udp_retry(cfd, sent.data(), kLen);
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

