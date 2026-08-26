// Reactor end-to-end passthrough test. Uses a local fake mutator defined here
// (make_pass_through_engine was removed from engine.hpp by the faults package).

#include <catch2/catch_test_macros.hpp>
#include <loki/reactor.hpp>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <exception>
#include <filesystem>
#include <span>
#include <thread>
#include <vector>

#include "../src/transport/socket_util.hpp"

using namespace loki;

namespace {
// Diagnose silent terminates: print the active exception type if any.
struct TerminateReporter {
  TerminateReporter() {
    std::set_terminate([]() {
      if (std::current_exception()) {
        try { throw; }
        catch (const std::exception& e) { std::fprintf(stderr, "[terminate] std::exception: %s\n", e.what()); }
        catch (...) { std::fprintf(stderr, "[terminate] non-std exception\n"); }
      } else {
        std::fprintf(stderr, "[terminate] no active exception\n");
      }
      std::abort();
    });
  }
};
const TerminateReporter g_terminate_reporter;
}  // namespace

namespace {

// Minimal pass-through mutator: echoes chunks unmodified, no decisions.
// Satisfies the MUST-schedule-connect invariant from on_connection_accepted.
class PassthroughMutator final : public INetworkMutator {
 public:
  void bind(Scheduler* scheduler, TimeUs epoch) override {
    sched_ = scheduler;
    epoch_ = epoch;
  }

  ProcessResult process_read(const StreamKey& key, std::uint64_t chunk_logical_offset,
                             std::span<const std::byte> data,
                             const StreamStats& /*stats*/, TimeUs now) override {
    ProcessResult pr;
    OutPiece p;
    p.payload.assign(data.begin(), data.end());
    p.logical_offset = chunk_logical_offset;
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
  bool listener_enabled(TimeUs) override { return listener_enabled_; }

  void set_decision_sink(DecisionSink sink) override { sink_ = std::move(sink); }
  const std::vector<FaultDecision>& lifecycle_decisions() const override { return none_; }

  bool manual_action(ManualAction action, ConnId conn, TimeUs now) override {
    switch (action) {
      case ManualAction::Pause:
        listener_enabled_ = false;
        return true;
      case ManualAction::Resume:
        listener_enabled_ = true;
        sched_->push(now, ActResumeListener{});
        return true;
      case ManualAction::InjectReset:
        sched_->push(now, ActReset{conn});
        return true;
    }
    return false;
  }

  ProcessResult on_engine_timer(const ScheduledAction&, TimeUs) override { return {}; }

 private:
  Scheduler* sched_ = nullptr;
  TimeUs epoch_ = 0;
  DecisionSink sink_;
  std::vector<FaultDecision> none_;
  std::atomic<bool> listener_enabled_{true};
};

// Echo server: echoes everything back until the peer closes, then loops on
// nonblocking accepts until asked to stop.
void run_echo_server(int lfd, std::atomic<bool>* stop) {
  while (!stop->load()) {
    int fd = ::accept(lfd, nullptr, nullptr);  // listener is nonblocking
    if (fd < 0) {
      usleep(5000);
      continue;
    }
    // macOS accepts inherit O_NONBLOCK; the echo loop below is blocking.
    const int fl = ::fcntl(fd, F_GETFL, 0);
    if (fl >= 0) (void)::fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    char buf[4096];
    while (true) {
      ssize_t n = ::recv(fd, buf, sizeof buf, 0);
      if (n <= 0) break;
      ssize_t off = 0;
      while (off < n) {
        ssize_t w = ::send(fd, buf + off, static_cast<std::size_t>(n - off), 0);
        if (w <= 0) break;
        off += w;
      }
    }
    ::close(fd);
  }
}

Endpoint pick_listen_port() {  // Endpoint rejects port 0: probe candidates
  for (int port = 47901; port <= 47920; ++port) {
    try {
      int fd = sock::tcp_listen(Endpoint{"127.0.0.1", static_cast<std::uint16_t>(port)});
      ::close(fd);
      return Endpoint{"127.0.0.1", static_cast<std::uint16_t>(port)};
    } catch (const std::exception&) {
      // in use: next candidate
    }
  }
  throw std::runtime_error("no free listen port in 47901..47920");
}

}  // namespace

TEST_CASE("reactor passes 64 KiB through end to end", "[reactor]") {
  const Endpoint listen_ep = pick_listen_port();

  // Upstream echo server on an ephemeral port.
  const int echo_lfd = sock::tcp_listen(Endpoint{"127.0.0.1", 0});
  const std::uint16_t echo_port = sock::local_port(echo_lfd);
  REQUIRE(echo_port != 0);
  std::atomic<bool> echo_stop{false};
  std::thread echo_thread(run_echo_server, echo_lfd, &echo_stop);

  CompiledScenario sc;
  sc.listen = listen_ep;
  sc.upstream = Endpoint{"127.0.0.1", echo_port};
  sc.seed = 1;
  sc.limits = ProxyLimits{};  // defaults

  ReactorConfig cfg;
  cfg.scenario = sc;
  // Short path on purpose: unix socket names cap around 104 chars on macOS.
  cfg.runs_root = "/tmp/loki-reactor-test";
  std::filesystem::remove_all(cfg.runs_root);

  std::atomic<bool> started{false};
  std::atomic<std::uint64_t> res_conns{0}, res_ab{0}, res_ba{0}, res_dec{0};
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
      ReactorSummary summary = run_proxy(cfg, factory);
      res_conns.store(summary.connections_total);
      res_ab.store(summary.bytes_a_to_b);
      res_ba.store(summary.bytes_b_to_a);
      res_dec.store(summary.decisions_logged);
    } catch (const std::exception& e) {
      std::fprintf(stderr, "run_proxy failed: %s\n", e.what());
      proxy_failed.store(true);
    }
    started.store(true);
  });

  // Client through the proxy once the listener accepts.
  int cfd = -1;
  for (int i = 0; i < 500 && cfd < 0; ++i) {
    const int candidate = sock::tcp_connect(listen_ep);
    if (candidate >= 0) {
      struct pollfd pfd{candidate, POLLOUT, 0};
      const int ready = ::poll(&pfd, 1, 20);
      if (ready > 0 && (pfd.revents & POLLOUT) != 0 &&
          sock::connect_error(candidate) == 0) {
        cfd = candidate;
        break;
      }
      ::close(candidate);
    }
    usleep(10000);
  }
  REQUIRE(cfd >= 0);

  constexpr std::size_t kTotal = 64 * 1024;
  std::vector<std::byte> sent(kTotal);
  for (std::size_t i = 0; i < kTotal; ++i) sent[i] = static_cast<std::byte>(i & 0xFF);

  std::vector<std::byte> got(kTotal);
  std::size_t written = 0, read_back = 0;
  while (written < kTotal || read_back < kTotal) {
    if (written < kTotal) {
      sock::IoResult w = sock::write_some(cfd, sent.data() + written, kTotal - written);
      if (w.n > 0) written += static_cast<std::size_t>(w.n);
      else if (!w.would_block) {
        std::fprintf(stderr, "write failed errno=%d (%s)\n", errno, std::strerror(errno));
        break;
      }
    }
    if (read_back < kTotal) {
      sock::IoResult r = sock::read_some(cfd, got.data() + read_back, kTotal - read_back);
      if (r.n > 0) read_back += static_cast<std::size_t>(r.n);
      else if (!r.would_block) {
        std::fprintf(stderr, "read failed errno=%d (%s)\n", errno, std::strerror(errno));
        break;
      }
    }
  }
  REQUIRE(written == kTotal);
  REQUIRE(read_back == kTotal);
  CHECK(std::memcmp(sent.data(), got.data(), kTotal) == 0);

  // Stop the proxy gracefully via SIGINT to our own pid.
  REQUIRE(::kill(::getpid(), SIGINT) == 0);
  proxy_thread.join();
  CHECK(started.load());
  CHECK(res_conns.load() == 1);
  CHECK(res_ab.load() == kTotal);
  CHECK(res_ba.load() == kTotal);
  CHECK(res_dec.load() == 0);
  ::close(cfd);

  // Shut the echo server down and join.
  echo_stop.store(true);
  echo_thread.join();
  ::close(echo_lfd);
}
