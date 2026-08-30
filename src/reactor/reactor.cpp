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

#include <loki/reactor.hpp>

#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <utility>
#include <vector>

#include <loki/control.hpp>
#include <loki/evidence.hpp>
#include <loki/json.hpp>
#include <loki/poller.hpp>
#include <loki/scheduler.hpp>
#include <loki/version.hpp>

#include "../config/validate_transport.hpp"
#include "../transport/socket_util.hpp"
#include "../transport/tls_client_hello.hpp"

#ifdef LOKI_GIT_SHA
#define LOKI_SHA LOKI_GIT_SHA
#else
#define LOKI_SHA "unknown"
#endif

namespace loki {

namespace {

constexpr std::size_t kChunkCap = 16 * 1024;
constexpr std::uint64_t kSignalConnMarker = 0xFFFFFFFFull;

TimeUs steady_now_us(const std::chrono::steady_clock::time_point& epoch) {
  const auto delta = std::chrono::steady_clock::now() - epoch;
  return std::chrono::duration_cast<std::chrono::microseconds>(delta).count();
}

WallUs wall_now_us() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// One buffered span of transformed bytes awaiting write toward the far leg.
struct OutBlob {
  std::vector<std::byte> payload;
  std::uint64_t logical_offset = 0;
  std::size_t sent = 0;  // partial-write progress
};

struct DirectionState {
  std::deque<OutBlob> out;           // ordered queue toward the far leg
  std::uint64_t pending_bytes = 0;   // unsent payload bytes in `out`
  std::uint64_t deferred_bytes = 0;  // bytes still inside scheduled ActDeliver
  StreamStats stats{};               // pristine logical stream counters
  bool read_armed = false;
  bool bp_paused = false;            // reads disarmed because pending >= bound
  bool write_armed = false;
  bool rx_shutdown = false;          // SHUT_RD done on the source leg
  bool eof_seen = false;             // source leg observed FIN
  bool fin_relayed = false;          // SHUT_WR done on the far leg
};

struct ConnState {
  ConnId conn = 0;
  std::string peer;
  WallUs opened_at = 0;
  int down_fd = -1;
  int up_fd = -1;
  bool connecting = false;
  bool established = false;
  bool downstream_eof_pending = false;  // client FIN seen before upstream ready
  DirectionState dir[2];                // indexed by Dir: [AtoB, BtoA]

  // TLS-aware tunneling: SNI is extracted from the client's ClientHello by
  // inspecting (not decrypting) the A->B byte stream. `sni_done` marks that the
  // ClientHello decision is settled (found / absent / not-TLS); `sni_stage`
  // buffers bytes until the parser can decide; `sni` holds the result.
  bool sni_done = false;
  std::vector<std::byte> sni_stage;
  std::string sni;
};

Dir inbound_dir(LegSide s) { return s == LegSide::Down ? Dir::AtoB : Dir::BtoA; }
Dir outbound_dir(LegSide s) { return s == LegSide::Up ? Dir::AtoB : Dir::BtoA; }

LegSide source_side(Dir d) { return d == Dir::AtoB ? LegSide::Down : LegSide::Up; }
LegSide far_side(Dir d) { return d == Dir::AtoB ? LegSide::Up : LegSide::Down; }

int& leg_fd(ConnState& c, LegSide s) { return s == LegSide::Down ? c.down_fd : c.up_fd; }

int source_fd(ConnState& c, Dir d) { return leg_fd(c, source_side(d)); }
int far_fd(ConnState& c, Dir d) { return leg_fd(c, far_side(d)); }

DirectionState& dir_of(ConnState& c, Dir d) { return c.dir[static_cast<int>(d)]; }

Token leg_token(LegSide s, ConnId conn) {
  const FdKind k = s == LegSide::Down ? FdKind::Downstream : FdKind::Upstream;
  return Token{k, conn};
}

json::Value connection_record(ConnId conn, const std::string& peer,
                              WallUs opened_at, ClosedReason reason,
                              std::uint64_t bytes_a_to_b,
                              std::uint64_t bytes_b_to_a,
                              const std::string& sni) {
  json::Value rec = json::Value::object();
  rec.set("connection", json::Value::u(conn));
  rec.set("peer", json::Value::str(peer));
  rec.set("opened_at_us", json::Value::u(static_cast<std::uint64_t>(opened_at)));
  rec.set("closed_at_us",
          json::Value::u(static_cast<std::uint64_t>(wall_now_us())));
  rec.set("reason", json::Value::str(closed_reason_name(reason)));
  rec.set("bytes_a_to_b", json::Value::u(bytes_a_to_b));
  rec.set("bytes_b_to_a", json::Value::u(bytes_b_to_a));
  rec.set("sni", json::Value::str(sni));
  return rec;
}

// ---------------------------------------------------------------------------
// Signal self-pipe: the handler writes one byte; the loop observes readiness.
// ---------------------------------------------------------------------------

int g_signal_write_fd = -1;

extern "C" void loki_signal_handler(int) {
  if (g_signal_write_fd >= 0) {
    const char b = 1;
    ssize_t ignored = ::write(g_signal_write_fd, &b, 1);
    (void)ignored;
  }
}

}  // namespace

// ---------------------------------------------------------------------------

class Reactor {
 public:
  ReactorSummary run(const ReactorConfig& config, MutatorFactory& factory);

 private:
  void arm_read(ConnState& c, Dir d);
  void disarm_read(ConnState& c, Dir d);
  void sync_leg_events(ConnState& c, LegSide s);
  void enqueue_piece(ConnState& c, Dir d, OutPiece piece, TimeUs now);
  void emit_pieces(ConnState& c, Dir d, ProcessResult result, TimeUs now);
  void flush_direction(ConnState& c, Dir d, TimeUs now);
  void read_leg(ConnState& c, Dir d, TimeUs now);
  void handle_eof(ConnState& c, Dir d, TimeUs now);
  void rst_teardown(ConnState& c, ClosedReason reason, TimeUs now);
  bool graceful_teardown_if_done(ConnState& c, TimeUs now);
  void log_decision(FaultDecision d);

  json::Value metrics_json() const;

  // -- state -----------------------------------------------------------------
  Poller* poller_ = nullptr;
  Scheduler* sched_ = nullptr;
  RunStore* store_ = nullptr;
  INetworkMutator* mutator_ = nullptr;
  const CompiledScenario* scenario_ = nullptr;
  std::map<ConnId, ConnState> conns_;  // keyed by ordinal for sorted iteration
  ConnId next_conn_ = 0;
  bool accepts_resumed_ = true;        // cleared by ActResumeListener
  bool stop_requested_ = false;
  ReactorSummary summary_{};
  std::map<std::uint32_t, std::uint64_t> rule_firings_;  // sampling bookkeeping
};

// Re-arm poller interest for one leg from current direction flags:
// reads come from the inbound direction, writes serve the outbound direction.
void Reactor::sync_leg_events(ConnState& c, LegSide s) {
  const int fd = leg_fd(c, s);
  if (fd < 0) return;
  DirectionState& in = dir_of(c, inbound_dir(s));
  DirectionState& out = dir_of(c, outbound_dir(s));
  PollEvents ev = PNone;
  if (in.read_armed && !in.rx_shutdown && !in.eof_seen) ev = ev | PRead;
  if (out.write_armed) ev = ev | PWrite;
  (void)poller_->mod(fd, leg_token(s, c.conn).raw(), ev);
}

void Reactor::arm_read(ConnState& c, Dir d) {
  DirectionState& ds = dir_of(c, d);
  if (ds.read_armed || source_fd(c, d) < 0) return;
  ds.read_armed = true;
  sync_leg_events(c, source_side(d));
}

void Reactor::disarm_read(ConnState& c, Dir d) {
  DirectionState& ds = dir_of(c, d);
  if (!ds.read_armed) return;
  ds.read_armed = false;
  sync_leg_events(c, source_side(d));
}

void Reactor::enqueue_piece(ConnState& c, Dir d, OutPiece piece, TimeUs now) {
  DirectionState& ds = dir_of(c, d);

  // Common path: an immediate piece with no older bytes can go straight to
  // the established far socket. This avoids constructing an OutBlob and a
  // second vector ownership transition for the usual passthrough case.
  const int fd = far_fd(c, d);
  if (ds.out.empty() && !piece.payload.empty() && fd >= 0 && !c.connecting) {
    const std::size_t size = piece.payload.size();
    const sock::IoResult w = sock::write_some(fd, piece.payload.data(), size);
    if (w.n == static_cast<long>(size)) {
      mutator_->on_data_flushed(StreamKey{c.conn, d}, size, now);
      flush_direction(c, d, now);  // backpressure release and teardown checks
      return;
    }
    if (w.n > 0) {
      const std::size_t sent = static_cast<std::size_t>(w.n);
      mutator_->on_data_flushed(StreamKey{c.conn, d}, sent, now);
      OutBlob blob;
      blob.logical_offset = piece.logical_offset;
      blob.payload = std::move(piece.payload);
      blob.sent = sent;
      ds.pending_bytes += blob.payload.size() - sent;
      ds.out.push_back(std::move(blob));
      flush_direction(c, d, now);
      return;
    }
    // EAGAIN and hard errors fall through to the existing queue path. The
    // latter keeps the current lifecycle behavior for a subsequent event.
  }

  OutBlob blob;
  blob.logical_offset = piece.logical_offset;
  blob.payload = std::move(piece.payload);
  ds.pending_bytes += blob.payload.size();
  ds.out.push_back(std::move(blob));
  flush_direction(c, d, now);
}

void Reactor::emit_pieces(ConnState& c, Dir d, ProcessResult result, TimeUs now) {
  for (FaultDecision& dec : result.decisions) log_decision(std::move(dec));
  for (OutPiece& p : result.pieces) {
    if (p.immediate || p.send_at_us <= now) {
      enqueue_piece(c, d, std::move(p), now);
    } else {
      DirectionState& ds = dir_of(c, d);
      ds.deferred_bytes += p.payload.size();
      sched_->push(p.send_at_us, ActDeliver{StreamKey{c.conn, d},
                                            std::move(p.payload),
                                            p.logical_offset});
    }
  }
}

void Reactor::flush_direction(ConnState& c, Dir d, TimeUs now) {
  DirectionState& ds = dir_of(c, d);
  const int fd = far_fd(c, d);
  // Far leg not established yet: keep bytes queued; they flush once the
  // upstream connect completes. Writing to a socket that is still connecting
  // is unsafe on kqueue (macOS): a write issued mid-connect followed by a
  // WRITE->READ filter transition makes the READ filter never report, hanging
  // the connection. Always wait for the connect to finish.
  if (fd >= 0 && !c.connecting) {
    std::uint64_t flushed = 0;
    while (!ds.out.empty()) {
      OutBlob& front = ds.out.front();
      const std::size_t remain = front.payload.size() - front.sent;
      sock::IoResult w =
          sock::write_some(fd, front.payload.data() + front.sent, remain);
      if (w.n > 0) {
        front.sent += static_cast<std::size_t>(w.n);
        ds.pending_bytes -= static_cast<std::uint64_t>(w.n);
        flushed += static_cast<std::uint64_t>(w.n);
        if (front.sent == front.payload.size()) ds.out.pop_front();
        continue;
      }
      if (w.would_block) {
        if (!ds.write_armed) {
          ds.write_armed = true;
          sync_leg_events(c, far_side(d));
        }
        break;
      }
      break;  // hard error: lifecycle paths clean up
    }
    if (flushed > 0) mutator_->on_data_flushed(StreamKey{c.conn, d}, flushed, now);
  }
  // Backpressure release: re-arm reads once drained below the bound.
  if (ds.bp_paused &&
      ds.pending_bytes + ds.deferred_bytes <
          scenario_->limits.pending_bytes_per_direction) {
    ds.bp_paused = false;
    if (source_fd(c, d) >= 0) arm_read(c, d);
  }
  graceful_teardown_if_done(c, now);
}

void Reactor::log_decision(FaultDecision d) {
  const LedgerMode mode = d.rule_index < scenario_->rules.size()
                              ? scenario_->rules[d.rule_index].ledger
                              : LedgerMode::Full;
  switch (mode) {
    case LedgerMode::Full:
      store_->events().append(d);
      break;
    case LedgerMode::Counts:
      store_->events().note_counts(d.kind, 1);
      break;
    case LedgerMode::SampleN: {
      const std::uint32_t sample_n =
          std::max<std::uint32_t>(1, scenario_->rules[d.rule_index].sample_n);
      const std::uint64_t n = ++rule_firings_[d.rule_index];
      if (n % sample_n == 0) {
        store_->events().append(d);
      } else {
        store_->events().note_counts(d.kind, 1);
      }
      break;
    }
  }
  ++summary_.decisions_logged;
}

void Reactor::read_leg(ConnState& c, Dir d, TimeUs now) {
  DirectionState& ds = dir_of(c, d);
  const int fd = source_fd(c, d);
  if (fd < 0 || ds.rx_shutdown || ds.eof_seen) return;
  char buf[kChunkCap];
  while (!stop_requested_) {
    sock::IoResult r = sock::read_some(fd, buf, sizeof buf);
    if (r.would_block || r.n <= 0) {
      if (r.closed) handle_eof(c, d, now);
      return;
    }
     const std::size_t n = static_cast<std::size_t>(r.n);
     // TLS-aware tunneling: inspect (never decrypt) the client's ClientHello to
     // extract SNI so fault rules can match `when.sni`. Buffered until the
     // parser can decide; the bytes are still forwarded verbatim below.
     if (d == Dir::AtoB && !c.sni_done) {
       const std::byte* base = reinterpret_cast<const std::byte*>(buf);
       if (n > loki::tls::kMaxClientHelloBytes -
                   std::min(c.sni_stage.size(), loki::tls::kMaxClientHelloBytes)) {
         // Keep a malicious or unusual prefix from growing the per-connection
         // inspection buffer without bound. The stream remains transparent.
         c.sni_done = true;
       } else {
         c.sni_stage.insert(c.sni_stage.end(), base, base + n);
         std::string extracted;
         const loki::tls::ClientHelloStatus st = loki::tls::parse_client_hello_sni(
             std::span<const std::byte>(c.sni_stage.data(), c.sni_stage.size()),
             extracted);
         if (st == loki::tls::ClientHelloStatus::Found) {
           c.sni = std::move(extracted);
           c.sni_done = true;
           mutator_->on_connection_sni(c.conn, c.sni, now);
         } else if (st == loki::tls::ClientHelloStatus::Incomplete) {
           if (c.sni_stage.size() >= loki::tls::kMaxClientHelloBytes) c.sni_done = true;
         } else {
           // NotTls or NoSni: no usable SNI for this connection.
           c.sni_done = true;
         }
       }
     }
     // Offset invariant: offset of this chunk's first pristine byte.
    const StreamStats stats_before = ds.stats;  // passed BY VALUE
    ProcessResult pr = mutator_->process_read(
        StreamKey{c.conn, d}, stats_before.bytes_seen,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), n),
        stats_before, now);
    ds.stats.bytes_seen += n;
    ds.stats.chunks_seen += 1;
    if (d == Dir::AtoB) {
      summary_.bytes_a_to_b += n;
    } else {
      summary_.bytes_b_to_a += n;
    }
    emit_pieces(c, d, std::move(pr), now);
    if (graceful_teardown_if_done(c, now)) return;
    // Backpressure: bound reached stops reading the source socket.
    if (ds.pending_bytes + ds.deferred_bytes >=
        scenario_->limits.pending_bytes_per_direction) {
      ds.bp_paused = true;
      disarm_read(c, d);
      return;
    }
  }
}

void Reactor::handle_eof(ConnState& c, Dir d, TimeUs now) {
  DirectionState& ds = dir_of(c, d);
  ds.eof_seen = true;
  disarm_read(c, d);
  // FIN relay: propagate EOF toward the far leg once that leg exists.
  const int ffd = far_fd(c, d);
  if (ffd >= 0 && !c.connecting) {
    sock::shutdown_write(ffd);
    DirectionState& out = dir_of(c, d);  // d's far leg carries d outbound
    out.write_armed = false;
    out.fin_relayed = true;
    sync_leg_events(c, far_side(d));
  } else if (c.connecting) {
    c.downstream_eof_pending = true;
  }
  graceful_teardown_if_done(c, now);
}

bool Reactor::graceful_teardown_if_done(ConnState& c, TimeUs now) {
  // Full teardown only when both write sides are shut AND no pending or
  // deferred data remains anywhere in this connection.
  if (!(dir_of(c, Dir::AtoB).eof_seen && dir_of(c, Dir::BtoA).eof_seen)) {
    return false;
  }
  for (const int i : {0, 1}) {
    const DirectionState& ds = c.dir[i];
    if (!ds.out.empty() || ds.pending_bytes > 0 || ds.deferred_bytes > 0) {
      return false;
    }
  }
  const ClosedReason reason = c.dir[static_cast<int>(Dir::AtoB)].eof_seen
                                  ? ClosedReason::ClientClosed
                                  : ClosedReason::ServerClosed;
  if (c.down_fd >= 0) {
    (void)poller_->del(c.down_fd);
    ::close(c.down_fd);
    c.down_fd = -1;
  }
  if (c.up_fd >= 0) {
    (void)poller_->del(c.up_fd);
    ::close(c.up_fd);
    c.up_fd = -1;
  }
  sched_->drop_connection(c.conn);
  store_->log_connection(connection_record(
      c.conn, c.peer, c.opened_at, reason, c.dir[0].stats.bytes_seen,
      c.dir[1].stats.bytes_seen, c.sni));
  mutator_->on_connection_closed(c.conn, now, reason);
  conns_.erase(c.conn);
  return true;
}

void Reactor::rst_teardown(ConnState& c, ClosedReason reason, TimeUs now) {
  // RST discards pending immediately on both legs.
  if (c.down_fd >= 0) {
    (void)poller_->del(c.down_fd);
    sock::rst_close(c.down_fd);
    c.down_fd = -1;
  }
  if (c.up_fd >= 0) {
    (void)poller_->del(c.up_fd);
    sock::rst_close(c.up_fd);
    c.up_fd = -1;
  }
  sched_->drop_connection(c.conn);
  store_->log_connection(connection_record(
      c.conn, c.peer, c.opened_at, reason, c.dir[0].stats.bytes_seen,
      c.dir[1].stats.bytes_seen, c.sni));
  mutator_->on_connection_closed(c.conn, now, reason);
  conns_.erase(c.conn);
}

json::Value Reactor::metrics_json() const {
  json::Value v = json::Value::object();
  v.set("connections_total", json::Value::u(summary_.connections_total));
  v.set("refused_total", json::Value::u(summary_.refused_total));
  v.set("active_connections", json::Value::u(conns_.size()));
  v.set("bytes_a_to_b", json::Value::u(summary_.bytes_a_to_b));
  v.set("bytes_b_to_a", json::Value::u(summary_.bytes_b_to_a));
  v.set("decisions_logged", json::Value::u(summary_.decisions_logged));
  v.set("wall_us", json::Value::u(static_cast<std::uint64_t>(summary_.wall_us)));
  return v;
}

ReactorSummary Reactor::run(const ReactorConfig& config, MutatorFactory& factory) {
  scenario_ = &config.scenario;
  const auto epoch = std::chrono::steady_clock::now();
  const WallUs started_wall = wall_now_us();

  // Bind the listener FIRST: clients may dial the moment run_proxy starts,
  // and a refused early connect is unrecoverable for them.
  const int listen_fd = sock::tcp_listen(config.scenario.listen);
 
  // --- evidence run directory ----------------------------------------------
  ManifestInfo info;
  info.loki_version = LOKI_VERSION_STRING;
  info.git_sha = LOKI_SHA;
  info.scenario_hash_hex = config.scenario.scenario_hash_hex();
  info.seed = config.scenario.seed;
  info.started_at = started_wall;
  struct utsname un {};
  if (::uname(&un) == 0) {
    info.platform = std::string(un.sysname) + " " + un.machine;
    info.kernel = un.release;
  }
  auto poller = make_poller();
  poller_ = poller.get();
  info.backend = poller->backend_name();
  switch (config.mode) {
    case RunMode::Live: info.mode = "live"; break;
    case RunMode::SeedReplay: info.mode = "seed-replay"; break;
    case RunMode::LedgerReplay: info.mode = "ledger-replay"; break;
  }
  RunStore store =
      RunStore::create(config.runs_root, info, "",
                       normalized_json(config.scenario));
  store_ = &store;

  // --- scheduler + mutator ---------------------------------------------------
  Scheduler scheduler;
  sched_ = &scheduler;
  auto mutator = factory(config.scenario, scheduler, 0);
  mutator_ = mutator.get();
  mutator_->set_decision_sink(
      [this](FaultDecision d) { log_decision(std::move(d)); });

  // --- signal self-pipe ------------------------------------------------------
  int sig_fds[2];
  if (::pipe(sig_fds) != 0) throw std::runtime_error("reactor: pipe failed");
  sock::set_nonblock_cloexec(sig_fds[0]);
  sock::set_nonblock_cloexec(sig_fds[1]);
  g_signal_write_fd = sig_fds[1];
  struct sigaction sa {};
  sa.sa_handler = loki_signal_handler;
  sigemptyset(&sa.sa_mask);  // exposed as a macro on macOS; no :: prefix
  sa.sa_flags = 0;  // no SA_RESTART: poll must observe interruption too
  ::sigaction(SIGINT, &sa, nullptr);
  ::sigaction(SIGTERM, &sa, nullptr);
  const std::uint64_t signal_token =
      Token{FdKind::Listener, kSignalConnMarker}.raw();
  (void)poller_->add(sig_fds[0], signal_token, PRead);

  // --- listener --------------------------------------------------------------
  (void)poller_->add(listen_fd, Token{FdKind::Listener, 0}.raw(), PRead);

  // --- control plane ---------------------------------------------------------
  ControlServer control(store.control_socket_path());
  (void)poller_->add(control.listen_fd(), Token{FdKind::Control, 0}.raw(), PRead);

  std::vector<PollEvent> events;
  std::vector<Scheduler::Due> due;

  auto accept_new = [&](TimeUs now) {
       while (!stop_requested_ && accepts_resumed_ &&
           mutator_->listener_enabled(now) &&
           conns_.size() < config.scenario.limits.max_connections) {
      std::string peer;
      const int cfd = sock::tcp_accept(listen_fd, &peer);
      if (cfd < 0) return;  // would-block: all pending accepts drained
      const ConnId conn = ++next_conn_;
      ConnState c;
      c.conn = conn;
      c.peer = peer;
      c.opened_at = wall_now_us();
      c.down_fd = cfd;
      conns_.emplace(conn, std::move(c));
      dir_of(conns_[conn], Dir::AtoB).read_armed =
          poller_->add(cfd, leg_token(LegSide::Down, conn).raw(), PRead);
      ++summary_.connections_total;
      // INVARIANT: the MUTATOR schedules ActConnectUpstream/ActRefuseDownstream.
      mutator_->on_connection_accepted(conn, now);
    }
  };

  auto execute_action = [&](Scheduler::Due item, TimeUs now) {
    if (auto* a = std::get_if<ActDeliver>(&item.action)) {
      const auto it = conns_.find(a->key.conn);
      if (it == conns_.end()) return;  // tombstoned lazily
      ConnState& c = it->second;
      DirectionState& ds = dir_of(c, a->key.dir);
      OutBlob blob;
      blob.logical_offset = a->logical_offset;
      blob.payload = std::move(a->payload);
  ds.deferred_bytes -= std::min<std::uint64_t>(ds.deferred_bytes, blob.payload.size());
      ds.pending_bytes += blob.payload.size();
      ds.out.push_back(std::move(blob));
      flush_direction(c, a->key.dir, now);
      return;
    }
    if (auto* a = std::get_if<ActFin>(&item.action)) {
      const auto it = conns_.find(a->conn);
      if (it == conns_.end()) return;
      ConnState& c = it->second;
      const int fd = leg_fd(c, a->leg);
      if (fd >= 0) sock::shutdown_write(fd);
      dir_of(c, outbound_dir(a->leg)).fin_relayed = true;
      // Same macOS constraint as the PWrite drain path: drop EVFILT_WRITE
      // once write interest ends so the READ knote keeps firing.
      sync_leg_events(c, a->leg);
      graceful_teardown_if_done(c, now);
      return;
    }
    if (auto* a = std::get_if<ActHalfCloseRx>(&item.action)) {
      const auto it = conns_.find(a->conn);
      if (it == conns_.end()) return;
      ConnState& c = it->second;
      const int fd = leg_fd(c, a->leg);
      if (fd >= 0) sock::shutdown_read(fd);
      dir_of(c, inbound_dir(a->leg)).rx_shutdown = true;
      disarm_read(c, inbound_dir(a->leg));
      return;
    }
    if (auto* a = std::get_if<ActReset>(&item.action)) {
      const auto it = conns_.find(a->conn);
      if (it == conns_.end()) return;
      rst_teardown(it->second, ClosedReason::FaultReset, now);
      return;
    }
    if (auto* a = std::get_if<ActConnectUpstream>(&item.action)) {
      const auto it = conns_.find(a->conn);
      if (it == conns_.end()) return;
      ConnState& c = it->second;
      c.up_fd = sock::tcp_connect(config.scenario.upstream);
      c.connecting = true;
      (void)poller_->add(c.up_fd, leg_token(LegSide::Up, c.conn).raw(), PWrite);
      return;
    }
    if (auto* a = std::get_if<ActRefuseDownstream>(&item.action)) {
      const auto it = conns_.find(a->conn);
      if (it == conns_.end()) return;
      ConnState& c = it->second;
      ++summary_.refused_total;
      if (c.down_fd >= 0) {
        (void)poller_->del(c.down_fd);
        ::close(c.down_fd);
        c.down_fd = -1;
      }
      sched_->drop_connection(a->conn);
      store_->log_connection(connection_record(a->conn, c.peer, c.opened_at,
                                               ClosedReason::ConnectFailed, 0, 0,
                                               c.sni));
      mutator_->on_connection_closed(a->conn, now, ClosedReason::ConnectFailed);
      conns_.erase(a->conn);
      return;
    }
    if (std::holds_alternative<ActResumeListener>(item.action)) {
      accepts_resumed_ = true;
      return;
    }
    // Engine-internal timers forward to the mutator; released pieces are
    // processed like process_read pieces.
    ProcessResult pr = mutator_->on_engine_timer(item.action, now);
    StreamKey key{};
    if (auto* fr = std::get_if<ActFlushReorder>(&item.action)) key = fr->key;
    if (auto* fc = std::get_if<ActFlushCoalesce>(&item.action)) key = fc->key;
    if (std::get_if<ActIdleFire>(&item.action) != nullptr) {
      // IdleFire carries only a conn id; released pieces (if any) have no
      // single direction, so decisions flow through the sink instead.
      return;
    }
    const auto it = conns_.find(key.conn);
    if (it != conns_.end()) emit_pieces(it->second, key.dir, std::move(pr), now);
  };

  // --- main loop -------------------------------------------------------------
  while (!stop_requested_) {
    const TimeUs now = steady_now_us(epoch);

    // Replay-style runs terminate themselves: once every connection drained
    // and the engine has no recorded work left, waiting longer only idles.
    if (config.mode == RunMode::LedgerReplay && conns_.empty() &&
        !mutator_->has_pending_work()) {
      break;
    }

    // Step 1: poller wait with timeout = time until next scheduler deadline.
    const TimeUs next_dl = scheduler.next_deadline();
    int timeout_ms = -1;  // block forever; self-pipe wakes us on signals
    if (next_dl != Scheduler::kTimeMaxSentinel) {
      const std::int64_t delta_us = std::max<std::int64_t>(0, next_dl - now);
      timeout_ms = static_cast<int>(
          std::min<std::int64_t>((delta_us + 999) / 1000,
                                 std::numeric_limits<int>::max()));
    }
    events.clear();
    (void)poller_->wait(timeout_ms, events);
   
    // Step 2: sort ready events by (conn ordinal, fd kind).
    std::sort(events.begin(), events.end(),
              [](const PollEvent& x, const PollEvent& y) {
                const Token tx = Token::from_raw(x.token);
                const Token ty = Token::from_raw(y.token);
                if (tx.conn != ty.conn) return tx.conn < ty.conn;
                return tx.kind < ty.kind;
              });

    bool listener_ready = false;
    bool control_ready = false;
    bool signal_ready = false;
    for (const PollEvent& ev : events) {
      const Token t = Token::from_raw(ev.token);
      if (t.kind == FdKind::Listener && t.conn == 0) {
        listener_ready = true;        continue;
      }
      if (t.kind == FdKind::Listener && t.conn == kSignalConnMarker) {
        signal_ready = true;        continue;
      }
      if (t.kind == FdKind::Control) {
        control_ready = true;        continue;
      }
           const auto it = conns_.find(t.conn);
      if (it == conns_.end()) continue;
      ConnState& c = it->second;
      const TimeUs tnow = steady_now_us(epoch);

       if (t.kind == FdKind::Upstream && c.connecting) {
         if ((ev.events & PWrite) != 0 || ev.err || ev.hup) {
           // Connect completion path.
            if (sock::connect_error(c.up_fd) == 0 && !ev.err) {
              c.connecting = false;
              c.established = true;
              dir_of(c, Dir::BtoA).read_armed = true;
              sync_leg_events(c, LegSide::Up);
            mutator_->on_connection_established(c.conn, tnow);
            // Arm downstream reads now that the far leg exists.
            if (!dir_of(c, Dir::AtoB).bp_paused) arm_read(c, Dir::AtoB);
            // Drain anything buffered while the upstream connect ran.
            flush_direction(c, Dir::AtoB, tnow);
            // A client FIN may have been observed before ActConnectUpstream
            // ran (connect actions pop one loop iteration after accept, so a
            // connect-and-immediately-close peer beats it reliably). In that
            // window eof_seen was recorded but no branch of handle_eof could
            // run; relay the FIN now that the far leg exists.
            if (c.downstream_eof_pending || dir_of(c, Dir::AtoB).eof_seen) {
              c.downstream_eof_pending = false;
              handle_eof(c, Dir::AtoB, tnow);
            }
          } else {
            ++summary_.refused_total;
            rst_teardown(c, ClosedReason::ConnectFailed, tnow);
          }
        }
        continue;
      }

       const LegSide side =
           t.kind == FdKind::Downstream ? LegSide::Down : LegSide::Up;
       const Dir inbound = inbound_dir(side);

      if (ev.err) {
        // Socket error on a data leg: tear down like an abrupt close.
        rst_teardown(c, side == LegSide::Down ? ClosedReason::ClientClosed
                                              : ClosedReason::ServerClosed,
                     tnow);
        continue;
      }
      if ((ev.events & PWrite) != 0) {
        dir_of(c, outbound_dir(side)).write_armed = false;
        flush_direction(c, outbound_dir(side), tnow);
        if (conns_.find(t.conn) == conns_.end()) continue;
        // Write interest ended: drop EVFILT_WRITE from the poller. On macOS
        // a lingering always-ready WRITE knote starves the READ knote on the
        // same socket - kevent keeps delivering only the WRITE event and the
        // peer's replies are never reported. Re-syncing recomputes exactly
        // the needed filters (and re-arms WRITE if flush hit EAGAIN again).
        sync_leg_events(c, side);
      }
      if (((ev.events & PRead) != 0 || ev.hup) &&
          conns_.find(t.conn) != conns_.end()) {
        read_leg(c, inbound, tnow);
      }
    }

    // Step 4: pop all due scheduler actions in (deadline, seq) order.
    due.clear();
    scheduler.pop_due(steady_now_us(epoch), due);
    for (Scheduler::Due& item : due) {
      execute_action(std::move(item), steady_now_us(epoch));
    }

    // Step 6: control requests drain between steps 4 and 5.
    if (control_ready) {
      for (const ControlRequest& req : control.poll_requests()) {
        ManualAction ma = ManualAction::Pause;
        if (req.cmd == ControlCmd::Resume) ma = ManualAction::Resume;
        if (req.cmd == ControlCmd::InjectReset) ma = ManualAction::InjectReset;
        (void)mutator_->manual_action(ma, req.conn, steady_now_us(epoch));
      }
    }

    if (listener_ready) accept_new(steady_now_us(epoch));

    if (signal_ready) {
      char drain[64];
      while (::read(sig_fds[0], drain, sizeof drain) > 0) {
      }
      stop_requested_ = true;
    }

    // Step 5: backpressure sweep - re-arm any direction that drained.
    for (auto& entry : conns_) {
      ConnState& c = entry.second;
      for (const int i : {0, 1}) {
        DirectionState& ds = c.dir[i];
        if (ds.bp_paused &&
            ds.pending_bytes + ds.deferred_bytes <
                scenario_->limits.pending_bytes_per_direction) {
          ds.bp_paused = false;
          arm_read(c, static_cast<Dir>(i));
        }
      }
    }
  }

  // --- graceful stop ---------------------------------------------------------
  // Close every live connection so peers observe EOF/RST immediately, then
  // flush evidence and write final artifacts.
  for (auto& entry : conns_) {
    ConnState& c = entry.second;
    if (c.down_fd >= 0) {
      (void)poller_->del(c.down_fd);
      ::close(c.down_fd);
    }
    if (c.up_fd >= 0) {
      (void)poller_->del(c.up_fd);
      ::close(c.up_fd);
    }
  }
  conns_.clear();
  (void)poller_->del(listen_fd);
  ::close(listen_fd);
  store.events().flush();

  summary_.wall_us = steady_now_us(epoch);
  store.finish(metrics_json(), metrics_json());

  ::close(sig_fds[0]);
  ::close(sig_fds[1]);
  g_signal_write_fd = -1;

  ReactorSummary out = summary_;
  return out;
}

ReactorSummary run_proxy(const ReactorConfig& config, MutatorFactory factory) {
  // Transport compatibility is enforced at the public entry point so that direct
  // API callers cannot run TCP-only faults through UDP either.
  check_transport_compat(config.scenario, config.transport);
  // Writes race peer closes constantly in a proxy; EPIPE must surface as a
  // write error, not a process kill.
  ::signal(SIGPIPE, SIG_IGN);
  if (config.transport == TransportMode::Udp) return run_proxy_udp(config, factory);
  Reactor r;
  return r.run(config, factory);
}

}  // namespace loki
