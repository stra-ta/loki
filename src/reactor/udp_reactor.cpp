// UDP transport reactor: a datagram proxy that reuses the exact same fault
// engine as the TCP reactor. Each client endpoint becomes a ConnId; the shared
// downstream socket recvfrom()s to learn clients, and every mapping gets its
// own upstream UDP socket connect()ed to the configured upstream so replies
// demultiplex cleanly. Datagrams are fed to the mutator one "chunk" at a time
// with a cumulative logical offset; the engine's RNG draw order, determinism
// contract, and all transport-agnostic faults therefore apply unchanged.
//
// TCP-only lifecycle faults (reset/fin/half_close/refuse/accept_stall/
// connect_delay) are rejected at scenario-validation time (see
// check_transport_compat), so the engine never emits ActReset/ActFin/... for
// UDP except via idle_timeout, which the reactor maps to mapping teardown.

#include <loki/reactor.hpp>

#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <string>
#include <utility>

#include <loki/control.hpp>
#include <loki/evidence.hpp>
#include <loki/json.hpp>
#include <loki/poller.hpp>
#include <loki/scheduler.hpp>
#include <loki/version.hpp>

#include "../config/validate_transport.hpp"
#include "../transport/socket_util.hpp"

#ifdef LOKI_GIT_SHA
#define LOKI_SHA LOKI_GIT_SHA
#else
#define LOKI_SHA "unknown"
#endif

namespace loki {

namespace {

// Max IPv4 UDP payload is 65507 bytes; 64 KiB covers it so a single recvfrom
// never truncates a legal datagram.
constexpr std::size_t kChunkCap = 65536;
constexpr ConnId kSignalConnMarker = 0xFFFFFFFFull;

TimeUs steady_now_us(const std::chrono::steady_clock::time_point& epoch) {
  const auto delta = std::chrono::steady_clock::now() - epoch;
  return std::chrono::duration_cast<std::chrono::microseconds>(delta).count();
}

WallUs wall_now_us() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// One buffered datagram (or transformed piece) awaiting write toward the far leg.
struct UdpOutBlob {
  std::vector<std::byte> payload;
  std::uint64_t logical_offset = 0;
  std::size_t sent = 0;
};

struct UdpDirState {
  std::deque<UdpOutBlob> out;          // ordered queue toward the far leg
  std::uint64_t pending_bytes = 0;     // unsent payload bytes in `out`
  std::uint64_t deferred_bytes = 0;    // bytes inside a scheduled ActDeliver
  StreamStats stats{};                 // pristine logical stream counters
  bool read_armed = false;             // upstream socket read interest (BtoA)
  bool write_armed = false;            // upstream socket write interest (AtoB)
  bool bp_paused = false;              // reads disarmed by backpressure
  bool empty_pending = false;          // a zero-length datagram awaiting write
};

struct UdpConn {
  ConnId conn = 0;
  std::string peer;                    // client addr, also the map key
  sockaddr_storage client_addr{};
  socklen_t client_addr_len = 0;
  WallUs opened_at = 0;
  int up_fd = -1;                      // per-conn upstream UDP socket (connected)
  UdpDirState dir[2];                  // [AtoB, BtoA]
  TimeUs last_activity = 0;
};

// A direction is over its backpressure bound when both what is already queued
// for the wire (pending_bytes) and what the scheduler will hand back later
// (deferred_bytes, inside a scheduled ActDeliver) is counted. Counting only
// pending_bytes let sustained latency traffic grow scheduler payload memory
// without bound.
bool dir_full(const UdpDirState& ds, std::uint64_t pending_bytes_per_direction) {
  return ds.pending_bytes + ds.deferred_bytes >= pending_bytes_per_direction;
}

Token up_token(ConnId c) { return Token{FdKind::Upstream, c}; }

// Signal self-pipe: handler writes one byte; the loop observes readiness.
int g_signal_write_fd = -1;
extern "C" void loki_udp_signal_handler(int) {
  if (g_signal_write_fd >= 0) {
    const char b = 1;
    ssize_t ignored = ::write(g_signal_write_fd, &b, 1);
    (void)ignored;
  }
}

json::Value udp_connection_record(ConnId conn, const std::string& peer,
                                  WallUs opened_at, ClosedReason reason,
                                  std::uint64_t bytes_a_to_b,
                                  std::uint64_t bytes_b_to_a) {
  json::Value rec = json::Value::object();
  rec.set("connection", json::Value::u(conn));
  rec.set("peer", json::Value::str(peer));
  rec.set("opened_at_us", json::Value::u(static_cast<std::uint64_t>(opened_at)));
  rec.set("closed_at_us", json::Value::u(static_cast<std::uint64_t>(wall_now_us())));
  rec.set("reason", json::Value::str(closed_reason_name(reason)));
  rec.set("bytes_a_to_b", json::Value::u(bytes_a_to_b));
  rec.set("bytes_b_to_a", json::Value::u(bytes_b_to_a));
  // UDP is datagram-based and carries no TLS ClientHello, so SNI is always
  // unknown; emit the field for schema consistency with the TCP reactor.
  rec.set("sni", json::Value::str(std::string{}));
  return rec;
}

}  // namespace

class UdpReactor {
 public:
  ReactorSummary run(const ReactorConfig& config, MutatorFactory& factory);

 private:
  void sync_down_read(TimeUs now);
  void sync_down_events();
  void sync_up_events(UdpConn& c);
  ConnId create_conn(const sockaddr_storage& from, socklen_t flen,
                     const std::string& key, TimeUs now);
  void teardown_conn(ConnId conn, ClosedReason reason, TimeUs now);
  void evict_oldest(TimeUs now);
  void process_chunk(UdpConn& c, Dir d, const char* buf, std::size_t n, TimeUs now);
  void emit_pieces(UdpConn& c, Dir d, ProcessResult pr, TimeUs now);
  void enqueue_piece(UdpConn& c, Dir d, OutPiece piece, TimeUs now);
  void flush_direction(UdpConn& c, Dir d, TimeUs now);
  sock::IoResult send_bytes(int fd, Dir d, const UdpConn& c, const void* buf, std::size_t len);
  void read_down(TimeUs now);
  void read_up(ConnId conn, TimeUs now);
  void log_decision(FaultDecision d);
  json::Value metrics_json() const;
  void execute_action(Scheduler::Due item, TimeUs now);

  Poller* poller_ = nullptr;
  Scheduler* sched_ = nullptr;
  RunStore* store_ = nullptr;
  INetworkMutator* mutator_ = nullptr;
  const CompiledScenario* scenario_ = nullptr;
  std::map<ConnId, UdpConn> conns_;
  std::map<std::string, ConnId> addr_to_conn_;
  ConnId next_conn_ = 0;
  int down_fd_ = -1;
  bool down_read_armed_ = true;
  bool down_write_armed_ = false;
  bool stop_requested_ = false;
  ReactorSummary summary_{};
  std::map<std::uint32_t, std::uint64_t> rule_firings_;
};

void UdpReactor::sync_down_read(TimeUs now) {
  bool allow = mutator_->listener_enabled(now);
  if (allow) {
    for (const auto& kv : conns_) {
      if (dir_full(kv.second.dir[static_cast<int>(Dir::AtoB)],
                   scenario_->limits.pending_bytes_per_direction)) {
        allow = false;
        break;
      }
    }
  }
  if (allow != down_read_armed_) {
    down_read_armed_ = allow;
    sync_down_events();
  }
}

void UdpReactor::sync_down_events() {
  PollEvents ev = PNone;
  if (down_read_armed_) ev = ev | PRead;
  bool ba_pending = false;
  for (const auto& kv : conns_) {
    if (!kv.second.dir[static_cast<int>(Dir::BtoA)].out.empty()) {
      ba_pending = true;
      break;
    }
  }
  down_write_armed_ = ba_pending;
  if (ba_pending) ev = ev | PWrite;
  poller_->mod(down_fd_, Token{FdKind::Listener, 0}.raw(), ev);
}

void UdpReactor::sync_up_events(UdpConn& c) {
  if (c.up_fd < 0) return;
  PollEvents ev = PNone;
  const UdpDirState& ba = c.dir[static_cast<int>(Dir::BtoA)];
  const UdpDirState& ab = c.dir[static_cast<int>(Dir::AtoB)];
  if (ba.read_armed &&
      !dir_full(ba, scenario_->limits.pending_bytes_per_direction)) {
    ev = ev | PRead;
  }
  if (!ab.out.empty()) ev = ev | PWrite;
  poller_->mod(c.up_fd, up_token(c.conn).raw(), ev);
}

ConnId UdpReactor::create_conn(const sockaddr_storage& from, socklen_t flen,
                               const std::string& key, TimeUs now) {
  if (conns_.size() >= scenario_->limits.max_connections) evict_oldest(now);
  const ConnId conn = ++next_conn_;
  UdpConn c;
  c.conn = conn;
  c.peer = sock::sockaddr_to_str(from, flen);
  std::memcpy(&c.client_addr, &from, sizeof from);
  c.client_addr_len = flen;
  c.opened_at = wall_now_us();
  try {
    c.up_fd = sock::udp_connect(scenario_->upstream);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "loki udp: upstream connect failed for %s: %s\n",
                 c.peer.c_str(), e.what());
    return 0;  // drop this datagram; do not register a broken mapping
  }
  conns_.emplace(conn, std::move(c));
  addr_to_conn_[key] = conn;
  UdpConn& ref = conns_[conn];
  ref.dir[static_cast<int>(Dir::BtoA)].read_armed = true;
  poller_->add(ref.up_fd, up_token(conn).raw(), PRead);
  sync_up_events(ref);
  ++summary_.connections_total;
  try {
    mutator_->on_connection_accepted(conn, now);
    mutator_->on_connection_established(conn, now);
  } catch (...) {
    // A throwing mutator callback must not leak the upstream fd; tear the
    // mapping down (which closes up_fd) before propagating.
    teardown_conn(conn, ClosedReason::ClientClosed, now);
    throw;
  }
  return conn;
}

void UdpReactor::teardown_conn(ConnId conn, ClosedReason reason, TimeUs now) {
  auto it = conns_.find(conn);
  if (it == conns_.end()) return;
  UdpConn& c = it->second;
  if (c.up_fd >= 0) {
    poller_->del(c.up_fd);
    ::close(c.up_fd);
    c.up_fd = -1;
  }
  addr_to_conn_.erase(c.peer);
  sched_->drop_connection(conn);
  store_->log_connection(udp_connection_record(
      conn, c.peer, c.opened_at, reason, c.dir[0].stats.bytes_seen,
      c.dir[1].stats.bytes_seen));
  mutator_->on_connection_closed(conn, now, reason);
  conns_.erase(conn);
}

void UdpReactor::evict_oldest(TimeUs now) {
  ConnId victim = 0;
  TimeUs oldest = std::numeric_limits<TimeUs>::max();
  for (const auto& kv : conns_) {
    if (kv.second.last_activity < oldest) {
      oldest = kv.second.last_activity;
      victim = kv.first;
    }
  }
  if (victim) teardown_conn(victim, ClosedReason::ClientClosed, now);
}

void UdpReactor::process_chunk(UdpConn& c, Dir d, const char* buf, std::size_t n,
                                TimeUs now) {
  UdpDirState& ds = c.dir[static_cast<int>(d)];
  const StreamStats stats_before = ds.stats;
  ProcessResult pr = mutator_->process_read(
      StreamKey{c.conn, d}, stats_before.bytes_seen,
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), n),
      stats_before, now);
  // Advance the pristine logical offset exactly as if the datagram were
  // delivered: blackhole discard still "consumes" the bytes (TCP ACKs into
  // Loki), so downstream offsets stay consistent. Freeze cannot reach here for
  // UDP (rejected at validation), so read_enabled false means discard.
  ds.stats.bytes_seen += n;
  ds.stats.chunks_seen += 1;
  if (d == Dir::AtoB)
    summary_.bytes_a_to_b += n;
  else
    summary_.bytes_b_to_a += n;
  c.last_activity = now;
  if (!mutator_->read_enabled(StreamKey{c.conn, d}, now)) {
    return;  // blackhole discard: drop the transformed output
  }
  emit_pieces(c, d, std::move(pr), now);
}

void UdpReactor::emit_pieces(UdpConn& c, Dir d, ProcessResult pr, TimeUs now) {
  for (FaultDecision& dec : pr.decisions) log_decision(std::move(dec));
  UdpDirState& ds = c.dir[static_cast<int>(d)];
  for (OutPiece& p : pr.pieces) {
    if (p.immediate || p.send_at_us <= now) {
      enqueue_piece(c, d, std::move(p), now);
    } else {
      ds.deferred_bytes += p.payload.size();
      sched_->push(p.send_at_us,
                   ActDeliver{StreamKey{c.conn, d}, std::move(p.payload),
                              p.logical_offset});
    }
  }
}

sock::IoResult UdpReactor::send_bytes(int fd, Dir d, const UdpConn& c, const void* buf,
                                std::size_t len) {
  if (d == Dir::AtoB) return sock::write_some(fd, buf, len);
  return sock::sendto_some(fd, buf, len, c.client_addr, c.client_addr_len);
}

void UdpReactor::enqueue_piece(UdpConn& c, Dir d, OutPiece piece, TimeUs now) {
  UdpDirState& ds = c.dir[static_cast<int>(d)];
  const int send_fd = (d == Dir::AtoB) ? c.up_fd : down_fd_;
  if (send_fd < 0) return;  // no far socket; drop
  // Zero-length datagrams are legal UDP and must round-trip transparently. We
  // track the pending empty send with a flag (not a queued blob) so it can never
  // strand at the queue head: a successful 0-byte send returns n == 0, so a
  // blob-based retry would never be dequeued. flush_direction drains it inline.
  if (piece.payload.empty()) {
    ds.empty_pending = true;
    flush_direction(c, d, now);
    return;
  }

  // Fast path: an immediate piece with an empty queue goes straight to the wire.
  if (ds.out.empty() && !piece.payload.empty()) {
    sock::IoResult w = send_bytes(send_fd, d, c, piece.payload.data(),
                            piece.payload.size());
    if (w.n == static_cast<long>(piece.payload.size())) {
      mutator_->on_data_flushed(StreamKey{c.conn, d},
                                static_cast<std::uint64_t>(w.n), now);
      flush_direction(c, d, now);
      return;
    }
    if (w.n > 0) {
      UdpOutBlob blob;
      blob.logical_offset = piece.logical_offset;
      blob.payload = std::move(piece.payload);
      blob.sent = static_cast<std::size_t>(w.n);
      ds.pending_bytes += blob.payload.size() - blob.sent;
      ds.out.push_back(std::move(blob));
      flush_direction(c, d, now);
      return;
    }
    if (!w.would_block) return;  // hard error: drop the piece
    // would_block: fall through to the queue path
  }

  UdpOutBlob blob;
  blob.logical_offset = piece.logical_offset;
  blob.payload = std::move(piece.payload);
  ds.pending_bytes += blob.payload.size();
  ds.out.push_back(std::move(blob));
  flush_direction(c, d, now);
}

void UdpReactor::flush_direction(UdpConn& c, Dir d, TimeUs now) {
  UdpDirState& ds = c.dir[static_cast<int>(d)];
  const int fd = (d == Dir::AtoB) ? c.up_fd : down_fd_;
  if (fd < 0) {
    ds.pending_bytes = 0;
    ds.out.clear();
    ds.empty_pending = false;
    return;
  }
  // Drain a pending zero-length datagram inline. A successful 0-byte send
  // returns n == 0, so it is treated as complete here (no deque entry needed).
  if (ds.empty_pending) {
    sock::IoResult w = send_bytes(fd, d, c, "", 0);
    if (w.would_block) {
      if (d == Dir::AtoB) ds.write_armed = true;
      // fall through: the re-arm at the end re-enables writable interest while
      // empty_pending stays set for the next flush.
    } else {
      ds.empty_pending = false;
    }
  }
  std::uint64_t flushed = 0;
  while (!ds.out.empty()) {
    UdpOutBlob& front = ds.out.front();
    const std::size_t remain = front.payload.size() - front.sent;
    sock::IoResult w = send_bytes(fd, d, c, front.payload.data() + front.sent, remain);
    if (w.n > 0) {
      front.sent += static_cast<std::size_t>(w.n);
      ds.pending_bytes -= static_cast<std::uint64_t>(w.n);
      flushed += static_cast<std::uint64_t>(w.n);
      if (front.sent == front.payload.size()) ds.out.pop_front();
      continue;
    }
    if (w.would_block) {
      if (d == Dir::AtoB) c.dir[static_cast<int>(Dir::AtoB)].write_armed = true;
      break;
    }
    break;  // hard error: leave queued; teardown will reclaim
  }
  if (flushed > 0) {
    mutator_->on_data_flushed(StreamKey{c.conn, d}, flushed, now);
  }
  if (ds.bp_paused &&
      ds.pending_bytes + ds.deferred_bytes <
          scenario_->limits.pending_bytes_per_direction) {
    ds.bp_paused = false;
    if (d == Dir::BtoA) {
      ds.read_armed = true;
      sync_up_events(c);
    }
    // AtoB read re-arm is handled globally by sync_down_read.
  }
  if (d == Dir::AtoB)
    sync_up_events(c);
  else
    sync_down_events();
}

void UdpReactor::read_down(TimeUs now) {
  while (!stop_requested_) {
    sockaddr_storage from{};
    socklen_t flen = sizeof from;
    char buf[kChunkCap];
    sock::IoResult r = sock::recvfrom_some(down_fd_, buf, sizeof buf, &from, &flen);
    if (r.would_block || r.n < 0) break;
    const std::string key = sock::sockaddr_to_str(from, flen);
    ConnId conn;
    auto it = addr_to_conn_.find(key);
    if (it == addr_to_conn_.end())
      conn = create_conn(from, flen, key, now);
    else
      conn = it->second;
    if (conn == 0) continue;
    auto cit = conns_.find(conn);
    if (cit == conns_.end()) continue;
    UdpConn& c = cit->second;
    UdpDirState& ds = c.dir[static_cast<int>(Dir::AtoB)];
    if (ds.bp_paused) break;  // over the backpressure bound: stop reading
    // r.n may be 0: a legal zero-length datagram, forwarded transparently.
    process_chunk(c, Dir::AtoB, buf, static_cast<std::size_t>(r.n), now);
    if (dir_full(ds, scenario_->limits.pending_bytes_per_direction)) {
      ds.bp_paused = true;
      break;
    }
  }
}

void UdpReactor::read_up(ConnId conn, TimeUs now) {
  auto it = conns_.find(conn);
  if (it == conns_.end()) return;
  UdpConn& c = it->second;
  UdpDirState& ba = c.dir[static_cast<int>(Dir::BtoA)];
  if (ba.bp_paused) return;
  while (!stop_requested_) {
    char buf[kChunkCap];
    sock::IoResult r = sock::read_some(c.up_fd, buf, sizeof buf);
    if (r.would_block || r.n < 0) break;
    // r.n == 0: upstream closed its write side (UDP peer sent a zero-length
    // datagram or shutdown); forward transparently.
    process_chunk(c, Dir::BtoA, buf, static_cast<std::size_t>(r.n), now);
    if (dir_full(ba, scenario_->limits.pending_bytes_per_direction)) {
      ba.bp_paused = true;
      ba.read_armed = false;
      sync_up_events(c);
      break;
    }
  }
}

void UdpReactor::log_decision(FaultDecision d) {
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
      const std::uint32_t sample_n = std::max<std::uint32_t>(
          1, scenario_->rules[d.rule_index].sample_n);
      const std::uint64_t n = ++rule_firings_[d.rule_index];
      if (n % sample_n == 0)
        store_->events().append(d);
      else
        store_->events().note_counts(d.kind, 1);
      break;
    }
  }
  ++summary_.decisions_logged;
}

void UdpReactor::execute_action(Scheduler::Due item, TimeUs now) {
  if (auto* a = std::get_if<ActDeliver>(&item.action)) {
    auto it = conns_.find(a->key.conn);
    if (it == conns_.end()) return;
    UdpConn& c = it->second;
    UdpDirState& ds = c.dir[static_cast<int>(a->key.dir)];
    UdpOutBlob blob;
    blob.logical_offset = a->logical_offset;
    blob.payload = std::move(a->payload);
    ds.deferred_bytes -=
        std::min(ds.deferred_bytes, static_cast<std::uint64_t>(blob.payload.size()));
    ds.pending_bytes += blob.payload.size();
    ds.out.push_back(std::move(blob));
    flush_direction(c, a->key.dir, now);
    return;
  }
  if (std::get_if<ActConnectUpstream>(&item.action)) {
    // UDP upstream is already connect()ed at mapping creation; nothing to do.
    return;
  }
  if (auto* a = std::get_if<ActReset>(&item.action)) {
    teardown_conn(a->conn, ClosedReason::FaultReset, now);
    return;
  }
  if (auto* a = std::get_if<ActFin>(&item.action)) {
    // UDP has no FIN; map to mapping teardown.
    teardown_conn(a->conn, ClosedReason::ClientClosed, now);
    return;
  }
  if (std::get_if<ActHalfCloseRx>(&item.action)) {
    return;  // no RX shutdown for datagrams
  }
  if (auto* a = std::get_if<ActRefuseDownstream>(&item.action)) {
    teardown_conn(a->conn, ClosedReason::ConnectFailed, now);
    return;
  }
  if (std::holds_alternative<ActResumeListener>(item.action)) {
    return;  // accept_stall is rejected for UDP; harmless no-op
  }
  if (auto* fi = std::get_if<ActIdleFire>(&item.action)) {
    // Forward to the engine: it re-arms stale fires, records the idle_timeout
    // ledger decision, and schedules the configured action (ActReset /
    // ActFin). The scheduled action is executed by the normal path below, which
    // performs the mapping teardown. Closing here would both miss the decision
    // and risk dropping an active mapping at an obsolete deadline.
    ProcessResult pr = mutator_->on_engine_timer(item.action, now);
    for (FaultDecision& d : pr.decisions) log_decision(std::move(d));
    return;
  }
  // Engine-internal timers: reorder/coalesce flush release queued pieces.
  ProcessResult pr = mutator_->on_engine_timer(item.action, now);
  StreamKey key{};
  if (auto* fr = std::get_if<ActFlushReorder>(&item.action)) key = fr->key;
  if (auto* fc = std::get_if<ActFlushCoalesce>(&item.action)) key = fc->key;
  if (key.conn == 0) return;
  auto it = conns_.find(key.conn);
  if (it != conns_.end()) emit_pieces(it->second, key.dir, std::move(pr), now);
}

json::Value UdpReactor::metrics_json() const {
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

ReactorSummary UdpReactor::run(const ReactorConfig& config, MutatorFactory& factory) {
  scenario_ = &config.scenario;
  const auto epoch = std::chrono::steady_clock::now();
  const WallUs started_wall = wall_now_us();

  const int down_fd = sock::udp_bind(config.scenario.listen);
  down_fd_ = down_fd;

  // RAII cleanup guard: guarantees the listener fd, every live upstream fd, the
  // signal self-pipe, the global signal write fd, and the installed signal
  // dispositions are released even if a later step throws. Closing an fd removes
  // it from the poller on both kqueue and epoll, so explicit poller_->del calls
  // are optional.
  int sig_read_fd = -1;
  int sig_write_fd = -1;
  struct sigaction old_int {};
  struct sigaction old_term {};
  bool sig_installed = false;
  struct Cleanup {
    int& down_fd;
    int& sig_read;
    int& sig_write;
    struct sigaction& old_int;
    struct sigaction& old_term;
    bool& installed;
    std::map<ConnId, UdpConn>& conns;
    ~Cleanup() {
      for (auto& entry : conns) {
        if (entry.second.up_fd >= 0) {
          ::close(entry.second.up_fd);
          entry.second.up_fd = -1;
        }
      }
      if (down_fd >= 0) { ::close(down_fd); down_fd = -1; }
      if (sig_read >= 0) { ::close(sig_read); sig_read = -1; }
      if (sig_write >= 0) { ::close(sig_write); sig_write = -1; }
      g_signal_write_fd = -1;
      if (installed) {
        ::sigaction(SIGINT, &old_int, nullptr);
        ::sigaction(SIGTERM, &old_term, nullptr);
      }
    }
  };
  Cleanup cleanup_guard{down_fd_, sig_read_fd, sig_write_fd, old_int, old_term,
                        sig_installed, conns_};

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

  Scheduler scheduler;
  sched_ = &scheduler;
  auto mutator = factory(config.scenario, scheduler, 0);
  mutator_ = mutator.get();
  mutator_->set_decision_sink(
      [this](FaultDecision d) { log_decision(std::move(d)); });

  int sig_fds[2];
  if (::pipe(sig_fds) != 0) throw std::runtime_error("udp reactor: pipe failed");
  sock::set_nonblock_cloexec(sig_fds[0]);
  sock::set_nonblock_cloexec(sig_fds[1]);
  sig_read_fd = sig_fds[0];
  sig_write_fd = sig_fds[1];
  g_signal_write_fd = sig_fds[1];
  struct sigaction sa {};
  sa.sa_handler = loki_udp_signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  ::sigaction(SIGINT, &sa, &old_int);
  ::sigaction(SIGTERM, &sa, &old_term);
  sig_installed = true;
  const std::uint64_t signal_token =
      Token{FdKind::Listener, kSignalConnMarker}.raw();
  (void)poller_->add(sig_fds[0], signal_token, PRead);

  down_read_armed_ = true;
  (void)poller_->add(down_fd, Token{FdKind::Listener, 0}.raw(), PRead);

  ControlServer control(store.control_socket_path());
  (void)poller_->add(control.listen_fd(), Token{FdKind::Control, 0}.raw(), PRead);

  std::vector<PollEvent> events;
  std::vector<Scheduler::Due> due;

  while (!stop_requested_) {
    const TimeUs now = steady_now_us(epoch);

    if (config.mode == RunMode::LedgerReplay && conns_.empty() &&
        !mutator_->has_pending_work()) {
      break;
    }

    sync_down_read(now);

    const TimeUs next_dl = scheduler.next_deadline();
    int timeout_ms = -1;
    if (next_dl != Scheduler::kTimeMaxSentinel) {
      const std::int64_t delta_us = std::max<std::int64_t>(0, next_dl - now);
      timeout_ms = static_cast<int>(std::min<std::int64_t>(
          (delta_us + 999) / 1000, std::numeric_limits<int>::max()));
    }
    events.clear();
    (void)poller_->wait(timeout_ms, events);

    std::sort(events.begin(), events.end(),
              [](const PollEvent& x, const PollEvent& y) {
                const Token tx = Token::from_raw(x.token);
                const Token ty = Token::from_raw(y.token);
                if (tx.conn != ty.conn) return tx.conn < ty.conn;
                return tx.kind < ty.kind;
              });

    bool down_read_ready = false;
    bool down_write_ready = false;
    bool control_ready = false;
    bool signal_ready = false;
    for (const PollEvent& ev : events) {
      const Token t = Token::from_raw(ev.token);
      if (t.kind == FdKind::Listener && t.conn == 0) {
        if ((ev.events & PRead) != 0) down_read_ready = true;
        if ((ev.events & PWrite) != 0) down_write_ready = true;
        continue;
      }
      if (t.kind == FdKind::Listener && t.conn == kSignalConnMarker) {
        signal_ready = true;
        continue;
      }
      if (t.kind == FdKind::Control) {
        control_ready = true;
        continue;
      }
      if (t.kind == FdKind::Upstream) {
        auto it = conns_.find(t.conn);
        if (it == conns_.end()) continue;
        UdpConn& c = it->second;
        const TimeUs tnow = steady_now_us(epoch);
        if (ev.err) {
          teardown_conn(t.conn, ClosedReason::ServerClosed, tnow);
          continue;
        }
        if ((ev.events & PWrite) != 0) {
          c.dir[static_cast<int>(Dir::AtoB)].write_armed = false;
          flush_direction(c, Dir::AtoB, tnow);
          if (conns_.find(t.conn) == conns_.end()) continue;
          sync_up_events(c);
        }
        if (((ev.events & PRead) != 0 || ev.hup) &&
            conns_.find(t.conn) != conns_.end()) {
          read_up(t.conn, tnow);
        }
        continue;
      }
    }

    due.clear();
    scheduler.pop_due(steady_now_us(epoch), due);
    for (Scheduler::Due& item : due) {
      execute_action(std::move(item), steady_now_us(epoch));
    }

    if (control_ready) {
      for (const ControlRequest& req : control.poll_requests()) {
        ManualAction ma = ManualAction::Pause;
        if (req.cmd == ControlCmd::Resume) ma = ManualAction::Resume;
        if (req.cmd == ControlCmd::InjectReset) ma = ManualAction::InjectReset;
        (void)mutator_->manual_action(ma, req.conn, steady_now_us(epoch));
      }
    }

    // The shared downstream socket became writable: drain queued B-to-A
    // datagrams (server replies) toward their clients. Without this, replies
    // could strand in per-conn queues when a sendto would have blocked.
    if (down_write_ready) {
      const TimeUs tnow = steady_now_us(epoch);
      for (auto& entry : conns_) {
        flush_direction(entry.second, Dir::BtoA, tnow);
      }
    }

    if (down_read_ready) read_down(steady_now_us(epoch));

    if (signal_ready) {
      char drain[64];
      while (::read(sig_fds[0], drain, sizeof drain) > 0) {
      }
      stop_requested_ = true;
    }
  }

  for (auto& entry : conns_) {
    UdpConn& c = entry.second;
    if (c.up_fd >= 0) {
      poller_->del(c.up_fd);
      ::close(c.up_fd);
      c.up_fd = -1;
    }
  }
  conns_.clear();
  store.events().flush();

  summary_.wall_us = steady_now_us(epoch);
  store.finish(metrics_json(), metrics_json());
  // Listener/pipe/signal cleanup is performed by the Cleanup guard at scope exit.

  ReactorSummary out = summary_;
  return out;
}

ReactorSummary run_proxy_udp(const ReactorConfig& config, MutatorFactory factory) {
  check_transport_compat(config.scenario, TransportMode::Udp);
  ::signal(SIGPIPE, SIG_IGN);
  UdpReactor r;
  return r.run(config, factory);
}

}  // namespace loki
