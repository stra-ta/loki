// Live V1 fault engine. Never touches a socket; the reactor executes the
// pieces and scheduled actions produced here.
//
// DRAW-ORDER INVARIANT (frozen):
//   One loki::Rng exists per run, created in bind() from scenario.seed.
//   Within one process_read call, rules evaluate in ascending index. A rule
//   consumes RNG only after ALL of its deterministic guards pass (direction,
//   after_us, min_stream_offset, connection selector, every_bytes crossing,
//   every_events crossing, max_occurrences -- none of which draw), and then:
//     - latency uniform : one next_double(); delay = mean + (2u-1)*jitter, clamped >= 0
//     - latency normal  : one next_normal(mean, stddev)
//     - fragment        : while remaining > 0, size = min(remaining,
//                         next_below(max-min+1)+min)
//     - reorder release : Fisher-Yates over held pieces, next_below(i+1)
//                         for i from n-1 down to 1
//     - everything else draws nothing.
//
// COMPOSITION INVARIANT: rules apply in ascending index to the current piece
// list; shape faults reshape it, timing faults stamp send deadlines with the
// LATER deadline winning (traffic never accelerates), silence/lifecycle
// faults queue side effects immediately.
//
// OFFSET INVARIANT: stream_offset / logical offsets are always pristine
// positions; transforms apply downstream of the decision point.
//
// No wall-clock reads anywhere: time comes only from `now` arguments and
// scheduler deadlines.

#include <loki/engine.hpp>
#include <loki/rng.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <variant>
#include <vector>

namespace loki {
namespace {

constexpr TimeUs kNoExpiry = ~static_cast<TimeUs>(0);

struct SKey {
  ConnId conn = 0;
  Dir dir = Dir::AtoB;

  bool operator<(const SKey& o) const {
    return conn != o.conn ? conn < o.conn : static_cast<int>(dir) < static_cast<int>(o.dir);
  }
};

struct ReorderWindow {
  std::vector<OutPiece> held;
  TimeUs first_hold_us = 0;
  bool timer_scheduled = false;
  std::uint64_t trigger_offset = 0;   // pristine offset of the capturing chunk
  std::uint64_t trigger_bytes = 0;    // pristine byte count at capture
  std::uint32_t rule_index = 0;
};

struct CoalesceAcc {
  std::vector<std::byte> buf;
  std::uint64_t first_offset = 0;
  TimeUs first_us = 0;
  bool timer_scheduled = false;
  std::uint32_t rule_index = 0;
};

struct Bucket {
  double tokens = 0.0;
  TimeUs last_us = 0;
  TimeUs next_us = 0;   // serialized wire clock: earliest free moment
  bool seeded = false;  // burst credit granted on first chunk
};

struct BlackholeWindow {
  BlackholeParams::Mode mode = BlackholeParams::Mode::Discard;
  TimeUs expiry_us = kNoExpiry;       // kNoExpiry = rest of the run
};

// Per-rule mutable runtime state.
struct RuleRt {
  std::uint64_t occurrences = 0;
  std::uint64_t fired_bytes_mult[2] = {0, 0};  // per direction, last fired multiple
  std::uint64_t fired_events_mult[2] = {0, 0};
  std::uint64_t events_seen[2] = {0, 0};       // chunk-read events per direction
};

class LiveEngine final : public INetworkMutator {
 public:
  explicit LiveEngine(const CompiledScenario& sc) : sc_(sc), rules_rt_(sc.rules.size()) {}

  void bind(Scheduler* scheduler, TimeUs epoch) override {
    sched_ = scheduler;
    epoch_ = epoch;
    rng_ = Rng::from_seed(sc_.seed);
  }

  // ------------------------------------------------------------------
  // Chunk processing
  // ------------------------------------------------------------------

  ProcessResult process_read(const StreamKey& key,
                             std::uint64_t chunk_logical_offset,
                             std::span<const std::byte> data,
                             const StreamStats& stats,
                             TimeUs now) override {
    ProcessResult res;

    const std::uint8_t d = static_cast<std::uint8_t>(key.dir);
    const TimeUs elapsed = now - epoch_;
    const std::uint64_t bytes_before = stats.bytes_seen;
    const std::uint64_t bytes_after = bytes_before + data.size();
    const std::uint64_t events_after = stats.chunks_seen + 1;

    // Blackhole discard: chunks in the silenced flow are consumed silently.
    auto bh = blackholes_.find(SKey{key.conn, key.dir});
    if (bh != blackholes_.end() && bh->second.mode == BlackholeParams::Mode::Discard &&
        now < bh->second.expiry_us) {
      return res;  // empty pieces, no decisions (decision happened at activation)
    }

    std::vector<OutPiece> pieces;
    std::vector<OutPiece> emitted;
    pieces.emplace_back();
    pieces.back().payload.assign(data.begin(), data.end());
    pieces.back().logical_offset = chunk_logical_offset;

    arm_idle_on_activity(key.conn, now);

    for (const CompiledRule& rule : sc_.rules) {
      RuleRt& rt = rules_rt_[rule.index];
      const MatchSpec& m = rule.when;

      // --- deterministic guards, no RNG ---
      if (m.direction && *m.direction != key.dir) continue;
      if (elapsed < m.after_us) continue;
      if (chunk_logical_offset < m.min_stream_offset) continue;
      if (m.connection.every > 0 && key.conn % m.connection.every != m.connection.equals) continue;

      bool crossed_bytes = true;
      if (m.every_bytes > 0) {
        const std::uint64_t mult = bytes_after / m.every_bytes;
        crossed_bytes = mult > bytes_before / m.every_bytes && mult > rt.fired_bytes_mult[d];
        if (!crossed_bytes) continue;
      }
      bool crossed_events = true;
      if (m.every_events > 0) {
        const std::uint64_t mult = events_after / m.every_events;
        crossed_events =
            mult > rt.events_seen[d] / m.every_events && mult > rt.fired_events_mult[d];
        if (!crossed_events) continue;
      }
      if (rt.occurrences >= m.max_occurrences) continue;

      // Crossing state commits once all earlier guards passed.
      if (m.every_bytes > 0) rt.fired_bytes_mult[d] = bytes_after / m.every_bytes;
      if (m.every_events > 0) {
        rt.fired_events_mult[d] = events_after / m.every_events;
      }
      rt.events_seen[d] = events_after;

      // --- probability draw, only after guards ---
      if (rng_.next_double() >= m.probability) continue;
      ++rt.occurrences;

      apply_rule(rule, key, chunk_logical_offset, bytes_after, elapsed, now, pieces, emitted, res);
      // Delayed flushes (reorder window full, coalesce size trigger) re-enter
      // the current piece list so later rules still see them.
      for (auto& pc : emitted) pieces.push_back(std::move(pc));
      emitted.clear();
      // A blackhole activation chunk itself still flows; the window applies
      // to later chunks via the short-circuit at the top of this method.
    }

    res.pieces = std::move(pieces);
    return res;
  }

  // ------------------------------------------------------------------
  // Lifecycle
  // ------------------------------------------------------------------

  void on_connection_accepted(ConnId conn, TimeUs now) override {
    const TimeUs elapsed = now - epoch_;
    bool scheduled = false;

    arm_idle_on_activity(conn, now);

    for (const CompiledRule& rule : sc_.rules) {
      RuleRt& rt = rules_rt_[rule.index];
      const MatchSpec& m = rule.when;

      // Only connection-phase faults act here; chunk faults must keep their
      // occurrence budget intact for process_read.
      switch (rule.kind) {
        case FaultKind::ConnectDelay:
        case FaultKind::Refuse:
        case FaultKind::AcceptStall:
          break;
        default:
          continue;
      }

      if (m.direction && *m.direction != Dir::AtoB) continue;
      if (elapsed < m.after_us) continue;
      if (m.connection.every > 0 && conn % m.connection.every != m.connection.equals) continue;
      if (rt.occurrences >= m.max_occurrences) continue;
      if (rng_.next_double() >= m.probability) continue;
      ++rt.occurrences;

      switch (rule.kind) {
        case FaultKind::ConnectDelay: {
          const auto& p = std::get<ConnectDelayParams>(rule.params);
          if (!scheduled) {
            sched_->push(now + static_cast<TimeUs>(p.delay_us), ActConnectUpstream{conn});
            scheduled = true;
            emit_lifecycle(rule, conn, Dir::AtoB, 0, elapsed, now,
                           resolved_obj().set("delay_us", json::Value::i(static_cast<std::int64_t>(p.delay_us))));
          }
          break;
        }
        case FaultKind::Refuse: {
          const auto& p = std::get<RefuseParams>(rule.params);
          if (!scheduled) {
            sched_->push(now + static_cast<TimeUs>(p.after_us), ActRefuseDownstream{conn});
            scheduled = true;
            emit_lifecycle(rule, conn, Dir::AtoB, 0, elapsed, now,
                           resolved_obj().set("after_us", json::Value::i(static_cast<std::int64_t>(p.after_us))));
          }
          break;
        }
        case FaultKind::AcceptStall: {
          const auto& p = std::get<AcceptStallParams>(rule.params);
          stall_until_us_ = now + static_cast<TimeUs>(p.stall_us);
          sched_->push(stall_until_us_, ActResumeListener{});
          emit_lifecycle(rule, conn, Dir::AtoB, 0, elapsed, now,
                         resolved_obj().set("stall_us", json::Value::i(static_cast<std::int64_t>(p.stall_us))));
          break;
        }
        default:
          break;  // chunk faults and idle arming are handled elsewhere
      }
    }

    // MUST-schedule invariant: exactly one connect/refuse per accepted conn.
    if (!scheduled) sched_->push(now, ActConnectUpstream{conn});
  }

  void on_connection_established(ConnId, TimeUs) override {}

  void on_connection_closed(ConnId conn, TimeUs, ClosedReason) override {
    sched_->drop_connection(conn);
    for (int dd = 0; dd < 2; ++dd) {
      reorder_.erase(SKey{conn, static_cast<Dir>(dd)});
      coalesce_.erase(SKey{conn, static_cast<Dir>(dd)});
      blackholes_.erase(SKey{conn, static_cast<Dir>(dd)});
    }
    for (std::size_t i = 0; i < sc_.rules.size(); ++i) {
      buckets_.erase({static_cast<std::uint32_t>(i), SKey{conn, Dir::AtoB}});
      buckets_.erase({static_cast<std::uint32_t>(i), SKey{conn, Dir::BtoA}});
    }
    idle_deadline_.erase(conn);
    idle_timer_live_.erase(conn);
  }

  void on_data_flushed(const StreamKey& key, std::uint64_t, TimeUs now) override {
    // Bytes hitting the wire count as connection activity for idle timeouts;
    // token buckets refill lazily inside process_read.
    arm_idle_on_activity(key.conn, now);
  }

  bool read_enabled(const StreamKey& key, TimeUs now) override {
    auto it = blackholes_.find(SKey{key.conn, key.dir});
    if (it != blackholes_.end() && it->second.mode == BlackholeParams::Mode::Freeze &&
        now < it->second.expiry_us) {
      return false;
    }
    return true;
  }

  bool listener_enabled(TimeUs now) override {
    if (paused_) return false;
    return now >= stall_until_us_;
  }

  void set_decision_sink(DecisionSink sink) override { sink_ = std::move(sink); }

  const std::vector<FaultDecision>& lifecycle_decisions() const override {
    return lifecycle_;
  }

  bool manual_action(ManualAction action, ConnId conn, TimeUs now) override {
    switch (action) {
      case ManualAction::Pause:
        paused_ = true;
        return true;
      case ManualAction::Resume:
        paused_ = false;
        return true;
      case ManualAction::InjectReset: {
        sched_->push(now, ActReset{conn});
        FaultDecision dec;
        dec.event_index = next_event_index();
        dec.conn = conn;
        dec.rule_index = ~std::uint32_t{0};
        dec.rule_name = "manual-ctl";
        dec.kind = FaultKind::Reset;
        dec.resolved = resolved_obj().set("after_us", json::Value::i(static_cast<std::int64_t>(0)));
        dec.inputs = {0, 0};
        dec.applied = true;
        record_lifecycle(std::move(dec));
        return true;
      }
    }
    return false;
  }

  ProcessResult on_engine_timer(const ScheduledAction& origin, TimeUs now) override {
    ProcessResult res;
    if (auto* fr = std::get_if<ActFlushReorder>(&origin)) {
      auto it = reorder_.find(SKey{fr->key.conn, fr->key.dir});
      if (it == reorder_.end()) return res;
      release_reorder(it->second, SKey{fr->key.conn, fr->key.dir}, now, res.pieces, res);
      reorder_.erase(it);
      return res;
    }
    if (auto* fc = std::get_if<ActFlushCoalesce>(&origin)) {
      auto it = coalesce_.find(SKey{fc->key.conn, fc->key.dir});
      if (it == coalesce_.end()) return res;
      flush_coalesce(it->second, SKey{fc->key.conn, fc->key.dir}, now, res.pieces, res);
      coalesce_.erase(it);
      return res;
    }
    if (auto* fi = std::get_if<ActIdleFire>(&origin)) {
      auto it = idle_deadline_.find(fi->conn);
      if (it == idle_deadline_.end()) return res;
      idle_timer_live_[fi->conn] = false;
      if (now < it->second.deadline) {
        // Stale fire from before a re-arm: re-schedule at the real deadline.
        sched_->push(it->second.deadline, ActIdleFire{fi->conn});
        idle_timer_live_[fi->conn] = true;
        return res;
      }
      fire_idle(fi->conn, now, it->second);
      idle_deadline_.erase(it);
      idle_timer_live_.erase(fi->conn);
      return res;
    }
    return res;  // ActResumeListener et al. are executed mechanically by the reactor
  }

 private:
  struct BKey {
    std::uint32_t rule;
    SKey stream;
    bool operator<(const BKey& o) const { return rule != o.rule ? rule < o.rule : stream < o.stream; }
  };

  struct IdleArm {
    TimeUs deadline = 0;
    IdleTimeoutParams::Action action = IdleTimeoutParams::Action::Reset;
    std::uint64_t idle_us = 0;
    std::uint32_t rule_index = 0;
  };

  static json::Value resolved_obj() { return json::Value::object(); }

  std::uint64_t next_event_index() { return event_counter_++; }

  void record_lifecycle(FaultDecision dec) {
    lifecycle_.push_back(dec);
    if (sink_) sink_(lifecycle_.back());
  }

  void emit_lifecycle(const CompiledRule& rule, ConnId conn, Dir dir,
                      std::uint64_t offset, TimeUs elapsed, TimeUs now,
                      json::Value resolved) {
    FaultDecision dec;
    dec.event_index = next_event_index();
    dec.conn = conn;
    dec.dir = dir;
    dec.stream_offset = offset;
    dec.rule_index = rule.index;
    dec.rule_name = rule.name;
    dec.kind = rule.kind;
    dec.resolved = std::move(resolved);
    dec.inputs = {0, static_cast<std::uint64_t>(elapsed)};
    (void)now;
    record_lifecycle(std::move(dec));
  }

  FaultDecision make_chunk_decision(const CompiledRule& rule, const StreamKey& key,
                                    std::uint64_t offset, std::uint64_t bytes_after,
                                    TimeUs elapsed, json::Value resolved, bool applied) {
    FaultDecision dec;
    dec.event_index = next_event_index();
    dec.conn = key.conn;
    dec.dir = key.dir;
    dec.stream_offset = offset;
    dec.rule_index = rule.index;
    dec.rule_name = rule.name;
    dec.kind = rule.kind;
    dec.resolved = std::move(resolved);
    dec.inputs = {bytes_after, static_cast<std::uint64_t>(elapsed)};
    dec.applied = applied;
    return dec;
  }

  // Applies one matched rule to the current piece list / engine state.
  void apply_rule(const CompiledRule& rule, const StreamKey& key,
                  std::uint64_t chunk_offset, std::uint64_t bytes_after,
                  TimeUs elapsed, TimeUs now,
                  std::vector<OutPiece>& pieces, std::vector<OutPiece>& emit,
                  ProcessResult& res) {
    const SKey sk{key.conn, key.dir};

    switch (rule.kind) {
      case FaultKind::Latency: {
        const auto& p = std::get<LatencyParams>(rule.params);
        TimeUs delay = 0;
        if (p.normal) {
          delay = static_cast<TimeUs>(std::llround(
              rng_.next_normal(static_cast<double>(p.mean_us), p.stddev_us)));
        } else {
          const double u = rng_.next_double();
          // mean + (2u-1)*jitter, clamped >= 0
          const double raw =
              static_cast<double>(p.mean_us) + (2.0 * u - 1.0) * static_cast<double>(p.jitter_us);
          delay = static_cast<TimeUs>(std::llround(std::max(0.0, raw)));
        }
        for (auto& pc : pieces) {
          if (delay <= 0) break;  // zero delay leaves immediate pieces untouched
          const TimeUs current = pc.immediate ? 0 : pc.send_at_us;
          pc.send_at_us = std::max(current, now + delay);
          pc.immediate = false;
        }
        res.decisions.push_back(make_chunk_decision(
            rule, key, chunk_offset, bytes_after, elapsed,
            resolved_obj().set("delay_us", json::Value::i(static_cast<std::int64_t>(delay))),
            true));
        break;
      }

      case FaultKind::Bandwidth: {
        const auto& p = std::get<BandwidthParams>(rule.params);
        Bucket& b = buckets_[BKey{rule.index, sk}];
        if (!b.seeded) {
          b.seeded = true;
          b.tokens = static_cast<double>(p.burst_bytes);
          b.last_us = now;
        }
        const double dt = static_cast<double>(now - b.last_us) / 1e6;
        b.last_us = now;
        b.tokens = std::min(static_cast<double>(p.burst_bytes),
                            b.tokens + static_cast<double>(p.rate_bytes_per_sec) * dt);
        // Serialized wire clock: pieces leave in order, so piece k cannot
        // start before piece k-1 finishes at the configured rate. Without
        // this, read-ahead chunks all time themselves from `now` and the
        // rate cap collapses to burst-size-per-read-batch.
        TimeUs start = now > b.next_us ? now : b.next_us;
        TimeUs max_send = now;
        for (auto& pc : pieces) {
          const double need = static_cast<double>(pc.payload.size());
          TimeUs t = start;
          if (b.tokens >= need) {
            b.tokens -= need;
          } else {
            const double deficit = need - std::max(0.0, b.tokens);
            b.tokens = 0.0;
            t = start + static_cast<TimeUs>(
                            std::ceil(deficit /
                                      static_cast<double>(p.rate_bytes_per_sec) * 1e6));
            start = t;
          }
          if (pc.immediate || t > pc.send_at_us) pc.send_at_us = t;
          pc.immediate = pc.send_at_us <= now && pc.immediate;
          if (pc.send_at_us > now) pc.immediate = false;
          max_send = std::max(max_send, pc.send_at_us);
        }
        b.next_us = start;
        const std::uint64_t waited =
            max_send > now ? static_cast<std::uint64_t>(max_send - now) : 0;
        res.decisions.push_back(make_chunk_decision(
            rule, key, chunk_offset, bytes_after, elapsed,
            resolved_obj().set("waited_us", json::Value::i(static_cast<std::int64_t>(waited))), true));
        break;
      }

      case FaultKind::Fragment: {
        const auto& p = std::get<FragmentParams>(rule.params);
        std::vector<OutPiece> out;
        json::Value sizes = json::Value::array();
        for (auto& pc : pieces) {
          std::uint64_t remaining = pc.payload.size();
          std::uint64_t off = 0;
          while (remaining > 0) {
            const std::uint64_t span = p.max_bytes - p.min_bytes + 1;
            const std::uint64_t sz =
                std::min(remaining, rng_.next_below(span) + p.min_bytes);
            OutPiece np;
            np.payload.assign(pc.payload.begin() + static_cast<long>(off),
                              pc.payload.begin() + static_cast<long>(off + sz));
            np.logical_offset = pc.logical_offset + off;
            np.send_at_us = pc.send_at_us;
            np.immediate = pc.immediate;
            out.push_back(std::move(np));
            sizes.push(json::Value::i(static_cast<std::int64_t>(sz)));
            off += sz;
            remaining -= sz;
          }
        }
        pieces = std::move(out);
        res.decisions.push_back(make_chunk_decision(
            rule, key, chunk_offset, bytes_after, elapsed,
            resolved_obj().set("sizes", std::move(sizes)), true));
        break;
      }

      case FaultKind::Coalesce: {
        const auto& p = std::get<CoalesceParams>(rule.params);
        CoalesceAcc& acc = coalesce_[sk];
        if (acc.buf.empty()) {
          acc.first_offset = pieces.empty() ? chunk_offset : pieces.front().logical_offset;
          acc.first_us = now;
          acc.rule_index = rule.index;
          if (p.max_delay_us > 0 && !acc.timer_scheduled) {
            sched_->push(acc.first_us + static_cast<TimeUs>(p.max_delay_us),
                         ActFlushCoalesce{key});
            acc.timer_scheduled = true;
          }
        }
        for (auto& pc : pieces) acc.buf.insert(acc.buf.end(), pc.payload.begin(), pc.payload.end());
        pieces.clear();
        if (acc.buf.size() >= p.size_bytes) {
          flush_coalesce(acc, sk, now, emit, res);
          coalesce_.erase(sk);
        }
        break;
      }

      case FaultKind::Reorder: {
        const auto& p = std::get<ReorderParams>(rule.params);
        ReorderWindow& w = reorder_[sk];
        if (w.held.empty()) {
          w.first_hold_us = now;
          w.trigger_offset = chunk_offset;
          w.trigger_bytes = bytes_after;
          w.rule_index = rule.index;
          if (p.max_hold_us > 0 && !w.timer_scheduled) {
            sched_->push(w.first_hold_us + static_cast<TimeUs>(p.max_hold_us),
                         ActFlushReorder{key});
            w.timer_scheduled = true;
          }
        }
        for (auto& pc : pieces) w.held.push_back(std::move(pc));
        pieces.clear();
        if (w.held.size() >= p.depth) {
          release_reorder(w, sk, now, emit, res);
          reorder_.erase(sk);
        }
        break;
      }

      case FaultKind::Duplicate: {
        const auto& p = std::get<DuplicateParams>(rule.params);
        std::vector<OutPiece> out;
        out.reserve(pieces.size() * p.count);
        for (const auto& pc : pieces) {
          for (std::uint32_t c = 0; c < p.count; ++c) out.push_back(pc);
        }
        pieces = std::move(out);
        res.decisions.push_back(make_chunk_decision(
            rule, key, chunk_offset, bytes_after, elapsed,
            resolved_obj().set("count", json::Value::i(static_cast<std::int64_t>(p.count))), true));
        break;
      }

      case FaultKind::Corrupt: {
        const auto& p = std::get<CorruptParams>(rule.params);
        bool applied = false;
        std::uint8_t new_byte = 0;
        for (auto& pc : pieces) {
          if (pc.logical_offset <= p.stream_offset &&
              p.stream_offset < pc.logical_offset + pc.payload.size()) {
            const std::size_t i = static_cast<std::size_t>(p.stream_offset - pc.logical_offset);
            if (p.mode == CorruptParams::Mode::XorByte) {
              new_byte = static_cast<std::uint8_t>(pc.payload[i]) ^ p.value;
            } else {
              new_byte = p.value;
            }
            pc.payload[i] = static_cast<std::byte>(new_byte);
            applied = true;
            break;
          }
        }
        json::Value r = resolved_obj()
                            .set("offset", json::Value::i(static_cast<std::int64_t>(p.stream_offset)))
                            .set("applied", json::Value::b(applied))
                            .set("byte", json::Value::i(static_cast<std::int64_t>(new_byte)));
        res.decisions.push_back(
            make_chunk_decision(rule, key, chunk_offset, bytes_after, elapsed, std::move(r), applied));
        break;
      }

      case FaultKind::Blackhole: {
        const auto& p = std::get<BlackholeParams>(rule.params);
        BlackholeWindow w;
        w.mode = p.mode;
        w.expiry_us = p.duration_us == 0
                          ? kNoExpiry
                          : now + static_cast<TimeUs>(p.duration_us);
        blackholes_[SKey{key.conn, p.dir}] = w;
        // Discard semantics: chunks are consumed and dropped from the first
        // byte of the window onward, so the activation chunk is dropped too.
        // (Freeze only stops future reads; the in-hand chunk still flows.)
        if (p.mode == BlackholeParams::Mode::Discard) pieces.clear();
        json::Value r =
            resolved_obj()
                .set("mode", json::Value::str(p.mode == BlackholeParams::Mode::Discard ? "discard" : "freeze"))
                .set("duration_us", json::Value::i(static_cast<std::int64_t>(p.duration_us)));
        res.decisions.push_back(
            make_chunk_decision(rule, key, chunk_offset, bytes_after, elapsed, std::move(r), true));
        break;
      }

      case FaultKind::Reset: {
        const auto& p = std::get<ResetParams>(rule.params);
        sched_->push(now + static_cast<TimeUs>(p.after_us), ActReset{key.conn});
        res.decisions.push_back(make_chunk_decision(
            rule, key, chunk_offset, bytes_after, elapsed,
            resolved_obj().set("after_us", json::Value::i(static_cast<std::int64_t>(p.after_us))), true));
        break;
      }

      case FaultKind::Fin:
      case FaultKind::HalfClose: {
        HalfCloseParams p;
        if (rule.kind == FaultKind::Fin) {
          // `fin:` sugar: half_close tx on the named side.
          const auto& fp = std::get<HalfCloseParams>(rule.params);
          p = fp;
          p.mode = HalfCloseParams::Mode::Tx;
        } else {
          p = std::get<HalfCloseParams>(rule.params);
        }
        if (p.mode == HalfCloseParams::Mode::Tx) {
          sched_->push(now, ActFin{key.conn, p.leg});
        } else {
          sched_->push(now, ActHalfCloseRx{key.conn, p.leg});
        }
        json::Value r =
            resolved_obj()
                .set("side", json::Value::str(p.leg == LegSide::Down ? "client" : "server"))
                .set("mode", json::Value::str(p.mode == HalfCloseParams::Mode::Tx ? "tx" : "rx"));
        res.decisions.push_back(
            make_chunk_decision(rule, key, chunk_offset, bytes_after, elapsed, std::move(r), true));
        break;
      }

      case FaultKind::IdleTimeout: {
        const auto& p = std::get<IdleTimeoutParams>(rule.params);
        arm_idle(key.conn, now + static_cast<TimeUs>(p.idle_us), p.action, p.idle_us, rule.index);
        break;
      }

      default:
        break;  // ConnectDelay / Refuse / AcceptStall are accept-time faults
    }
  }

  // Fisher-Yates release of a reorder window; ONE decision at flush time.
  void release_reorder(ReorderWindow& w, const SKey& sk, TimeUs now, std::vector<OutPiece>& out, ProcessResult& res) {
    const std::size_t n = w.held.size();
    std::vector<std::uint64_t> perm(n);
    for (std::size_t i = 0; i < n; ++i) perm[i] = i;
    for (std::size_t i = n; i-- > 1;) {
      const std::uint64_t j = rng_.next_below(i + 1);
      std::swap(perm[i], perm[j]);
    }
    json::Value order = json::Value::array();
    for (std::size_t i = 0; i < n; ++i) {
      out.push_back(w.held[static_cast<std::size_t>(perm[i])]);
      order.push(json::Value::i(static_cast<std::int64_t>(perm[i])));
    }
    const CompiledRule& rule = sc_.rules[w.rule_index];
    FaultDecision dec;
    dec.event_index = next_event_index();
    dec.conn = sk.conn;
    dec.dir = sk.dir;
    dec.stream_offset = w.trigger_offset;
    dec.rule_index = rule.index;
    dec.rule_name = rule.name;
    dec.kind = FaultKind::Reorder;
    dec.resolved = resolved_obj().set("order", std::move(order));
    dec.inputs = {w.trigger_bytes,
                  static_cast<std::uint64_t>(now - epoch_)};
    dec.applied = true;
    res.decisions.push_back(std::move(dec));
  }

  void flush_coalesce(CoalesceAcc& acc, const SKey& sk, TimeUs now, std::vector<OutPiece>& out, ProcessResult& res) {
    OutPiece pc;
    pc.payload = std::move(acc.buf);
    acc.buf.clear();
    pc.logical_offset = acc.first_offset;
    pc.immediate = true;
    out.push_back(std::move(pc));

    const CompiledRule& rule = sc_.rules[acc.rule_index];
    const auto& p = std::get<CoalesceParams>(rule.params);
    FaultDecision dec;
    dec.event_index = next_event_index();
    dec.conn = sk.conn;
    dec.dir = sk.dir;
    dec.stream_offset = acc.first_offset;
    dec.rule_index = rule.index;
    dec.rule_name = rule.name;
    dec.kind = FaultKind::Coalesce;
    dec.resolved = resolved_obj().set("flushed_bytes", json::Value::i(static_cast<std::int64_t>(p.size_bytes)));
    dec.inputs = {acc.first_offset, static_cast<std::uint64_t>(now - epoch_)};
    dec.applied = true;
    res.decisions.push_back(std::move(dec));
  }

  void arm_idle_on_activity(ConnId conn, TimeUs now) {
    // Activity alone re-arms an existing deadline only when a rule matched
    // earlier (arm entries persist per conn); fresh arming happens through
    // rule matches in apply_rule / on_connection_accepted.
    auto it = idle_deadline_.find(conn);
    if (it != idle_deadline_.end()) {
      // Push a fresh timer for the shifted deadline.
      IdleArm arm = it->second;
      arm_idle(conn, now + static_cast<TimeUs>(arm.idle_us), arm.action, arm.idle_us,
               arm.rule_index);
    }
  }

  void arm_idle(ConnId conn, TimeUs deadline, IdleTimeoutParams::Action action,
                std::uint64_t idle_us, std::uint32_t rule_index) {
    idle_deadline_[conn] = IdleArm{deadline, action, idle_us, rule_index};
    // One live timer per connection; a surfaced stale fire re-pushes itself
    // (see on_engine_timer). Avoids stacking timers on every activity.
    if (!idle_timer_live_[conn]) {
      sched_->push(deadline, ActIdleFire{conn});
      idle_timer_live_[conn] = true;
    }
  }

  void fire_idle(ConnId conn, TimeUs now, const IdleArm& arm) {
    if (arm.action == IdleTimeoutParams::Action::Reset) {
      sched_->push(now, ActReset{conn});
    } else {
      sched_->push(now, ActFin{conn, LegSide::Down});
      sched_->push(now, ActFin{conn, LegSide::Up});
    }
    FaultDecision dec;
    dec.event_index = next_event_index();
    dec.conn = conn;
    dec.rule_index = arm.rule_index;
    dec.rule_name = sc_.rules[arm.rule_index].name;
    dec.kind = FaultKind::IdleTimeout;
    dec.resolved =
        resolved_obj()
            .set("idle_us", json::Value::i(static_cast<std::int64_t>(arm.idle_us)))
            .set("action",
                 json::Value::str(arm.action == IdleTimeoutParams::Action::Reset ? "reset" : "fin"));
    dec.inputs = {0, static_cast<std::uint64_t>(now - epoch_)};
    dec.applied = true;
    record_lifecycle(std::move(dec));
  }

  CompiledScenario sc_;
  std::vector<RuleRt> rules_rt_;
  Scheduler* sched_ = nullptr;
  TimeUs epoch_ = 0;
  Rng rng_{};
  std::uint64_t event_counter_ = 1;

  std::map<SKey, ReorderWindow> reorder_;
  std::map<SKey, CoalesceAcc> coalesce_;
  std::map<SKey, BlackholeWindow> blackholes_;
  std::map<BKey, Bucket> buckets_;
  std::map<ConnId, IdleArm> idle_deadline_;
  std::map<ConnId, bool> idle_timer_live_;

  TimeUs stall_until_us_ = ~static_cast<TimeUs>(0);  // accept_stall window
  bool paused_ = false;                              // manual Pause

  DecisionSink sink_;
  std::vector<FaultDecision> lifecycle_;
};

}  // namespace

std::unique_ptr<INetworkMutator> make_live_fault_engine(const CompiledScenario& scenario) {
  return std::make_unique<LiveEngine>(scenario);
}

}  // namespace loki
