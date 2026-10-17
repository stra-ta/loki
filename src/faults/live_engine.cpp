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
// list; shape faults (corrupt, duplicate, fragment, reorder) reshape it,
// timing faults (latency, bandwidth) stamp send deadlines with the LATER
// deadline winning (traffic never accelerates).
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

struct Bucket {
  double tokens = 0.0;
  TimeUs last_us = 0;
  TimeUs next_us = 0;   // serialized wire clock: earliest free moment
  bool seeded = false;  // burst credit granted on first chunk
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

    std::vector<OutPiece> pieces;
    std::vector<OutPiece> emitted;
    pieces.emplace_back();
    pieces.back().payload.assign(data.begin(), data.end());
    pieces.back().logical_offset = chunk_logical_offset;

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
      // Delayed flushes (reorder window full) re-enter the current piece list
      // so later rules still see them.
      for (auto& pc : emitted) pieces.push_back(std::move(pc));
      emitted.clear();
    }

    res.pieces = std::move(pieces);
    return res;
  }

  // ------------------------------------------------------------------
  // Lifecycle
  // ------------------------------------------------------------------

  void on_connection_accepted(ConnId conn, TimeUs now) override {
    // MUST-schedule invariant: exactly one connect action per accepted
    // connection; the reactor never opens the upstream socket on its own.
    sched_->push(now, ActConnectUpstream{conn});
  }

  void on_connection_established(ConnId, TimeUs) override {}

  void on_connection_closed(ConnId conn, TimeUs, ClosedReason) override {
    sched_->drop_connection(conn);
    for (int dd = 0; dd < 2; ++dd) {
      reorder_.erase(SKey{conn, static_cast<Dir>(dd)});
    }
    for (std::size_t i = 0; i < sc_.rules.size(); ++i) {
      buckets_.erase({static_cast<std::uint32_t>(i), SKey{conn, Dir::AtoB}});
      buckets_.erase({static_cast<std::uint32_t>(i), SKey{conn, Dir::BtoA}});
    }
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
    return res;
  }

  bool has_pending_work() const override {
    // A live run makes progress until stopped externally; the reactor's
    // replay-style termination uses the ledger engine instead.
    return true;
  }

 private:
  struct BKey {
    std::uint32_t rule;
    SKey stream;
    bool operator<(const BKey& o) const { return rule != o.rule ? rule < o.rule : stream < o.stream; }
  };

  static json::Value resolved_obj() { return json::Value::object(); }

  std::uint64_t next_event_index() { return event_counter_++; }

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

  CompiledScenario sc_;
  std::vector<RuleRt> rules_rt_;
  Scheduler* sched_ = nullptr;
  TimeUs epoch_ = 0;
  Rng rng_{};
  std::uint64_t event_counter_ = 1;

  std::map<SKey, ReorderWindow> reorder_;
  std::map<BKey, Bucket> buckets_;
};

}  // namespace

std::unique_ptr<INetworkMutator> make_live_fault_engine(const CompiledScenario& scenario) {
  return std::make_unique<LiveEngine>(scenario);
}

}  // namespace loki
