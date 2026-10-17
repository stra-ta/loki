// LedgerEngine: mechanical re-application of recorded RESOLVED decisions.
// No RNG anywhere: every sampled outcome comes from the ledger's parameters.

#include <loki/version.hpp>
#include <loki/replay.hpp>

#include <algorithm>
#include <map>
#include <optional>
#include <stdexcept>
#include <utility>

namespace loki {
namespace {

std::uint64_t get_u64(const json::Value& obj, const char* key, std::uint64_t dflt = 0) {
  const json::Value* v = obj.find(key);
  if (v == nullptr) return dflt;
  if (v->type() == json::Value::Type::UInt) return v->as_uint();
  if (v->type() == json::Value::Type::Int && v->as_int() >= 0)
    return static_cast<std::uint64_t>(v->as_int());
  return dflt;
}

struct StreamKeyLess {
  bool operator()(const StreamKey& a, const StreamKey& b) const {
    if (a.conn != b.conn) return a.conn < b.conn;
    return static_cast<int>(a.dir) < static_cast<int>(b.dir);
  }
};

struct StreamState {
  std::size_t cursor = 0;                    // next unconsumed decision index
  std::vector<OutPiece> reorder_held;        // held pieces awaiting window flush
  bool reorder_flush_scheduled = false;
};

class ReplayEngine final : public INetworkMutator, public LedgerEngine {
 public:
  ReplayEngine(LoadedLedger ledger, LedgerEngineOptions options)
      : options_(options) {
    // Index by (conn ordinal, direction); order by (stream_offset, event_index).
    for (auto& d : ledger.decisions) by_stream_[{d.conn, d.dir}].push_back(std::move(d));
    for (auto& [k, list] : by_stream_) {
      std::stable_sort(list.begin(), list.end(),
                       [](const FaultDecision& a, const FaultDecision& b) {
                         if (a.stream_offset != b.stream_offset)
                           return a.stream_offset < b.stream_offset;
                         return a.event_index < b.event_index;
                       });
      total_decisions_ += list.size();
    }
  }

  // --- INetworkMutator ---

  void bind(Scheduler* scheduler, TimeUs epoch) override {
    scheduler_ = scheduler;
    epoch_ = epoch;
  }

  ProcessResult process_read(const StreamKey& key,
                             std::uint64_t chunk_logical_offset,
                             std::span<const std::byte> data,
                             const StreamStats&,
                             TimeUs now) override {
    ProcessResult result;
    if (data.empty()) return result;

    auto it = by_stream_.find(key);
    if (it == by_stream_.end() || it->second.empty()) {
      ++stats_.position_misses;
      return passthrough(chunk_logical_offset, data);
    }
    auto& list = it->second;
    StreamState& st = streams_[key];
    const std::uint64_t chunk_end = chunk_logical_offset + data.size();

    // Consume every pending recorded decision whose position falls inside
    // this chunk's pristine span.
    std::vector<const FaultDecision*> matched;
    while (st.cursor < list.size() && list[st.cursor].stream_offset < chunk_end) {
      matched.push_back(&list[st.cursor]);
      ++st.cursor;
      ++consumed_total_;
      ++stats_.reapplied;
    }

    // Effects replay in recorded chronological order (event_index); position
    // matching above only decides WHICH decisions belong to this chunk.
    std::stable_sort(matched.begin(), matched.end(),
                     [](const FaultDecision* a, const FaultDecision* b) {
                       return a->event_index < b->event_index;
                     });

    if (matched.empty()) {
      ++stats_.position_misses;
      return passthrough(chunk_logical_offset, data);
    }

    // Start with one piece covering the whole chunk.
    std::vector<OutPiece> pieces;
    OutPiece whole;
    whole.payload.assign(data.begin(), data.end());
    whole.logical_offset = chunk_logical_offset;
    whole.immediate = true;
    pieces.push_back(std::move(whole));

    for (const FaultDecision* d : matched) apply_decision(*d, key, pieces, st, now);

    result.pieces = std::move(pieces);
    return result;
  }

  void on_connection_accepted(ConnId conn, TimeUs now) override {
    // Replay contract: exactly one connect action per accepted connection.
    // Immediate upstream unless a ledger decision defers it.
    scheduler_->push(now, ActConnectUpstream{conn});
  }

  void on_connection_established(ConnId, TimeUs) override {}

  void on_connection_closed(ConnId conn, TimeUs, ClosedReason) override {
    scheduler_->drop_connection(conn);
    for (auto& [k, st] : streams_) {
      if (k.conn == conn) {
        st.reorder_held.clear();
        st.reorder_flush_scheduled = false;
      }
    }
  }

  ProcessResult on_engine_timer(const ScheduledAction& origin, TimeUs now) override {
    ProcessResult out;
    const auto* fr = std::get_if<ActFlushReorder>(&origin);
    if (fr == nullptr) return out;
    auto it = streams_.find(fr->key);
    if (it == streams_.end()) return out;
    out.pieces = flush_reorder(it->second, now);
    return out;
  }

  // --- LedgerEngine ---

  const Stats& stats() const override {
    stats_.unconsumed = total_decisions_ - consumed_total_;
    return stats_;
  }

  // --- INetworkMutator: replay termination ---

  bool has_pending_work() const override { return consumed_total_ < total_decisions_; }

 private:
  static ProcessResult passthrough(std::uint64_t off, std::span<const std::byte> data) {
    ProcessResult r;
    OutPiece p;
    p.payload.assign(data.begin(), data.end());
    p.logical_offset = off;
    r.pieces.push_back(std::move(p));
    return r;
  }

  void stamp_send_at(std::vector<OutPiece>& pieces, TimeUs at) {
    for (auto& p : pieces) {
      // Later stamps win; traffic never accelerates.
      if (p.immediate || at > p.send_at_us) {
        p.send_at_us = at;
        p.immediate = false;
      }
    }
  }

  std::vector<OutPiece> flush_reorder(StreamState& st, TimeUs) {
    std::vector<OutPiece> out;
    out.swap(st.reorder_held);
    st.reorder_flush_scheduled = false;
    return out;
  }

  void schedule_reorder_flush(const StreamKey& key, StreamState& st,
                              const json::Value& params, TimeUs now) {
    if (st.reorder_flush_scheduled) return;
    const std::uint64_t max_hold_us = get_u64(params, "max_hold_us", 1000);
    scheduler_->push(now + static_cast<TimeUs>(max_hold_us), ActFlushReorder{key});
    st.reorder_flush_scheduled = true;
  }

  void apply_reorder_order(const json::Value& params, std::vector<OutPiece>& pieces) {
    const json::Value* order = params.find("order");
    if (order == nullptr || order->type() != json::Value::Type::Array) return;
    std::vector<OutPiece> permuted;
    permuted.reserve(order->items().size());
    for (const auto& idxv : order->items()) {
      std::uint64_t i = 0;
      if (idxv.type() == json::Value::Type::UInt) i = idxv.as_uint();
      else if (idxv.type() == json::Value::Type::Int && idxv.as_int() >= 0)
        i = static_cast<std::uint64_t>(idxv.as_int());
      if (i < pieces.size()) permuted.push_back(std::move(pieces[i]));
    }
    // Any indices not named in `order` (shouldn't happen in a valid ledger)
    // keep relative tail order rather than dropping bytes.
    std::vector<bool> taken(pieces.size(), false);
    for (const auto& idxv : order->items()) {
      std::uint64_t i = idxv.type() == json::Value::Type::UInt ? idxv.as_uint() : ~0ull;
      if (i < taken.size()) taken[i] = true;
    }
    for (std::size_t i = 0; i < pieces.size(); ++i) {
      if (!taken[i] && !pieces[i].payload.empty()) permuted.push_back(std::move(pieces[i]));
    }
    pieces = std::move(permuted);
  }

  void apply_decision(const FaultDecision& d, const StreamKey& key,
                      std::vector<OutPiece>& pieces, StreamState& st, TimeUs now) {
    const json::Value& p = d.resolved;
    switch (d.kind) {
      case FaultKind::Latency:
        stamp_send_at(pieces, now + static_cast<TimeUs>(get_u64(p, "delay_us")));
        break;
      case FaultKind::Bandwidth:
        stamp_send_at(pieces, now + static_cast<TimeUs>(get_u64(p, "waited_us")));
        break;
      case FaultKind::Duplicate: {
        std::uint32_t count =
            static_cast<std::uint32_t>(get_u64(p, "count", 1));
        std::vector<OutPiece> doubled;
        doubled.reserve(pieces.size() * (1 + count));
        for (const auto& piece : pieces) {
          doubled.push_back(piece);  // original
          for (std::uint32_t c = 0; c < count; ++c) doubled.push_back(piece);
        }
        pieces = std::move(doubled);
        break;
      }
      case FaultKind::Corrupt: {
        if (!d.applied) break;  // missed target on record: replay as no-op
        const std::uint64_t target = get_u64(p, "offset");
        const auto value = static_cast<std::uint8_t>(get_u64(p, "value"));
        bool overwrite = false;
        if (const json::Value* m = p.find("mode");
            m != nullptr && m->type() == json::Value::Type::String) {
          overwrite = m->as_str() == "overwrite";
        }
        for (auto& piece : pieces) {
          const std::uint64_t lo = piece.logical_offset;
          if (target >= lo && target < lo + piece.payload.size()) {
            auto& byte = piece.payload[target - lo];
            byte = overwrite ? std::byte{value} : byte ^ std::byte{value};
            break;
          }
        }
        break;
      }
      case FaultKind::Fragment: {
        const json::Value* sizes = p.find("sizes");
        if (sizes == nullptr || sizes->type() != json::Value::Type::Array ||
            sizes->items().empty())
          break;
        // Concatenate current bytes, then split per the resolved sizes array.
        std::vector<std::byte> all;
        std::uint64_t base = pieces.empty() ? d.stream_offset : pieces.front().logical_offset;
        for (const auto& piece : pieces) {
          all.insert(all.end(), piece.payload.begin(), piece.payload.end());
        }
        std::vector<OutPiece> parts;
        std::size_t pos = 0;
        for (const auto& sv : sizes->items()) {
          std::uint64_t n = sv.type() == json::Value::Type::UInt ? sv.as_uint()
                            : sv.type() == json::Value::Type::Int && sv.as_int() > 0
                                ? static_cast<std::uint64_t>(sv.as_int())
                                : 0;
          if (n == 0 || pos >= all.size()) continue;
          n = std::min<std::uint64_t>(n, all.size() - pos);
          OutPiece part;
          part.payload.assign(all.begin() + static_cast<std::ptrdiff_t>(pos),
                              all.begin() + static_cast<std::ptrdiff_t>(pos + n));
          part.logical_offset = base + pos;
          part.immediate = true;
          parts.push_back(std::move(part));
          pos += n;
        }
        if (pos < all.size()) {
          OutPiece rest;
          rest.payload.assign(all.begin() + static_cast<std::ptrdiff_t>(pos), all.end());
          rest.logical_offset = base + pos;
          rest.immediate = true;
          parts.push_back(std::move(rest));
        }
        pieces = std::move(parts);
        break;
      }
      case FaultKind::Reorder: {
        const std::uint64_t depth = get_u64(p, "depth", 2);
        auto& held = st.reorder_held;
        for (auto& piece : pieces) held.push_back(std::move(piece));
        pieces.clear();
        schedule_reorder_flush(key, st, p, now);
        if (held.size() >= depth) {
          apply_reorder_order(p, held);
          for (auto& h : held) pieces.push_back(std::move(h));
          held.clear();
          st.reorder_flush_scheduled = false;
        }
        break;
      }
    }
  }

  LedgerEngineOptions options_;
  Scheduler* scheduler_ = nullptr;
  TimeUs epoch_ = 0;
  std::map<StreamKey, std::vector<FaultDecision>, StreamKeyLess> by_stream_;
  std::map<StreamKey, StreamState, StreamKeyLess> streams_;
  std::uint64_t total_decisions_ = 0;
  std::uint64_t consumed_total_ = 0;
  mutable Stats stats_{};
};

}  // namespace

std::unique_ptr<INetworkMutator> make_ledger_engine(const CompiledScenario& scenario,
                                                    LoadedLedger ledger,
                                                    LedgerEngineOptions options) {
  (void)scenario;  // positions come from the ledger; scenario kept for identity
  return std::make_unique<ReplayEngine>(std::move(ledger), options);
}

}  // namespace loki
