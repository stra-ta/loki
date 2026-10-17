#pragma once

// Global deadline scheduler. One min-heap ordered by (deadline_us, seq).
// Sequence numbers are assigned monotonically at push time, so equal deadlines
// release in insertion order: the determinism backbone of the data plane.
//
// Cancellation is lazy: drop_connection() tombstones an ordinal and stale
// actions are discarded as they surface.

#include <cstdint>
#include <unordered_set>
#include <variant>
#include <vector>

#include <loki/types.hpp>

namespace loki {

struct ActDeliver {
  StreamKey key;                        // direction names the SOURCE flow
  std::vector<std::byte> payload;       // bytes to write toward the far end
  std::uint64_t logical_offset = 0;     // pristine offset for evidence
};

// Release a full reorder window (engine-managed state machine).
struct ActFlushReorder { StreamKey key; };

// Begin the upstream connect for this connection.
struct ActConnectUpstream { ConnId conn; };

using ScheduledAction = std::variant<ActDeliver, ActFlushReorder, ActConnectUpstream>;

class Scheduler {
 public:
  struct Due {
    TimeUs deadline;
    SeqNo seq;
    ScheduledAction action;
  };

  // Pushes an action; assigns and returns its sequence number.
  SeqNo push(TimeUs deadline, ScheduledAction a);

  // Appends all entries with deadline <= now, ordered by (deadline, seq),
  // and removes them from the heap.
  void pop_due(TimeUs now, std::vector<Due>& out);

  // Earliest pending deadline; kTimeMaxSentinel when empty.
  TimeUs next_deadline() const;

  // Tombstones all future actions referencing this connection.
  void drop_connection(ConnId conn);

  std::size_t size() const;

  static constexpr TimeUs kTimeMaxSentinel = ~static_cast<TimeUs>(0);

 private:
  struct Entry {
    TimeUs deadline;
    SeqNo seq;
    ScheduledAction action;
  };
  static bool entry_before(const Entry& a, const Entry& b);  // min-heap comparator

  std::vector<Entry> heap_;
  SeqNo next_seq_ = 1;
  std::unordered_set<ConnId> dropped_;  // lazy tombstones, purged as entries surface
};

}  // namespace loki
