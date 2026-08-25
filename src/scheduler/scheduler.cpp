// Deadline scheduler: single min-heap ordered by (deadline_us, seq).

#include <loki/scheduler.hpp>

#include <algorithm>

namespace loki {

bool Scheduler::entry_before(const Entry& a, const Entry& b) {
  if (a.deadline != b.deadline) return a.deadline > b.deadline;  // min-heap
  return a.seq > b.seq;
}

SeqNo Scheduler::push(TimeUs deadline, ScheduledAction a) {
  const SeqNo seq = next_seq_++;
  heap_.push_back(Entry{deadline, seq, std::move(a)});
  std::push_heap(heap_.begin(), heap_.end(), entry_before);
  return seq;
}

void Scheduler::pop_due(TimeUs now, std::vector<Due>& out) {
  while (!heap_.empty() && heap_.front().deadline <= now) {
    Entry e = std::move(heap_.front());
    std::pop_heap(heap_.begin(), heap_.end(), entry_before);
    heap_.pop_back();
    // Lazy tombstone purge: stale actions are discarded as they surface.
    ConnId conn = 0;
    bool references_conn = false;
    if (auto* d = std::get_if<ActDeliver>(&e.action)) {
      conn = d->key.conn;
      references_conn = true;
    } else if (auto* f = std::get_if<ActFin>(&e.action)) {
      conn = f->conn;
      references_conn = true;
    } else if (auto* h = std::get_if<ActHalfCloseRx>(&e.action)) {
      conn = h->conn;
      references_conn = true;
    } else if (auto* r = std::get_if<ActReset>(&e.action)) {
      conn = r->conn;
      references_conn = true;
    } else if (auto* fr = std::get_if<ActFlushReorder>(&e.action)) {
      conn = fr->key.conn;
      references_conn = true;
    } else if (auto* fc = std::get_if<ActFlushCoalesce>(&e.action)) {
      conn = fc->key.conn;
      references_conn = true;
    } else if (auto* cu = std::get_if<ActConnectUpstream>(&e.action)) {
      conn = cu->conn;
      references_conn = true;
    } else if (auto* rd = std::get_if<ActRefuseDownstream>(&e.action)) {
      conn = rd->conn;
      references_conn = true;
    } else if (auto* id = std::get_if<ActIdleFire>(&e.action)) {
      conn = id->conn;
      references_conn = true;
    }
    // ActResumeListener carries no connection and always survives.
    if (references_conn && dropped_.count(conn) != 0) continue;
    out.push_back(Due{e.deadline, e.seq, std::move(e.action)});
  }
}

TimeUs Scheduler::next_deadline() const {
  if (heap_.empty()) return kTimeMaxSentinel;
  return heap_.front().deadline;
}

void Scheduler::drop_connection(ConnId conn) { dropped_.insert(conn); }

std::size_t Scheduler::size() const { return heap_.size(); }

}  // namespace loki
