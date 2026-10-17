// Scheduler tests: ordering, FIFO ties, boundary inclusivity, lazy tombstones.

#include <catch2/catch_test_macros.hpp>
#include <loki/scheduler.hpp>

#include <algorithm>
#include <limits>
#include <vector>

using namespace loki;

TEST_CASE("scheduler orders by deadline then seq") {
  Scheduler s;
  s.push(100, ActConnectUpstream{1});
  s.push(50, ActFlushReorder{StreamKey{2, Dir::AtoB}});
  s.push(100, ActConnectUpstream{3});
  std::vector<Scheduler::Due> out;
  s.pop_due(std::numeric_limits<TimeUs>::max(), out);
  REQUIRE(out.size() == 3);
  REQUIRE(std::get<ActFlushReorder>(out[0].action).key.conn == 2);
  // Equal deadlines: FIFO by push order (seq).
  REQUIRE(out[1].seq < out[2].seq);
  REQUIRE(std::get<ActConnectUpstream>(out[1].action).conn == 1);
  REQUIRE(std::get<ActConnectUpstream>(out[2].action).conn == 3);
}

TEST_CASE("scheduler pop_due is inclusive at the boundary") {
  Scheduler s;
  const SeqNo q = s.push(42, ActConnectUpstream{9});
  REQUIRE(q == 1);  // monotonic seq starts at 1
  std::vector<Scheduler::Due> out;
  s.pop_due(41, out);
  REQUIRE(out.empty());
  s.pop_due(42, out);  // deadline <= now, inclusive
  REQUIRE(out.size() == 1);
  REQUIRE(s.next_deadline() == Scheduler::kTimeMaxSentinel);
}

TEST_CASE("scheduler tombstones dropped connections lazily") {
  Scheduler s;
  s.push(10, ActDeliver{StreamKey{7, Dir::AtoB}, {}, 0});
  s.push(11, ActFlushReorder{StreamKey{7, Dir::BtoA}});
  s.push(14, ActConnectUpstream{8});  // other conn: untouched
  s.drop_connection(7);

  std::vector<Scheduler::Due> out;
  s.pop_due(20, out);
  REQUIRE(out.size() == 1);
  REQUIRE(std::holds_alternative<ActConnectUpstream>(out[0].action));
}

TEST_CASE("scheduler size and next_deadline") {
  Scheduler s;
  REQUIRE(s.size() == 0);
  REQUIRE(s.next_deadline() == Scheduler::kTimeMaxSentinel);
  s.push(5, ActConnectUpstream{1});
  s.push(3, ActConnectUpstream{1});
  REQUIRE(s.size() == 2);
  REQUIRE(s.next_deadline() == 3);
}
