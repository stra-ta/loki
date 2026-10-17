// Fault-engine tests. Scenarios are built through compile_scenario() (the real
// config package) from YAML strings; the engine is driven directly with virtual
// times. No threads, no sockets.
//
// NOTE on the scheduler: tests use whatever loki_core provides. While the
// transport-core package is landing, verification may use a scratch reference
// scheduler implementing the frozen header.

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include <loki/engine.hpp>
#include <loki/scheduler.hpp>

using namespace loki;

namespace {

std::span<const std::byte> bytes_of(const std::string& s) {
  return std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.data()), s.size());
}

std::string as_string(const std::vector<std::byte>& v) {
  return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}

struct Harness {
  CompiledScenario sc;
  // Per-test scheduler with a stable identity for the harness lifetime; the
  // mutator only borrows the pointer, and declaration order keeps the
  // scheduler alive until after the engine is destroyed.
  std::unique_ptr<Scheduler> sch = std::make_unique<Scheduler>();
  std::unique_ptr<INetworkMutator> eng;

  explicit Harness(const std::string& yaml, TimeUs epoch = 0)
      : sc(compile_scenario(yaml)), eng(make_live_fault_engine(sc)) {
    eng->bind(sch.get(), epoch);
  }

  ProcessResult read(ConnId conn, Dir dir, std::uint64_t offset, const std::string& data,
                     TimeUs now, std::uint64_t chunks_before = 0) {
    StreamStats stats{offset, chunks_before};
    return eng->process_read(StreamKey{conn, dir}, offset, bytes_of(data), stats, now);
  }
};

std::vector<Scheduler::Due> due(Scheduler& sch, TimeUs now) {
  std::vector<Scheduler::Due> out;
  sch.pop_due(now, out);
  return out;
}

const std::string kBase = R"(version: 1
seed: 7
listen: ":9000"
upstream: "127.0.0.1:9001"
)";

std::string with_rule(const std::string& rule_yaml) {
  return kBase + "rules:\n" + rule_yaml;
}

}  // namespace

// ---------------------------------------------------------------------------

TEST_CASE("passthrough with zero rules echoes pieces immediately", "[faults]") {
  Harness h(kBase);
  auto r = h.read(1, Dir::AtoB, 100, "hello", 5);
  REQUIRE(r.pieces.size() == 1);
  CHECK(as_string(r.pieces[0].payload) == "hello");
  CHECK(r.pieces[0].logical_offset == 100);
  CHECK(r.pieces[0].immediate);
  CHECK(r.decisions.empty());
}

TEST_CASE("fragment splits byte-exact with order preserved and sizes recorded", "[faults]") {
  Harness h(with_rule(R"(
  - name: frag
    inject:
      fragment:
        min: 2
        max: 4
)"));
  const std::string payload = "abcdefghijklmnop";  // 16 bytes
  auto r = h.read(1, Dir::AtoB, 0, payload, 0);
  REQUIRE(r.decisions.size() == 1);
  CHECK(r.decisions[0].kind == FaultKind::Fragment);
  REQUIRE(r.decisions[0].resolved.find("sizes") != nullptr);

  std::string joined;
  std::vector<std::uint64_t> sizes;
  std::uint64_t expected_off = 0;
  for (const auto& pc : r.pieces) {
    joined += as_string(pc.payload);
    sizes.push_back(pc.payload.size());
    CHECK(pc.logical_offset == expected_off);
    expected_off += pc.payload.size();
  }
  CHECK(joined == payload);  // byte-exact multiset + order preserved
  const auto* arr = r.decisions[0].resolved.find("sizes");
  REQUIRE(arr != nullptr);
  REQUIRE(arr->items().size() == r.pieces.size());
  for (std::size_t i = 0; i < arr->items().size(); ++i) {
    CHECK(arr->items()[i].as_int() == static_cast<std::int64_t>(r.pieces[i].payload.size()));
  }
  // deterministic across replays
  Harness h2(with_rule(R"(
  - name: frag
    inject:
      fragment:
        min: 2
        max: 4
)"));
  auto r2 = h2.read(1, Dir::AtoB, 0, payload, 0);
  REQUIRE(r2.pieces.size() == r.pieces.size());
  for (std::size_t i = 0; i < r.pieces.size(); ++i) {
    CHECK(as_string(r2.pieces[i].payload) == as_string(r.pieces[i].payload));
  }
}

TEST_CASE("reorder depth-2 releases a valid permutation of two pieces", "[faults]") {
  Harness h(with_rule(R"(
  - name: ro
    inject:
      reorder:
        depth: 2
        max_hold: 10ms
)"));
  auto r1 = h.read(1, Dir::AtoB, 0, "AAAA", 0);
  CHECK(r1.pieces.empty());  // held
  auto r2 = h.read(1, Dir::AtoB, 4, "BBBB", 10);
  REQUIRE(r2.pieces.size() == 2);

  // Same bytes out, exactly once each.
  std::string all = as_string(r2.pieces[0].payload) + as_string(r2.pieces[1].payload);
  CHECK((all == "AAAABBBB" || all == "BBBBAAAA"));

  // order array matches emission: order[k] indexes into the held sequence.
  REQUIRE(r2.decisions.size() == 1);
  CHECK(r2.decisions[0].kind == FaultKind::Reorder);
  const auto* order = r2.decisions[0].resolved.find("order");
  REQUIRE(order != nullptr);
  REQUIRE(order->items().size() == 2);
  const int first = static_cast<int>(order->items()[0].as_uint());
  CHECK(as_string(r2.pieces[0].payload) == (first == 0 ? "AAAA" : "BBBB"));

  // Deterministic permutation on replay.
  Harness h2(with_rule(R"(
  - name: ro
    inject:
      reorder:
        depth: 2
        max_hold: 10ms
)"));
  h2.read(1, Dir::AtoB, 0, "AAAA", 0);
  auto r2b = h2.read(1, Dir::AtoB, 4, "BBBB", 10);
  REQUIRE(r2b.pieces.size() == 2);
  CHECK(as_string(r2b.pieces[0].payload) == as_string(r2.pieces[0].payload));
  CHECK(as_string(r2b.pieces[1].payload) == as_string(r2.pieces[1].payload));
}

TEST_CASE("reorder flushes on max_hold deadline", "[faults]") {
  Harness h(with_rule(R"(
  - name: ro
    inject:
      reorder:
        depth: 8
        max_hold: 300us
)"));
  h.read(1, Dir::AtoB, 0, "X", 0);
  auto fired = due(*h.sch, 300);
  REQUIRE(!fired.empty());
  bool found = false;
  for (auto& f : fired) {
    if (auto* p = std::get_if<ActFlushReorder>(&f.action)) {
      if (p->key.conn == 1 && p->key.dir == Dir::AtoB) found = true;
    }
  }
  CHECK(found);
  auto r = h.eng->on_engine_timer(fired[0].action, 300);
  REQUIRE(r.pieces.size() == 1);
  CHECK(as_string(r.pieces[0].payload) == "X");
  REQUIRE(r.decisions.size() == 1);
  CHECK(r.decisions[0].kind == FaultKind::Reorder);
}

TEST_CASE("latency uniform stamps send_at within jitter bounds", "[faults]") {
  Harness h(with_rule(R"(
  - name: lat
    inject:
      latency:
        mean: 100us
        jitter: 50us
)"));
  auto r = h.read(1, Dir::AtoB, 0, "z", 1000);
  REQUIRE(r.pieces.size() == 1);
  CHECK(!r.pieces[0].immediate);
  // delay in [50,150] => send_at in [1050,1150]
  CHECK(r.pieces[0].send_at_us >= 1050);
  CHECK(r.pieces[0].send_at_us <= 1150);
  REQUIRE(r.decisions.size() == 1);
  const auto* d = r.decisions[0].resolved.find("delay_us");
  REQUIRE(d != nullptr);
  CHECK(d->as_int() == r.pieces[0].send_at_us - 1000);
  CHECK(d->as_int() >= 50);
  CHECK(d->as_int() <= 150);
}

TEST_CASE("latency normal distribution is deterministic", "[faults]") {
  const std::string yaml = with_rule(R"(
  - name: latn
    inject:
      latency:
        mean: 200us
        distribution: normal
        stddev: 25us
)");
  Harness h(yaml);
  auto r1 = h.read(1, Dir::AtoB, 0, "a", 0);
  Harness h2(yaml);
  auto r2 = h2.read(1, Dir::AtoB, 0, "a", 0);
  REQUIRE(r1.pieces.size() == 1);
  CHECK(r1.pieces[0].send_at_us == r2.pieces[0].send_at_us);
  const auto* d = r1.decisions[0].resolved.find("delay_us");
  REQUIRE(d != nullptr);
  CHECK(r1.pieces[0].send_at_us == d->as_int());
}

TEST_CASE("token bucket paces by rate and records waited_us", "[faults]") {
  // rate 100 B/s, burst 10: a 30-byte chunk spends the burst, then pays
  // deficit time on a serialized wire clock: deficit 20 bytes -> +200000us.
  Harness h(with_rule(R"(
  - name: bw
    inject:
      bandwidth:
        rate: 100
        burst: 10
)"));
  auto r = h.read(1, Dir::AtoB, 0, std::string(30, 'q'), 1000);
  REQUIRE(r.pieces.size() == 1);
  CHECK(!r.pieces[0].immediate);
  // tokens=10 consumed now; deficit=20 bytes at 100 B/s -> 200000us wait
  CHECK(r.pieces[0].send_at_us == 1000 + 200000);
  const auto* w = r.decisions[0].resolved.find("waited_us");
  REQUIRE(w != nullptr);
  CHECK(w->as_int() == 200000);

  // The wire clock serializes: this chunk cannot start before the previous
  // one finishes at 201000. Real-time refill over dt=100us adds only
  // 100 B/s * 100us = 0.01 tokens, so deficit 14.99 -> ceil = 149900us more.
  auto r2 = h.read(1, Dir::AtoB, 30, std::string(15, 'q'), 1100);
  REQUIRE(r2.pieces.size() == 1);
  CHECK(r2.pieces[0].send_at_us == 350900);
  const auto* w2 = r2.decisions[0].resolved.find("waited_us");
  REQUIRE(w2 != nullptr);
  CHECK(w2->as_int() == 349800);  // measured from now=1100
}

TEST_CASE("duplicate replicates pieces count times with same offsets", "[faults]") {
  Harness h(with_rule(R"(
  - name: dup
    inject:
      duplicate:
        count: 3
)"));
  auto r = h.read(1, Dir::AtoB, 40, "ab", 0);
  REQUIRE(r.pieces.size() == 3);
  for (const auto& pc : r.pieces) {
    CHECK(as_string(pc.payload) == "ab");
    CHECK(pc.logical_offset == 40);
  }
  REQUIRE(r.decisions.size() == 1);
  const auto* c = r.decisions[0].resolved.find("count");
  REQUIRE(c != nullptr);
  CHECK(c->as_int() == 3);
}

TEST_CASE("corrupt xor, overwrite, and applied=false miss", "[faults]") {
  Harness hx(with_rule(R"(
  - name: cx
    inject:
      corrupt:
        mode: xor
        offset: 3
        value: 15
)"));
  auto rx = hx.read(1, Dir::AtoB, 0, "abcdef", 0);
  REQUIRE(rx.pieces.size() == 1);
  std::string got = as_string(rx.pieces[0].payload);
  CHECK(got[3] == static_cast<char>('d' ^ 15));
  const auto* dec = &rx.decisions[0];
  CHECK(dec->resolved.find("applied")->as_bool());
  CHECK(dec->resolved.find("byte")->as_int() == ('d' ^ 15));

  Harness ho(with_rule(R"(
  - name: co
    inject:
      corrupt:
        mode: overwrite
        offset: 3
        value: 90
)"));
  auto ro = ho.read(1, Dir::AtoB, 0, "abcdef", 0);
  CHECK(as_string(ro.pieces[0].payload)[3] == static_cast<char>(90));
  CHECK(ro.decisions[0].resolved.find("applied")->as_bool());

  Harness hm(with_rule(R"(
  - name: cm
    inject:
      corrupt:
        mode: xor
        offset: 100
        value: 1
)"));
  auto rm = hm.read(1, Dir::AtoB, 0, "abcdef", 0);
  CHECK(as_string(rm.pieces[0].payload) == "abcdef");  // untouched
  CHECK(rm.decisions.size() == 1);
  CHECK_FALSE(rm.decisions[0].resolved.find("applied")->as_bool());
  CHECK_FALSE(rm.decisions[0].applied);
}

TEST_CASE("probability draws only after deterministic guards pass", "[faults]") {
  // Engine A: guard always fails (after: 1h), then fragment rule.
  // Engine B: fragment rule alone. A must match B exactly (no draw consumed).
  const std::string frag = R"(
  - name: frag2
    inject:
      fragment:
        min: 3
        max: 5
)";
  const std::string guarded = R"(
  - name: never
    when:
      probability: 0.5
      after: 1h
    inject:
      duplicate:
        count: 2
)";
  Harness a(with_rule(guarded + frag));
  auto ra = a.read(1, Dir::AtoB, 0, "0123456789ABCDEF", 0);
  Harness b(with_rule(frag));
  auto rb = b.read(1, Dir::AtoB, 0, "0123456789ABCDEF", 0);
  REQUIRE(rb.pieces.size() == ra.pieces.size());
  for (std::size_t i = 0; i < ra.pieces.size(); ++i) {
    CHECK(as_string(ra.pieces[i].payload) == as_string(rb.pieces[i].payload));
  }
  CHECK(ra.decisions.size() == 1);  // only the fragment decision

  // When the probability guard PASSES it must consume a draw: engine C's
  // fragment sizes differ from B's for this seed (verified deterministically).
  const std::string firing = R"(
  - name: sometimes
    when:
      probability: 0.999999
    inject:
      duplicate:
        count: 2
)";
    Harness c(with_rule(firing + frag));
  auto rc = c.read(1, Dir::AtoB, 0, "0123456789ABCDEF", 0);
  // With a draw consumed before fragment, C's split pattern differs from B's
  // for this seed with overwhelming likelihood; assert it to pin the ordering.
  bool differs = rc.pieces.size() != rb.pieces.size();
  for (std::size_t i = 0; i < std::min(rc.pieces.size(), rb.pieces.size()); ++i) {
    if (as_string(rc.pieces[i].payload) != as_string(rb.pieces[i].payload)) differs = true;
  }
  CHECK(differs);
}

TEST_CASE("max_occurrences caps total firings per rule", "[faults]") {
  Harness h(with_rule(R"(
  - name: cap
    when:
      max_occurrences: 2
    inject:
      duplicate:
        count: 2
)"));
  for (int i = 0; i < 5; ++i) {
    auto r = h.read(1, Dir::AtoB, static_cast<std::uint64_t>(i * 2), "xy",
                    static_cast<TimeUs>(i * 10));
    if (i < 2) {
      CHECK(r.pieces.size() == 2);
    } else {
      CHECK(r.pieces.size() == 1);
    }
  }
}

TEST_CASE("every_bytes fires once per crossing of a new multiple", "[faults]") {
  Harness h(with_rule(R"(
  - name: eb
    when:
      every_bytes: 100
    inject:
      duplicate:
        count: 2
)"));
  // chunk 1: bytes 0..99 -> crosses multiple 1 -> fires
  auto r1 = h.read(1, Dir::AtoB, 0, std::string(100, 'a'), 0);
  CHECK(r1.pieces.size() == 2);
  // chunk 2: bytes 100..149 -> no new multiple -> silent
  auto r2 = h.read(1, Dir::AtoB, 100, std::string(50, 'b'), 10);
  CHECK(r2.pieces.size() == 1);
  // chunk 3: bytes 150..250 -> crosses multiple 2 -> fires once
  auto r3 = h.read(1, Dir::AtoB, 150, std::string(101, 'c'), 20);
  CHECK(r3.pieces.size() == 2);
}

TEST_CASE("every_events fires once per chunk-count multiple", "[faults]") {
  Harness h(with_rule(R"(
  - name: ev
    when:
      every_events: 3
    inject:
      duplicate:
        count: 2
)"));
  int fires = 0;
  for (int i = 0; i < 7; ++i) {
    auto r = h.read(1, Dir::AtoB, static_cast<std::uint64_t>(i), "x", 0,
                    static_cast<std::uint64_t>(i));
    if (r.pieces.size() == 2) ++fires;
  }
  CHECK(fires == 2);  // events 3 and 6
}

TEST_CASE("connection selector filters by ordinal", "[faults]") {
  Harness h(with_rule(R"(
  - name: sel
    when:
      connection:
        every: 2
        equals: 0
    inject:
      duplicate:
        count: 2
)"));
  CHECK(h.read(2, Dir::AtoB, 0, "x", 0).pieces.size() == 2);  // 2 % 2 == 0
  CHECK(h.read(3, Dir::AtoB, 0, "x", 0).pieces.size() == 1);  // filtered
}

TEST_CASE("direction filter applies to named direction only", "[faults]") {
  Harness h(with_rule(R"(
  - name: one_way
    when:
      direction: b_to_a
    inject:
      duplicate:
        count: 2
)"));
  CHECK(h.read(1, Dir::AtoB, 0, "x", 0).pieces.size() == 1);
  CHECK(h.read(1, Dir::BtoA, 0, "x", 0).pieces.size() == 2);
}

TEST_CASE("min_stream_offset and after guards gate matching", "[faults]") {
  Harness h(with_rule(R"(
  - name: gated
    when:
      after: 100us
      min_stream_offset: 50
    inject:
      duplicate:
        count: 2
)"));
  CHECK(h.read(1, Dir::AtoB, 49, "x", 200).pieces.size() == 1);  // offset fails
  CHECK(h.read(1, Dir::AtoB, 60, "x", 50).pieces.size() == 1);   // elapsed fails
  CHECK(h.read(1, Dir::AtoB, 60, "x", 100).pieces.size() == 2);  // passes
}

TEST_CASE("on_connection_closed cancels pending state", "[faults]") {
  Harness h(with_rule(R"(
  - name: hold2
    inject:
      reorder:
        depth: 4
        max_hold: 1ms
)"));
  auto held = h.read(4, Dir::AtoB, 0, "x", 0);
  CHECK(held.pieces.empty());     // held by the reorder window
  CHECK(h.sch->size() > 0);       // flush timer armed
  h.eng->on_connection_closed(4, 10, ClosedReason::ServerClosed);
  CHECK(due(*h.sch, 5000).empty());  // conn 4's flush was tombstoned
  // Other connections keep working: conn 5 starts its own window and the
  // held bytes release through the engine timer path.
  auto held5 = h.read(5, Dir::AtoB, 0, "y", 20);
  CHECK(held5.pieces.empty());
  auto flushed = h.eng->on_engine_timer(ActFlushReorder{StreamKey{5, Dir::AtoB}}, 40);
  CHECK(flushed.pieces.size() == 1);
  CHECK(as_string(flushed.pieces[0].payload) == "y");
}

TEST_CASE("event_index is global and starts at 1 across decisions", "[faults]") {
  Harness h(with_rule(R"(
  - name: dup2
    inject:
      duplicate:
        count: 2
  - name: dup3
    inject:
      duplicate:
        count: 3
)"));
  auto r = h.read(1, Dir::AtoB, 0, "x", 0);
  REQUIRE(r.decisions.size() == 2);
  CHECK(r.decisions[0].event_index == 1);
  CHECK(r.decisions[1].event_index == 2);
  // pieces: dup2 makes 2, dup3 triples them
  CHECK(r.pieces.size() == 6);
  h.eng->on_connection_accepted(9, 0);  // default connect schedules ActConnectUpstream only
}

TEST_CASE("full determinism: identical seed and script produce identical runs", "[faults]") {
  const std::string yaml = with_rule(R"(
  - name: fragD
    when:
      probability: 0.8
    inject:
      fragment:
        min: 1
        max: 6
  - name: latD
    when:
      connection:
        every: 1
    inject:
      latency:
        mean: 50us
        jitter: 40us
  - name: dupD
    when:
      every_events: 2
    inject:
      duplicate:
        count: 2
)");

  auto run = [&](Harness& h) {
    std::vector<std::string> trace;
    std::uint64_t off = 0;
    for (int i = 0; i < 10; ++i) {
      const std::string data(static_cast<std::size_t>(i % 3 + 1),
                             static_cast<char>('A' + i));
      auto r = h.read(1, Dir::AtoB, off, data, static_cast<TimeUs>(i * 120),
                      static_cast<std::uint64_t>(i));
      off += data.size();
      for (const auto& pc : r.pieces) {
        trace.push_back(as_string(pc.payload) + "@" + std::to_string(pc.logical_offset) +
                        "+" + std::to_string(pc.send_at_us) +
                        (pc.immediate ? "!im" : ""));
      }
      for (const auto& d : r.decisions) {
        trace.push_back(std::to_string(d.event_index) + ":" + d.rule_name + ":" +
                        d.resolved.dump());
      }
    }
    h.eng->on_connection_accepted(3, 5000);
    return trace;
  };

  Harness h1(yaml), h2(yaml);
  auto t1 = run(h1);
  auto t2 = run(h2);
  REQUIRE(t1.size() > 10);  // something actually happened
  CHECK(t1 == t2);
}
