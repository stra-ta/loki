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
  // Leaked deliberately: guarantees stable, never-reused scheduler identity
  // for the lifetime of the test binary.
  Scheduler* sch = new Scheduler();
  std::unique_ptr<INetworkMutator> eng;

  explicit Harness(const std::string& yaml, TimeUs epoch = 0)
      : sc(compile_scenario(yaml)), eng(make_live_fault_engine(sc)) {
    eng->bind(sch, epoch);
    eng->set_decision_sink([this](FaultDecision d) { sink.push_back(std::move(d)); });
  }

  std::vector<FaultDecision> sink;  // lifecycle decisions captured via set_decision_sink

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

TEST_CASE("coalesce merges until size trigger then emits one piece", "[faults]") {
  Harness h(with_rule(R"(
  - name: coal
    inject:
      coalesce:
        size: 10
        max_delay: 1ms
)"));
  auto r1 = h.read(1, Dir::AtoB, 0, "12345", 10);
  CHECK(r1.pieces.empty());  // held
  auto r2 = h.read(1, Dir::AtoB, 5, "67890", 20);
  REQUIRE(r2.pieces.size() == 1);
  CHECK(as_string(r2.pieces[0].payload) == "1234567890");
  CHECK(r2.pieces[0].logical_offset == 0);  // first held byte offset
  CHECK(!r2.decisions.empty());
}

TEST_CASE("coalesce safety flush fires via ActFlushCoalesce timer", "[faults]") {
  Harness h(with_rule(R"(
  - name: coal
    inject:
      coalesce:
        size: 100
        max_delay: 500us
)"));
  auto r1 = h.read(1, Dir::AtoB, 0, "abc", 100);
  CHECK(r1.pieces.empty());
  auto fired = due(*h.sch, 600);
  bool found = false;
  for (auto& f : fired) {
    if (std::get_if<ActFlushCoalesce>(&f.action)) found = true;
  }
  CHECK(found);
  auto r2 = h.eng->on_engine_timer(fired[0].action, 600);
  REQUIRE(r2.pieces.size() == 1);
  CHECK(as_string(r2.pieces[0].payload) == "abc");
  CHECK(r2.pieces[0].logical_offset == 0);
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

TEST_CASE("blackhole discard drops activation and later chunks, decision only at activation", "[faults]") {
  Harness h(with_rule(R"(
  - name: bh
    when:
      direction: b_to_a
      max_occurrences: 1
    inject:
      blackhole:
        direction: b_to_a
        mode: discard
        duration: 1ms
)"));
  // Discard semantics: chunks are consumed from the first byte of the
  // window onward, including the chunk that activates it.
  auto act = h.read(1, Dir::BtoA, 0, "first", 0);
  CHECK(act.pieces.empty());
  REQUIRE(act.decisions.size() == 1);
  CHECK(act.decisions[0].kind == FaultKind::Blackhole);
  CHECK(act.decisions[0].resolved.find("mode")->as_str() == "discard");
  CHECK(act.decisions[0].resolved.find("duration_us")->as_int() == 1000);

  auto dropped = h.read(1, Dir::BtoA, 5, "gone", 10);
  CHECK(dropped.pieces.empty());
  CHECK(dropped.decisions.empty());

  // Other direction unaffected; window expires after duration.
  auto other = h.read(1, Dir::AtoB, 0, "ok", 10);
  CHECK(other.pieces.size() == 1);
  auto after = h.read(1, Dir::BtoA, 5, "back", 5000);
  CHECK(after.pieces.size() == 1);
}

TEST_CASE("blackhole freeze toggles read_enabled around expiry", "[faults]") {
  Harness h(with_rule(R"(
  - name: bf
    inject:
      blackhole:
        direction: client_to_server
        mode: freeze
        duration: 2ms
)"));
  h.read(1, Dir::AtoB, 0, "x", 0);
  CHECK_FALSE(h.eng->read_enabled(StreamKey{1, Dir::AtoB}, 1999));
  CHECK(h.eng->read_enabled(StreamKey{1, Dir::AtoB}, 2000));  // time-based re-enable
  CHECK(h.eng->read_enabled(StreamKey{1, Dir::BtoA}, 100));   // other flow unaffected
}

TEST_CASE("reset schedules ActReset after its delay", "[faults]") {
  Harness h(with_rule(R"(
  - name: rst
    inject:
      reset:
        after: 250us
)"));
  auto r = h.read(3, Dir::AtoB, 0, "x", 100);
  REQUIRE(r.decisions.size() == 1);
  CHECK(r.decisions[0].kind == FaultKind::Reset);
  CHECK(r.decisions[0].resolved.find("after_us")->as_int() == 250);
  auto fired = due(*h.sch, 350);
  REQUIRE(fired.size() == 1);
  REQUIRE(std::get_if<ActReset>(&fired[0].action) != nullptr);
  CHECK(std::get<ActReset>(fired[0].action).conn == 3);
}

TEST_CASE("fin and half_close map sides to legs correctly", "[faults]") {
  Harness hf(with_rule(R"(
  - name: finc
    inject:
      fin:
        side: server
)"));
  auto rf = hf.read(1, Dir::AtoB, 0, "x", 0);
  REQUIRE(rf.decisions.size() == 1);  // chunk-fault decision, not lifecycle
  CHECK(rf.decisions[0].resolved.find("side")->as_str() == "server");
  CHECK(rf.decisions[0].resolved.find("mode")->as_str() == "tx");
  auto f = due(*hf.sch, 0);
  REQUIRE(f.size() == 1);
  auto* fin = std::get_if<ActFin>(&f[0].action);
  REQUIRE(fin != nullptr);
  CHECK(fin->leg == LegSide::Up);  // server side == Up
  CHECK(fin->conn == 1);
  CHECK(hf.sink.empty());  // fin via chunk read is a ProcessResult decision

  // half_close rx on client side -> ActHalfCloseRx{Down}
  Harness hr(with_rule(R"(
  - name: hc
    inject:
      half_close:
        side: client
        mode: rx
)"));
  auto rh = hr.read(2, Dir::BtoA, 0, "y", 0);
  CHECK(rh.decisions.size() == 1);
  auto g = due(*hr.sch, 0);
  REQUIRE(g.size() == 1);
  auto* rx = std::get_if<ActHalfCloseRx>(&g[0].action);
  REQUIRE(rx != nullptr);
  CHECK(rx->leg == LegSide::Down);  // client side == Down
}

TEST_CASE("connect lifecycle schedules exactly one connect or refuse", "[faults]") {
  SECTION("no rule matches: immediate upstream connect") {
    Harness h(kBase);
    h.eng->on_connection_accepted(1, 100);
    auto f = due(*h.sch, 100);
    REQUIRE(f.size() == 1);
    REQUIRE(std::get_if<ActConnectUpstream>(&f[0].action) != nullptr);
  }
  SECTION("connect_delay defers the upstream connect") {
    Harness h(with_rule(R"(
  - name: cd
    inject:
      connect_delay:
        delay: 5ms
)"));
    h.eng->on_connection_accepted(2, 1000);
    auto f = due(*h.sch, 1000 + 5000);
    REQUIRE(f.size() == 1);
    REQUIRE(std::get_if<ActConnectUpstream>(&f[0].action) != nullptr);
    REQUIRE(h.sink.size() == 1);
    CHECK(h.sink[0].kind == FaultKind::ConnectDelay);
    CHECK(h.sink[0].resolved.find("delay_us")->as_int() == 5000);
  }
  SECTION("refuse closes downstream without upstream") {
    Harness h(with_rule(R"(
  - name: rf
    inject:
      refuse:
        after: 1ms
)"));
    h.eng->on_connection_accepted(4, 0);
    auto f = due(*h.sch, 1000);
    REQUIRE(f.size() == 1);
    REQUIRE(std::get_if<ActRefuseDownstream>(&f[0].action) != nullptr);
  }
}

TEST_CASE("accept_stall disables listener until expiry", "[faults]") {
  Harness h(with_rule(R"(
  - name: st
    inject:
      accept_stall:
        stall: 3ms
)"));
  h.eng->on_connection_accepted(1, 0);
  CHECK_FALSE(h.eng->listener_enabled(2999));
  CHECK(h.eng->listener_enabled(3000));
}

TEST_CASE("idle timeout arms, re-arms, and fires reset and fin actions", "[faults]") {
  const std::string yaml = with_rule(R"(
  - name: idle
    inject:
      idle_timeout:
        idle: 1ms
        action: reset
)");
  Harness h(yaml);
  h.read(1, Dir::AtoB, 0, "a", 0);       // arm @1000
  h.read(1, Dir::AtoB, 1, "b", 400);     // re-arm @1400
  // The @1000 timer surfaces at 1300 but must NOT fire (real deadline 1400);
  // the engine returns empty and re-schedules.
  auto stale = due(*h.sch, 1300);
  for (const auto& s : stale) {
    if (std::get_if<ActIdleFire>(&s.action)) {
      auto nothing = h.eng->on_engine_timer(s.action, 1300);
      CHECK(nothing.pieces.empty());
    }
  }
  CHECK(due(*h.sch, 1399).empty());       // no reset before deadline
  CHECK(h.sink.empty());
  auto f = due(*h.sch, 1400);
  REQUIRE(f.size() == 1);
  auto res = h.eng->on_engine_timer(f[0].action, 1400);
  CHECK(res.pieces.empty());
  auto fired_reset = due(*h.sch, 1400);
  REQUIRE(fired_reset.size() == 1);
  REQUIRE(std::get_if<ActReset>(&fired_reset[0].action) != nullptr);
  REQUIRE(h.sink.size() == 1);
  CHECK(h.sink[0].kind == FaultKind::IdleTimeout);
  CHECK(h.sink[0].applied);
  CHECK(h.sink[0].resolved.find("idle_us")->as_int() == 1000);
  CHECK(h.sink[0].resolved.find("action")->as_str() == "reset");

  SECTION("fin action pushes FIN toward both legs") {
    Harness hf(with_rule(R"(
  - name: idlef
    inject:
      idle_timeout:
        idle: 1ms
        action: fin
)"));
    hf.read(9, Dir::AtoB, 0, "a", 0);
    auto ff = due(*hf.sch, 1000);
    REQUIRE(ff.size() == 1);
    hf.eng->on_engine_timer(ff[0].action, 1000);
    auto acts = due(*hf.sch, 1000);
    REQUIRE(acts.size() == 2);
    int downs = 0, ups = 0;
    for (const auto& a : acts) {
      const auto* fin = std::get_if<ActFin>(&a.action);
      REQUIRE(fin != nullptr);
      if (fin->leg == LegSide::Down) ++downs;
      if (fin->leg == LegSide::Up) ++ups;
    }
    CHECK(downs == 1);
    CHECK(ups == 1);
  }
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
    auto r = h.read(1, Dir::AtoB, i * 2, "xy", i * 10);
    if (i < 2) {
      CHECK(r.pieces.size() == 2);
    } else {
      CHECK(r.pieces.size() == 1);
    }
  }
  CHECK(h.sink.empty());  // process_read decisions are not lifecycle decisions
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
    auto r = h.read(1, Dir::AtoB, i, "x", 0, static_cast<std::uint64_t>(i));
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

TEST_CASE("manual pause/resume and InjectReset behave per spec", "[faults]") {
  Harness h(kBase);
  CHECK(h.eng->manual_action(ManualAction::Pause, 0, 0));
  CHECK_FALSE(h.eng->listener_enabled(1000));
  CHECK(h.eng->manual_action(ManualAction::Resume, 0, 1000));
  CHECK(h.eng->listener_enabled(1000));

  CHECK(h.eng->manual_action(ManualAction::InjectReset, 5, 77));
  auto f = due(*h.sch, 77);
  REQUIRE(f.size() == 1);
  const auto* rst = std::get_if<ActReset>(&f[0].action);
  REQUIRE(rst != nullptr);
  CHECK(rst->conn == 5);
  REQUIRE(h.sink.size() == 1);
  CHECK(h.sink[0].rule_name == "manual-ctl");
  CHECK(h.sink[0].kind == FaultKind::Reset);
  CHECK(h.sink[0].applied);
  CHECK(h.sink[0].stream_offset == 0);
  CHECK(h.sink[0].inputs.bytes_seen == 0);
  CHECK(h.sink[0].inputs.elapsed_us == 0);
  CHECK(h.sink[0].resolved.find("after_us")->as_int() == 0);
}

TEST_CASE("on_connection_closed cancels pending state", "[faults]") {
  Harness h(with_rule(R"(
  - name: rst2
    inject:
      reset:
        after: 1ms
)"));
  h.read(4, Dir::AtoB, 0, "x", 0);
  CHECK(h.sch->size() > 0);
  h.eng->on_connection_closed(4, 10, ClosedReason::FaultReset);
  CHECK(due(*h.sch, 5000).empty());  // tombstoned
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
  h.eng->on_connection_accepted(9, 0);  // default connect logs nothing here
  CHECK(h.sink.empty());
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
      const std::string data(i % 3 + 1, static_cast<char>('A' + i));
      auto r = h.read(1, Dir::AtoB, off, data, i * 120, static_cast<std::uint64_t>(i));
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
    for (const auto& d : h.sink) {
      trace.push_back("L:" + std::to_string(d.event_index) + ":" + d.resolved.dump());
    }
    return trace;
  };

  Harness h1(yaml), h2(yaml);
  auto t1 = run(h1);
  auto t2 = run(h2);
  REQUIRE(t1.size() > 10);  // something actually happened
  CHECK(t1 == t2);
}
