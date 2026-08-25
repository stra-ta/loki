// Replay package tests: ledger loader and LedgerEngine mechanics.

#include <catch2/catch_test_macros.hpp>

#include <unistd.h>
#include <cstdlib>
#include <cstdlib>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <loki/json.hpp>
#include <loki/json_parse.hpp>
#include <loki/version.hpp>
#include <loki/replay.hpp>

using namespace loki;
namespace fs = std::filesystem;

namespace {

std::string make_temp_dir() {
  char tmpl[] = "/tmp/loki-replay-test-XXXXXX";
  char* dir = ::mkdtemp(tmpl);
  REQUIRE(dir != nullptr);
  return dir;
}

void write_file(const std::string& path, const std::string& data) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f << data;
}

FaultDecision make_decision(std::uint64_t event, ConnId conn, Dir dir,
                            std::uint64_t offset, FaultKind kind, json::Value params) {
  FaultDecision d;
  d.event_index = event;
  d.conn = conn;
  d.dir = dir;
  d.stream_offset = offset;
  d.rule_index = 0;
  d.rule_name = "r";
  d.kind = kind;
  d.resolved = std::move(params);
  d.inputs.bytes_seen = offset;
  d.inputs.elapsed_us = event * 10;
  d.applied = true;
  return d;
}

std::vector<std::byte> bytes_of(const std::string& s) {
  std::vector<std::byte> out(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    out[i] = static_cast<std::byte>(static_cast<unsigned char>(s[i]));
  }
  return out;
}

std::string text_of(const OutPiece& p) {
  std::string out;
  for (auto b : p.payload) out += static_cast<char>(b);
  return out;
}

LoadedLedger simple_ledger() {
  LoadedLedger l;
  l.scenario_hash_hex = "cafe";
  l.seed = 7;
  // Chunk "hello world" (11 bytes) at offset 0. Corrupt is recorded BEFORE
  // the duplicate, so replay applies it to the single pre-copy piece and
  // both emitted copies carry the flip.
  json::Value corr = json::Value::object();
  corr.set("mode", json::Value::str("xor"));
  corr.set("offset", json::Value::u(6));
  corr.set("value", json::Value::u(0x20));  // 'w' ^ 0x20 = 'W'
  l.decisions.push_back(make_decision(1, 1, Dir::AtoB, 6, FaultKind::Corrupt, corr));

  json::Value dup = json::Value::object();
  dup.set("count", json::Value::u(1));
  l.decisions.push_back(make_decision(2, 1, Dir::AtoB, 0, FaultKind::Duplicate, dup));
  return l;
}

}  // namespace

TEST_CASE("loader parses happy-path events.jsonl with manifest", "[replay]") {
  const std::string dir = make_temp_dir();
  write_file(dir + "/manifest.json",
             "{\"seed\": 99, \"scenario_hash_hex\": \"abcd1234\"}");
  const std::string line1 =
      decision_to_json(make_decision(1, 2, Dir::AtoB, 0, FaultKind::Latency,
                                     [] {
                                       json::Value p = json::Value::object();
                                       p.set("delay_us", json::Value::u(100));
                                       return p;
                                     }()))
          .dump();
  const std::string line2 =
      decision_to_json(make_decision(2, 2, Dir::AtoB, 40, FaultKind::Reset,
                                     json::Value::object()))
          .dump();
  write_file(dir + "/events.jsonl", "\n" + line1 + "\n\n" + line2 + "\n");

  LoadedLedger l = load_events_jsonl(dir + "/events.jsonl", "", false);
  REQUIRE(l.decisions.size() == 2);  // empty lines skipped
  CHECK(l.decisions[0].kind == FaultKind::Latency);
  CHECK(l.decisions[1].kind == FaultKind::Reset);
  CHECK(l.scenario_hash_hex == "abcd1234");
  CHECK(l.seed == 99);

  SECTION("strict hash mismatch throws") {
    CHECK_THROWS_AS(load_events_jsonl(dir + "/events.jsonl", "deadbeef", true),
                    std::runtime_error);
    CHECK_NOTHROW(load_events_jsonl(dir + "/events.jsonl", "abcd1234", true));
    CHECK_NOTHROW(load_events_jsonl(dir + "/events.jsonl", "deadbeef", false));
  }
}

TEST_CASE("loader reports malformed lines with line numbers", "[replay]") {
  const std::string dir = make_temp_dir();
  write_file(dir + "/events.jsonl",
             "{\"event\":1,\"connection\":1,\"direction\":\"a_to_b\",\"stream_offset\":0,"
             "\"rule_index\":0,\"rule\":\"r\",\"kind\":\"latency\",\"applied\":true,"
             "\"bytes_seen\":0,\"elapsed_us\":0,\"parameters\":{}}\n"
             "{\"event\": broken\n");
  try {
    load_events_jsonl(dir + "/events.jsonl", "", false);
    FAIL("expected throw");
  } catch (const std::runtime_error& e) {
    CHECK(std::string(e.what()).find("line 2") != std::string::npos);
  }
}

TEST_CASE("loader rejects missing and mistyped fields", "[replay]") {
  auto bad = R"({"connection":1,"direction":"a_to_b","stream_offset":0,"rule_index":0,
               "rule":"r","kind":"latency","applied":true,"bytes_seen":0,"elapsed_us":0,
               "parameters":{}})";  // missing event
  CHECK_THROWS_AS(decision_from_json(json::parse_json(bad)), std::runtime_error);
  auto mistyped = R"({"event":1,"connection":"one","direction":"a_to_b","stream_offset":0,
                    "rule_index":0,"rule":"r","kind":"latency","applied":true,"bytes_seen":0,
                    "elapsed_us":0,"parameters":{}})";
  CHECK_THROWS_AS(decision_from_json(json::parse_json(mistyped)), std::runtime_error);
  auto unknown_kind = R"({"event":1,"connection":1,"direction":"a_to_b","stream_offset":0,
                         "rule_index":0,"rule":"r","kind":"meteor","applied":true,"bytes_seen":0,
                         "elapsed_us":0,"parameters":{}})";
  CHECK_THROWS_AS(decision_from_json(json::parse_json(unknown_kind)), std::runtime_error);
}

TEST_CASE("LedgerEngine replays duplicate + corrupt byte-exactly", "[replay]") {
  CompiledScenario sc;
  LedgerEngineOptions opts;
  auto engine_ptr = make_ledger_engine(sc, simple_ledger(), opts);
  Scheduler sched;
  engine_ptr->bind(&sched, 0);

  StreamKey key{1, Dir::AtoB};
  StreamStats stats;
  ProcessResult r =
      engine_ptr->process_read(key, 0, bytes_of("hello world"), stats, /*now=*/100);

  // Duplicate count=1 -> original plus one extra copy; corrupt flips
  // 'w'->'W' before the copy, so both pieces carry the flip.
  REQUIRE(r.pieces.size() == 2);
  CHECK(text_of(r.pieces[0]) == "hello World");
  CHECK(text_of(r.pieces[1]) == "hello World");

  const auto* ledger_engine = dynamic_cast<const LedgerEngine*>(engine_ptr.get());
  REQUIRE(ledger_engine != nullptr);
  const auto& st = ledger_engine->stats();
  CHECK(st.reapplied == 2);
  CHECK(st.position_misses == 0);

  SECTION("chunk where ledger has nothing is a position miss passthrough") {
    ProcessResult miss =
        engine_ptr->process_read(key, 100, bytes_of("xyz"), stats, 200);
    REQUIRE(miss.pieces.size() == 1);
    CHECK(text_of(miss.pieces[0]) == "xyz");
    CHECK(ledger_engine->stats().position_misses == 1);
  }

  SECTION("decision never consumed by the workload counts as unconsumed") {
    // Fresh engine whose ledger holds one decision far ahead of any visited
    // position: it stays unconsumed.
    LoadedLedger l2;
    json::Value lat2 = json::Value::object();
    lat2.set("delay_us", json::Value::u(10));
    l2.decisions.push_back(make_decision(1, 1, Dir::AtoB, 5000, FaultKind::Latency, lat2));
    auto e2 = make_ledger_engine(sc, l2, {});
    Scheduler sched2;
    e2->bind(&sched2, 0);
    StreamStats stats2;
    (void)e2->process_read(key, 0, bytes_of("abc"), stats2, 300);
    const auto* le2 = dynamic_cast<const LedgerEngine*>(e2.get());
    REQUIRE(le2 != nullptr);
    CHECK(le2->stats().reapplied == 0);
    CHECK(le2->stats().position_misses == 1);
    CHECK(le2->stats().unconsumed == 1);
  }
}

TEST_CASE("LedgerEngine stamps latency deadlines without RNG", "[replay]") {
  CompiledScenario sc;
  LoadedLedger l;
  json::Value lat = json::Value::object();
  lat.set("delay_us", json::Value::u(2500));
  l.decisions.push_back(make_decision(1, 1, Dir::BtoA, 0, FaultKind::Latency, lat));

  auto engine = make_ledger_engine(sc, l, {});
  Scheduler sched;
  engine->bind(&sched, 0);

  StreamStats stats;
  ProcessResult r =
      engine->process_read({1, Dir::BtoA}, 0, bytes_of("abc"), stats, /*now=*/500);
  REQUIRE(r.pieces.size() == 1);
  CHECK_FALSE(r.pieces[0].immediate);
  CHECK(r.pieces[0].send_at_us == 500 + 2500);
}

TEST_CASE("LedgerEngine fragments per resolved sizes array", "[replay]") {
  CompiledScenario sc;
  LoadedLedger l;
  json::Value frag = json::Value::object();
  json::Value sizes = json::Value::array();
  sizes.push(json::Value::u(3));
  sizes.push(json::Value::u(5));
  frag.set("sizes", sizes);
  l.decisions.push_back(make_decision(1, 4, Dir::AtoB, 0, FaultKind::Fragment, frag));

  auto engine = make_ledger_engine(sc, l, {});
  Scheduler sched;
  engine->bind(&sched, 0);

  StreamStats stats;
  ProcessResult r = engine->process_read({4, Dir::AtoB}, 0, bytes_of("abcdefgh"), stats, 0);
  // Sizes 3 + 5 exactly cover the 8-byte chunk.
  REQUIRE(r.pieces.size() == 2);
  CHECK(text_of(r.pieces[0]) == "abc");
  CHECK(r.pieces[0].logical_offset == 0);
  CHECK(text_of(r.pieces[1]) == "defgh");  // remainder preserved exactly once
  CHECK(r.pieces[1].logical_offset == 3);
}

TEST_CASE("LedgerEngine blackhole discard yields empty pieces in window", "[replay]") {
  CompiledScenario sc;
  LoadedLedger l;
  json::Value bh = json::Value::object();
  bh.set("duration_us", json::Value::u(1000));
  bh.set("window_bytes", json::Value::u(20));
  bh.set("mode", json::Value::str("discard"));
  l.decisions.push_back(make_decision(1, 1, Dir::AtoB, 0, FaultKind::Blackhole, bh));

  auto engine = make_ledger_engine(sc, l, {});
  Scheduler sched;
  engine->bind(&sched, 0);

  StreamStats stats;
  ProcessResult dropped = engine->process_read({1, Dir::AtoB}, 0, bytes_of("aaa"), stats, 10);
  CHECK(dropped.pieces.empty());

  // After the window expires traffic flows again.
  ProcessResult after = engine->process_read({1, Dir::AtoB}, 20, bytes_of("bbb"), stats, 2000);
  REQUIRE(after.pieces.size() == 1);
  CHECK(text_of(after.pieces[0]) == "bbb");
}

TEST_CASE("LedgerEngine queues lifecycle actions on the scheduler", "[replay]") {
  CompiledScenario sc;
  LoadedLedger l;

  json::Value rst = json::Value::object();
  rst.set("after_us", json::Value::u(50));
  l.decisions.push_back(make_decision(1, 9, Dir::AtoB, 0, FaultKind::Reset, rst));

  json::Value fin = json::Value::object();
  fin.set("side", json::Value::str("client"));
  l.decisions.push_back(make_decision(2, 9, Dir::AtoB, 0, FaultKind::Fin, fin));

  auto engine = make_ledger_engine(sc, l, {});
  Scheduler sched;
  engine->bind(&sched, 0);
  engine->on_connection_accepted(9, 0);

  StreamStats stats;
  (void)engine->process_read({9, Dir::AtoB}, 0, bytes_of("x"), stats, 100);

  std::vector<Scheduler::Due> due;
  sched.pop_due(200, due);
  int resets = 0, fins = 0, connects = 0;
  for (const auto& d : due) {
    if (std::holds_alternative<ActReset>(d.action)) ++resets;
    if (std::holds_alternative<ActFin>(d.action)) ++fins;
    if (std::holds_alternative<ActConnectUpstream>(d.action)) ++connects;
  }
  CHECK(resets == 1);
  CHECK(fins == 1);
  CHECK(connects == 1);  // accept contract: exactly one connect action
}
