// Evidence package tests: RunStore artifacts, decision round-trip,
// EventLog accounting, JSON parser corpus.

#include <catch2/catch_test_macros.hpp>

#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <loki/version.hpp>
#include <loki/evidence.hpp>
#include <loki/json_parse.hpp>
#include <loki/version.hpp>

using namespace loki;
namespace fs = std::filesystem;

namespace {

std::string make_temp_dir() {
  char tmpl[] = "/tmp/loki-ev-test-XXXXXX";
  char* dir = ::mkdtemp(tmpl);
  REQUIRE(dir != nullptr);
  return dir;
}

std::string slurp(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

FaultDecision sample_decision(std::uint64_t event, std::uint64_t off) {
  FaultDecision d;
  d.event_index = event;
  d.conn = 3;
  d.dir = Dir::AtoB;
  d.stream_offset = off;
  d.rule_index = 1;
  d.rule_name = "rule-latency";
  d.kind = FaultKind::Latency;
  json::Value params = json::Value::object();
  params.set("delay_us", json::Value::u(1500));
  params.set("jitter_us", json::Value::u(250));
  d.resolved = params;
  d.inputs.bytes_seen = off;
  d.inputs.elapsed_us = event * 100;
  d.applied = true;
  return d;
}

}  // namespace

TEST_CASE("RunStore creates complete artifact layout", "[evidence]") {
  const std::string root = make_temp_dir() + "/runs";
  ManifestInfo info;
  info.git_sha = "deadbee";
  info.scenario_hash_hex = std::string(64, 'a');
  info.seed = 42;
  info.started_at = 1724000000123456ll;
  info.platform = "Darwin arm64";
  info.kernel = "25.0.0";
  info.backend = "kqueue";
  info.mode = "live";

  RunStore rs = RunStore::create(root, info, "version: 1\n", "{}");

  SECTION("run-id shape and directory contents") {
    const std::string dir = rs.run_dir();
    INFO(dir);
    REQUIRE(dir.find("/run-") != std::string::npos);
    for (const char* name :
         {"manifest.json", "scenario.yaml", "scenario.normalized.json",
          "events.jsonl", "connections.jsonl"}) {
      REQUIRE(fs::exists(fs::path(dir) / name));
    }
    REQUIRE(slurp(dir + "/scenario.yaml") == "version: 1\n");
    REQUIRE(slurp(dir + "/scenario.normalized.json") == "{}");
  }

  SECTION("manifest fields present and pretty-printed") {
    const std::string text = slurp(rs.run_dir() + "/manifest.json");
    REQUIRE(text.find("\"loki_version\": \"0.1.0\"") != std::string::npos);
    REQUIRE(text.find("\"rng_version\": 1") != std::string::npos);
    REQUIRE(text.find("\"ledger_format_version\": 1") != std::string::npos);
    REQUIRE(text.find("\"git_sha\": \"deadbee\"") != std::string::npos);
    REQUIRE(text.find("\"seed\": 42") != std::string::npos);
    REQUIRE(text.find("\"started_at_iso\": \"2024-08-18T") != std::string::npos);
    REQUIRE(text.find("\n  ") != std::string::npos);  // 2-space indent
  }

  SECTION("run-id collision appends suffix") {
    ManifestInfo same = info;
    same.started_at += 1000000;  // different second would change id; keep identical
    same.started_at = info.started_at;
    RunStore rs2 = RunStore::create(root, same, "", "{}");
    // Same stamp+pid -> second directory gets -2.
    std::string base = rs.run_dir();
    REQUIRE(rs2.run_dir() != base);
    // The base path itself must still exist and not be reused.
    REQUIRE(fs::exists(base));
  }
}

TEST_CASE("decision ledger round-trip preserves all fields", "[evidence]") {
  std::vector<FaultDecision> decisions;
  decisions.push_back(sample_decision(1, 0));

  FaultDecision corrupt = sample_decision(2, 512);
  corrupt.dir = Dir::BtoA;
  corrupt.conn = 9;
  corrupt.rule_index = 7;
  corrupt.rule_name = "corrupt-xor";
  corrupt.kind = FaultKind::Corrupt;
  corrupt.applied = false;
  json::Value cp = json::Value::object();
  cp.set("mode", json::Value::str("xor"));
  cp.set("offset", json::Value::u(512));
  cp.set("value", json::Value::u(255));
  corrupt.resolved = cp;
  decisions.push_back(corrupt);

  for (const auto& d : decisions) {
    json::Value encoded = decision_to_json(d);
    FaultDecision back = decision_from_json(encoded);
    CHECK(back.event_index == d.event_index);
    CHECK(back.conn == d.conn);
    CHECK(back.dir == d.dir);
    CHECK(back.stream_offset == d.stream_offset);
    CHECK(back.rule_index == d.rule_index);
    CHECK(back.rule_name == d.rule_name);
    CHECK(back.kind == d.kind);
    CHECK(back.applied == d.applied);
    CHECK(back.inputs.bytes_seen == d.inputs.bytes_seen);
    CHECK(back.inputs.elapsed_us == d.inputs.elapsed_us);
    CHECK(back.resolved.dump() == d.resolved.dump());  // opaque passthrough
    // Locked field order on the wire:
    const std::string wire = encoded.dump();
    std::vector<std::string> keys = {"\"event\"", "\"connection\"", "\"direction\"",
                                     "\"stream_offset\"", "\"rule_index\"", "\"rule\"",
                                     "\"kind\"", "\"applied\"", "\"bytes_seen\"",
                                     "\"elapsed_us\"", "\"parameters\""};
    std::size_t last = 0;
    for (const auto& k : keys) {
      std::size_t pos = wire.find(k);
      REQUIRE(pos != std::string::npos);
      REQUIRE((pos > last || last == 0));
      last = pos;
    }
  }
}

TEST_CASE("EventLog writes one compact line per decision and tracks counts", "[evidence]") {
  const std::string root = make_temp_dir() + "/runs";
  ManifestInfo info;
  RunStore rs = RunStore::create(root, info, "", "{}");

  auto& log = rs.events();
  log.append(sample_decision(1, 0));
  log.note_counts(FaultKind::Latency, 5);  // aggregated only: no detail lines
  log.note_counts(FaultKind::Corrupt, 2);
  log.append(sample_decision(2, 128));
  CHECK(log.written() == 2);

  json::Value conn = json::Value::object();
  conn.set("conn", json::Value::u(3));
  conn.set("bytes_a_to_b", json::Value::u(640));
  rs.log_connection(conn);

  const std::string events = slurp(rs.run_dir() + "/events.jsonl");
  REQUIRE(events == decision_to_json(sample_decision(1, 0)).dump() + "\n" +
                        decision_to_json(sample_decision(2, 128)).dump() + "\n");
  REQUIRE(events.find("\"counts\"") == std::string::npos);  // notes never hit the file

  const std::string conns = slurp(rs.run_dir() + "/connections.jsonl");
  REQUIRE(conns == "{\"conn\":3,\"bytes_a_to_b\":640}\n");
}

TEST_CASE("finish is idempotent", "[evidence]") {
  const std::string root = make_temp_dir() + "/runs";
  ManifestInfo info;
  RunStore rs = RunStore::create(root, info, "", "{}");
  json::Value metrics = json::Value::object();
  metrics.set("chunks", json::Value::u(11));
  json::Value summary = json::Value::object();
  summary.set("decisions", json::Value::u(7));

  rs.finish(metrics, summary);
  const std::string metrics_text = slurp(rs.run_dir() + "/metrics.json");
  const std::string summary_text = slurp(rs.run_dir() + "/summary.json");
  rs.finish(metrics, summary);  // second finish is a no-op
  CHECK(slurp(rs.run_dir() + "/metrics.json") == metrics_text);
  CHECK(slurp(rs.run_dir() + "/summary.json") == summary_text);
  CHECK(metrics_text.find("\"chunks\": 11") != std::string::npos);
  CHECK(summary_text.find("\"decisions\": 7") != std::string::npos);
}

TEST_CASE("control_socket_path sits inside the run dir", "[evidence]") {
  const std::string root = make_temp_dir() + "/runs";
  ManifestInfo info;
  RunStore rs = RunStore::create(root, info, "", "{}");
  CHECK(rs.control_socket_path() == rs.run_dir() + "/control.sock");
}

TEST_CASE("json parser accepts a valid corpus", "[json-parse]") {
  auto v = json::parse_json(R"({"a": [1, -2, 3], "b": {"c": null}, "d": true})");
  REQUIRE(v.type() == json::Value::Type::Object);
  REQUIRE(v.find("a") != nullptr);
  CHECK(v.find("a")->items().size() == 3);
  CHECK(v.find("a")->items()[1].as_int() == -2);
  REQUIRE(v.find("b") != nullptr);
  CHECK(v.find("b")->find("c")->is_null());
  CHECK(v.find("d")->as_bool());

  // \uXXXX escapes including surrogate pairs.
  auto s = json::parse_json("\"\\u0041\\u00e9 \\ud83d\\ude00\"");
  CHECK(s.as_str() == "A\u00e9 \xF0\x9F\x98\x80");

  // Integers, unsigned overflow, doubles.
  CHECK(json::parse_json("9223372036854775807").type() == json::Value::Type::Int);
  CHECK(json::parse_json("18446744073709551615").type() == json::Value::Type::UInt);
  CHECK(json::parse_json("-9223372036854775808").as_int() ==
        static_cast<std::int64_t>(0x8000000000000000ull));
  CHECK(json::parse_json("1.5e3").as_double() == 1500.0);
  CHECK(json::parse_json("[]").items().empty());
  CHECK(json::parse_json("{}").members().empty());
}

TEST_CASE("json parser rejects malformed input cleanly", "[json-parse]") {
  const char* bad[] = {
      "{",                          // truncated
      "{\"a\":1,}",                 // trailing comma
      "[1 2]",                      // missing comma
      "{\"a\":1} trailing",         // trailing garbage
      "{\"a\":1,\"a\":2}",          // duplicate key
      "\"\\x41\"",                  // bad escape
      "\"\\ud83d\"",                // lone high surrogate
      "\"\\ud83dx\\udc00\"",        // broken surrogate pair
      "01",                         // leading zero number
      "1.2.3",                      // malformed double
      "-",                          // bare minus
      "nan",                        // NaN literal
      "NaN",                        // NaN literal
      "infinity",                   // infinity literal
      "99999999999999999999999999", // integer overflow past UInt
      "[[[[[[[[[[",                 // deep nesting (also depth cap below)
      "{\"a\" 1}",                  // missing colon
      "'single'",                   // single quotes
      "truex",                      // literal prefix garbage
      "\"unterminated",
  };
  for (const char* text : bad) {
    try {
      json::parse_json(text);
      FAIL_CHECK(std::string("expected rejection: ") + text);
    } catch (const std::runtime_error&) {
      // clean rejection
    }
  }

  // Depth cap: 65 nested arrays rejected, 64 accepted.
  std::string deep65(65, '[');
  deep65 += std::string(65, ']');
  CHECK_THROWS_AS(json::parse_json(deep65), std::runtime_error);
  std::string deep64(64, '[');
  deep64 += std::string(64, ']');
  CHECK_NOTHROW(json::parse_json(deep64));

  // Errors carry line numbers when newlines precede the failure.
  try {
    json::parse_json("{\n\n  \"bad\": tru }");
    FAIL("expected throw");
  } catch (const std::runtime_error& e) {
    CHECK(std::string(e.what()).find("line 3") != std::string::npos);
  }
}
