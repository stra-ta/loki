// Config pipeline tests: parsing, schema validation, normalization, hashing.
#include <catch2/catch_test_macros.hpp>

#include <string>

#include <loki/scenario.hpp>

using namespace loki;

namespace {

const std::string kMinimal = R"(
version: 1
seed: 42
listen: :9000
upstream: 127.0.0.1:9001
)";

const std::string kRule = R"(
rules:
  - inject:
      latency:
        mean: 10ms
        jitter: 2ms
)";

std::string compile_error_line(const std::string& yaml) {
  try {
    compile_scenario(yaml);
  } catch (const ScenarioError& e) {
    return std::to_string(e.line) + ": " + e.what();
  }
  return "no error";
}

}  // namespace

TEST_CASE("minimal scenario compiles with defaults", "[loki_config]") {
  const auto sc = compile_scenario(kMinimal);
  REQUIRE(sc.seed == 42);
  REQUIRE(sc.listen.port == 9000);
  REQUIRE(sc.listen.host == "127.0.0.1");
  REQUIRE_FALSE(sc.listen.ipv6);
  REQUIRE(sc.upstream.to_string() == "127.0.0.1:9001");
  REQUIRE(sc.limits.pending_bytes_per_direction == 1048576);
  REQUIRE(sc.limits.max_connections == 1024);
  REQUIRE(sc.rules.empty());
  REQUIRE(sc.scenario_hash_hex().size() == 64);
}

TEST_CASE("every inject kind compiles", "[loki_config]") {
  struct Case {
    const char* inject;
    FaultKind kind;
  };
  const Case cases[] = {
      {"latency:\n          mean: 5ms\n          jitter: 1ms", FaultKind::Latency},
      {"latency:\n          mean: 5ms\n          distribution: normal\n          stddev: 2ms",
       FaultKind::Latency},
      {"bandwidth:\n          rate: 1000\n          burst: 4096", FaultKind::Bandwidth},
      {"fragment:\n          min: 2\n          max: 8", FaultKind::Fragment},
      {"coalesce:\n          size: 512\n          max_delay: 3ms", FaultKind::Coalesce},
      {"reorder:\n          depth: 4\n          max_hold: 1ms", FaultKind::Reorder},
      {"duplicate:\n          count: 3", FaultKind::Duplicate},
      {"corrupt:\n          mode: xor\n          offset: 16\n          value: 255",
       FaultKind::Corrupt},
      {"blackhole:\n          direction: b_to_a\n          mode: freeze\n          duration: 100ms",
       FaultKind::Blackhole},
      {"reset:\n          after: 250ms", FaultKind::Reset},
      {"fin:\n          side: client", FaultKind::HalfClose},
      {"half_close:\n          side: server\n          mode: rx", FaultKind::HalfClose},
      {"connect_delay:\n          delay: 20ms", FaultKind::ConnectDelay},
      {"refuse:\n          after: 1s", FaultKind::Refuse},
      {"accept_stall:\n          stall: 500ms", FaultKind::AcceptStall},
      {"idle_timeout:\n          idle: 30s\n          action: fin", FaultKind::IdleTimeout},
  };
  for (const auto& c : cases) {
    std::string yaml = std::string(kMinimal) + "\nrules:\n  - name: probe\n    inject:\n      " +
                       c.inject + "\n";
    CAPTURE(yaml);
    const auto sc = compile_scenario(yaml);
    REQUIRE(sc.rules.size() == 1);
    REQUIRE(sc.rules[0].kind == c.kind);
    // kind_of must agree with the compiler's kind.
    REQUIRE(kind_of(sc.rules[0].params) == c.kind);
  }
}

TEST_CASE("zero-field fault mapping defaults", "[loki_config]") {
  const auto sc = compile_scenario(std::string(kMinimal) + R"(
rules:
  - inject:
      reset:
)");
  REQUIRE(sc.rules.size() == 1);
  REQUIRE(std::get<ResetParams>(sc.rules[0].params).after_us == 0);
}

TEST_CASE("fin sugar maps to half_close tx with leg from side", "[loki_config]") {
  const auto client = compile_scenario(std::string(kMinimal) + R"(
rules:
  - inject:
      fin:
        side: client
)");
  REQUIRE(client.rules[0].kind == FaultKind::HalfClose);
  auto p = std::get<HalfCloseParams>(client.rules[0].params);
  REQUIRE(p.mode == HalfCloseParams::Mode::Tx);
  REQUIRE(p.leg == LegSide::Down);

  const auto server = compile_scenario(std::string(kMinimal) + R"(
rules:
  - inject:
      fin:
        side: server
)");
  p = std::get<HalfCloseParams>(server.rules[0].params);
  REQUIRE(p.leg == LegSide::Up);
}

TEST_CASE("direction aliases resolve", "[loki_config]") {
  for (const char* alias : {"a_to_b", "client_to_server", "c2s"}) {
    const auto sc = compile_scenario(std::string(kMinimal) + std::string("\nrules:\n  - when:\n      direction: ") +
                                     alias + "\n    inject:\n      reset:\n");
    REQUIRE(sc.rules[0].when.direction == Dir::AtoB);
  }
  const auto sc = compile_scenario(std::string(kMinimal) + R"(
rules:
  - when:
      direction: s2c
    inject:
      reset:
)");
  REQUIRE(sc.rules[0].when.direction == Dir::BtoA);
}

TEST_CASE("unknown key rejected with line number", "[loki_config]") {
  const std::string bad = "version: 1\nseed: 1\nlisten: :1\nupstream: :2\nbogus: 7\n";
  try {
    compile_scenario(bad);
    FAIL("expected ScenarioError");
  } catch (const ScenarioError& e) {
    REQUIRE(e.line == 5);
    REQUIRE(std::string(e.what()).find("unknown key") != std::string::npos);
  }
}

TEST_CASE("tab indentation rejected", "[loki_config]") {
  const std::string bad = "version: 1\nseed: 1\nlisten: :1\nupstream: :2\nlimits:\n\tmax_connections: 5\n";
  REQUIRE_THROWS_AS(compile_scenario(bad), ScenarioError);
  bool has_line = false;
  try {
    compile_scenario(bad);
  } catch (const ScenarioError& e) {
    has_line = e.line > 0;
  }
  REQUIRE(has_line);
}

TEST_CASE("flow style rejected", "[loki_config]") {
  const std::string bad =
      "version: 1\nseed: 1\nlisten: :1\nupstream: :2\nrules:\n  - inject: {latency: {mean: 1ms}}\n";
  REQUIRE_THROWS_AS(compile_scenario(bad), ScenarioError);
}

TEST_CASE("anchor rejected", "[loki_config]") {
  const std::string bad = "version: &v 1\nseed: 1\nlisten: :1\nupstream: :2\n";
  REQUIRE_THROWS_AS(compile_scenario(bad), ScenarioError);
}

TEST_CASE("alias rejected", "[loki_config]") {
  const std::string bad = "version: *v\nseed: 1\nlisten: :1\nupstream: :2\n";
  REQUIRE_THROWS_AS(compile_scenario(bad), ScenarioError);
}

TEST_CASE("block scalar rejected", "[loki_config]") {
  const std::string bad = "version: 1\nseed: 1\nlisten: |\n  x\nupstream: :2\n";
  REQUIRE_THROWS_AS(compile_scenario(bad), ScenarioError);
}

TEST_CASE("duplicate key rejected", "[loki_config]") {
  const std::string bad = "version: 1\nseed: 1\nseed: 2\nlisten: :1\nupstream: :2\n";
  REQUIRE_THROWS_AS(compile_scenario(bad), ScenarioError);
  const std::string nested =
      "version: 1\nseed: 1\nlisten: :1\nupstream: :2\nlimits:\n  max_connections: 1\n  max_connections: 2\n";
  REQUIRE_THROWS_AS(compile_scenario(nested), ScenarioError);
}

TEST_CASE("second document rejected", "[loki_config]") {
  const std::string bad = "---\nversion: 1\nseed: 1\nlisten: :1\nupstream: :2\n---\nversion: 1\n";
  REQUIRE_THROWS_AS(compile_scenario(bad), ScenarioError);
}

TEST_CASE("bad duration rejected", "[loki_config]") {
  const std::string bad = std::string(kMinimal) + R"(
rules:
  - inject:
      latency:
        mean: 100
)";
  REQUIRE_THROWS_AS(compile_scenario(bad), ScenarioError);
}

TEST_CASE("endpoint forms accepted and garbage rejected", "[loki_config]") {
  const auto v6 = compile_scenario("version: 1\nseed: 1\nlisten: \"[::1]:9000\"\nupstream: :80\n");
  REQUIRE(v6.listen.ipv6);
  REQUIRE(v6.listen.host == "::1");
  REQUIRE(v6.listen.port == 9000);

  const auto dns = compile_scenario("version: 1\nseed: 1\nlisten: example.com:80\nupstream: :80\n");
  REQUIRE(dns.listen.host == "example.com");
  REQUIRE(dns.listen.port == 80);

  REQUIRE_THROWS_AS(parse_endpoint("no-port-here"), std::invalid_argument);
  REQUIRE_THROWS_AS(parse_endpoint("[::1]:99999"), std::invalid_argument);
  REQUIRE_THROWS_AS(parse_endpoint(""), std::invalid_argument);
}

TEST_CASE("probability bounds enforced", "[loki_config]") {
  const std::string over = std::string(kMinimal) + R"(
rules:
  - when:
      probability: 1.5
    inject:
      reset:
)";
  REQUIRE_THROWS_AS(compile_scenario(over), ScenarioError);
  const std::string under = std::string(kMinimal) + R"(
rules:
  - when:
      probability: -0.1
    inject:
      reset:
)";
  REQUIRE_THROWS_AS(compile_scenario(under), ScenarioError);
}

TEST_CASE("range validations enforced", "[loki_config]") {
  const auto frag_bad = [&](const char* frag) {
    return compile_error_line(std::string(kMinimal) + "\nrules:\n  - inject:\n      fragment:\n" +
                              frag);
  };
  REQUIRE(frag_bad("          min: 0\n          max: 4").find(">= 1") != std::string::npos);
  REQUIRE(frag_bad("          min: 8\n          max: 4").find(">= min") != std::string::npos);

  REQUIRE(compile_error_line(std::string(kMinimal) +
                             "\nrules:\n  - inject:\n      reorder:\n        depth: 1\n        max_hold: 1ms")
              .find("depth") != std::string::npos);
  REQUIRE(compile_error_line(std::string(kMinimal) +
                             "\nrules:\n  - inject:\n      bandwidth:\n        rate: 0\n        burst: 1")
              .find("rate") != std::string::npos);
  REQUIRE(compile_error_line(std::string(kMinimal) +
                             "\nrules:\n  - inject:\n      corrupt:\n        mode: xor\n        offset: 0\n        value: 256")
              .find("value") != std::string::npos);
  REQUIRE(compile_error_line(std::string(kMinimal) +
                             "\nrules:\n  - ledger: sample:0\n    inject:\n      reset:")
              .find("sample") != std::string::npos);
  REQUIRE(compile_error_line(std::string(kMinimal) +
                             "\nrules:\n  - inject:\n      latency:\n        mean: 5ms\n        distribution: normal\n        stddev: 0us")
              .find("stddev") != std::string::npos);
}

TEST_CASE("normalized json is stable across runs and source key order", "[loki_config]") {
  const std::string a = std::string(kMinimal) + R"(
rules:
  - name: chop
    when:
      direction: a_to_b
      every_bytes: 1024
      probability: 0.5
    inject:
      fragment:
        min: 1
        max: 64
)";
  // Same content, different key order.
  const std::string b = R"(

rules:
  - inject:
      fragment:
        max: 64
        min: 1
    when:
      probability: 0.5
      every_bytes: 1024
      direction: a_to_b
    name: chop
upstream: 127.0.0.1:9001
listen: :9000
seed: 42
version: 1
)";

  const auto sa = compile_scenario(a);
  const auto sb = compile_scenario(b);
  const std::string ja = normalized_json(sa);
  const std::string jb = normalized_json(sb);
  REQUIRE(ja == jb);
  REQUIRE(sa.scenario_hash_hex() == sb.scenario_hash_hex());
  REQUIRE(ja == normalized_json(compile_scenario(a)));  // stable across runs
}

TEST_CASE("normalized json keys are sorted and integers only", "[loki_config]") {
  const auto sc = compile_scenario(std::string(kMinimal) + R"(
limits:
  max_connections: 128
  pending_bytes_per_direction: 4096
rules:
  - name: r
    ledger: sample:7
    when:
      direction: client_to_server
      after: 1s
      connection:
        every: 3
        equals: 1
      probability: 0.25
      max_occurrences: 9
      min_stream_offset: 12
      every_events: 2
    inject:
      latency:
        mean: 1500us
        jitter: 200us
)");
  const std::string j = normalized_json(sc);
  REQUIRE(j ==
          "{\"limits\":{\"max_connections\":128,\"pending_bytes_per_direction\":4096},"
          "\"listen\":\"127.0.0.1:9000\","
          "\"rules\":[{\"inject\":{\"jitter_us\":200,\"mean_us\":1500},"
          "\"kind\":\"latency\",\"ledger\":\"sample\","
          "\"name\":\"r\",\"sample_n\":7,"
          "\"when\":{\"after_us\":1000000,\"connection\":{\"equals\":1,\"every\":3},"
          "\"direction\":\"a_to_b\",\"every_events\":2,\"max_occurrences\":9,"
          "\"min_stream_offset\":12,\"probability\":0.25}}],"
          "\"seed\":42,\"upstream\":\"127.0.0.1:9001\"}");

  // Durations and counters serialize as integers (no exponent formatting).
  REQUIRE(j.find("e-") == std::string::npos);
  REQUIRE(j.find("e+") == std::string::npos);
}

TEST_CASE("defaulted keys omitted from normalized json", "[loki_config]") {
  const std::string j = normalized_json(compile_scenario(std::string(kMinimal) + R"(
rules:
  - inject:
      blackhole:
        direction: a_to_b
        mode: discard
)"));
  // Default rule name omitted; Full ledger omitted; zero duration omitted;
  // empty when{} present as {} per shape definition.
  REQUIRE(j.find("\"name\"") == std::string::npos);
  REQUIRE(j.find("\"ledger\"") == std::string::npos);
  REQUIRE(j.find("\"duration_us\"") == std::string::npos);
  REQUIRE(j.find("\"when\":{}") != std::string::npos);
  REQUIRE(j.find("\"kind\":\"blackhole\"") != std::string::npos);
}

TEST_CASE("scenario error carries nonzero line for inline errors", "[loki_config]") {
  const std::string bad = std::string(kMinimal) + "\nrules:\n  - inject:\n      nosuchfault:\n        x: 1\n";
  int line = 0;
  try {
    compile_scenario(bad);
    FAIL("expected ScenarioError");
  } catch (const ScenarioError& e) {
    line = e.line;
    REQUIRE(std::string(e.what()).find("nosuchfault") != std::string::npos);
  }
  REQUIRE(line > 0);
}
