#include <catch2/catch_test_macros.hpp>

#include <loki/scenario.hpp>

#include "../../src/config/validate_transport.hpp"

using namespace loki;

// The scenario YAML parser rejects flow style ({} / []), so all rule params are
// written in block style here.

namespace {
// Build a one-rule scenario with the given `inject:` body and check whether it
// passes UDP transport compatibility.
bool udp_accepts(const std::string& inject_body) {
  const std::string yaml =
      "version: 1\n"
      "seed: 42\n"
      "listen: 127.0.0.1:9000\n"
      "upstream: 127.0.0.1:9001\n"
      "rules:\n"
      "  - name: r1\n"
      "    inject:\n" +
      inject_body;
  CompiledScenario sc = compile_scenario(yaml);
  try {
    check_transport_compat(sc, TransportMode::Udp);
    return true;
  } catch (const ScenarioError&) {
    return false;
  }
}
}  // namespace

TEST_CASE("udp rejects the six tcp-only lifecycle faults") {
  REQUIRE_FALSE(udp_accepts("      reset:\n        after: 0ms\n"));
  REQUIRE_FALSE(udp_accepts("      fin:\n        side: client\n"));
  REQUIRE_FALSE(udp_accepts("      half_close:\n        side: client\n        mode: tx\n"));
  REQUIRE_FALSE(udp_accepts("      refuse:\n        after: 0ms\n"));
  REQUIRE_FALSE(udp_accepts("      accept_stall:\n        stall: 10ms\n"));
  REQUIRE_FALSE(udp_accepts("      connect_delay:\n        delay: 5ms\n"));
}

TEST_CASE("udp rejects blackhole freeze but allows discard") {
  REQUIRE_FALSE(udp_accepts("      blackhole:\n        direction: a_to_b\n        mode: freeze\n"));
  REQUIRE(udp_accepts("      blackhole:\n        direction: a_to_b\n        mode: discard\n"));
}

TEST_CASE("udp accepts transport-agnostic faults and idle_timeout") {
  REQUIRE(udp_accepts("      latency:\n        mean: 10ms\n"));
  REQUIRE(udp_accepts("      bandwidth:\n        rate: 1000\n        burst: 100\n"));
  REQUIRE(udp_accepts("      fragment:\n        min: 1\n        max: 4\n"));
  REQUIRE(udp_accepts("      coalesce:\n        size: 8\n        max_delay: 5ms\n"));
  REQUIRE(udp_accepts("      reorder:\n        depth: 3\n        max_hold: 5ms\n"));
  REQUIRE(udp_accepts("      duplicate:\n        count: 2\n"));
  REQUIRE(udp_accepts("      corrupt:\n        mode: xor\n        offset: 0\n        value: 1\n"));
  REQUIRE(udp_accepts("      idle_timeout:\n        idle: 50ms\n        action: reset\n"));
}
