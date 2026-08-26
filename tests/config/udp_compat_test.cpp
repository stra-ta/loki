#include <catch2/catch_test_macros.hpp>

#include <loki/scenario.hpp>

#include "../../src/config/validate_transport.hpp"

using namespace loki;

// The scenario YAML parser rejects flow style ({} / []), so all rule params are
// written in block style here.

TEST_CASE("udp rejects tcp-only faults") {
  const std::string yaml =
      "version: 1\n"
      "seed: 42\n"
      "listen: 127.0.0.1:9000\n"
      "upstream: 127.0.0.1:9001\n"
      "rules:\n"
      "  - name: r1\n"
      "    inject:\n"
      "      reset:\n"
      "        after: 0ms\n";

  CompiledScenario sc = compile_scenario(yaml);

  REQUIRE_THROWS_AS(check_transport_compat(sc, TransportMode::Udp), ScenarioError);
  REQUIRE_NOTHROW(check_transport_compat(sc, TransportMode::Tcp));
}

TEST_CASE("udp accepts latency-only scenario") {
  const std::string yaml =
      "version: 1\n"
      "seed: 7\n"
      "listen: 127.0.0.1:9000\n"
      "upstream: 127.0.0.1:9001\n"
      "rules:\n"
      "  - name: r2\n"
      "    inject:\n"
      "      latency:\n"
      "        mean: 10ms\n";

  CompiledScenario sc = compile_scenario(yaml);

  REQUIRE_NOTHROW(check_transport_compat(sc, TransportMode::Udp));
}
