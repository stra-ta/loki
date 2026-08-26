// SNI-based fault matching: compiler parsing + normalized JSON.
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

}  // namespace

TEST_CASE("when.sni parses into MatchSpec and normalized json", "[loki_config]") {
  const auto sc = compile_scenario(std::string(kMinimal) + R"(
rules:
  - name: sni-rule
    when:
      sni: example.com
    inject:
      reset:
)");
  REQUIRE(sc.rules.size() == 1);
  REQUIRE(sc.rules[0].when.sni == "example.com");

  const std::string j = normalized_json(sc);
  // sni must appear exactly as given in the normalized "when" object.
  REQUIRE(j.find("\"sni\":\"example.com\"") != std::string::npos);
}

TEST_CASE("when.sni unknown key rejected", "[loki_config]") {
  const std::string bad = std::string(kMinimal) + R"(
rules:
  - when:
      sni_typo: example.com
    inject:
      reset:
)";
  REQUIRE_THROWS_AS(compile_scenario(bad), ScenarioError);
}

TEST_CASE("when.sni with connection-phase faults is rejected", "[loki_config]") {
  // SNI is only known after the ClientHello is read (data phase), so it can
  // never be combined with faults that act at accept/connect time.
  for (const char* inject : {"connect_delay:\n      delay: 10ms",
                             "refuse:\n", "accept_stall:\n      stall: 10ms"}) {
    const std::string bad = std::string(kMinimal) + "\nrules:\n  - when:\n      sni: example.com\n    inject:\n      " + inject + "\n";
    INFO("rejecting: " << inject);
    REQUIRE_THROWS_AS(compile_scenario(bad), ScenarioError);
  }
  // Data-phase faults remain valid with when.sni.
  const auto ok = compile_scenario(std::string(kMinimal) + R"(
rules:
  - when:
      sni: example.com
    inject:
      latency:
        mean: 10ms
)");
  REQUIRE(ok.rules.size() == 1);
  REQUIRE(ok.rules[0].when.sni == "example.com");
}
