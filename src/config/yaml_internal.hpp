#pragma once

// Internal YAML-subset AST shared by src/config/*.cpp. Not part of the public
// contract; include/loki stays frozen.

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <loki/scenario.hpp>

namespace loki::cfg {

struct YNode {
  enum class Kind : std::uint8_t { Scalar, Map, Seq };
  Kind kind = Kind::Scalar;
  int line = 0;                       // 1-based source line
  std::string scalar;                 // Scalar: unquoted text (quotes stripped)
  bool quoted = false;                // Scalar came from quotes -> always string
  std::vector<std::pair<std::string, YNode>> map;   // Map, insertion order
  std::vector<int> key_lines;         // Map: source line of each key (parallel to map)
  std::vector<YNode> seq;             // Seq items

  const YNode* find(const std::string& key) const {
    for (const auto& [k, v] : map) {
      if (k == key) return &v;
    }
    return nullptr;
  }
};

// Parses the strict subset documented in AGENTS.md. Throws ScenarioError.
YNode parse_yaml(const std::string& text);

}  // namespace loki::cfg
