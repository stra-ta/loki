#pragma once

// JSON parser for evidence/replay. Additive to the frozen json.hpp emitter:
// this header only DECLARES parse_json; the implementation lives in
// src/evidence/json_parse.cpp.
//
// Accepted: RFC 8259 subset - objects (duplicate keys are errors), arrays,
// strings with escapes including \uXXXX surrogate pairs, integers (int64,
// unsigned overflow promoted to UInt), doubles, true/false/null.
// Rejected: trailing garbage, nesting deeper than 64, NaN/Infinity literals.
// Errors throw std::runtime_error with a line number when available.

#include <string_view>

#include <loki/json.hpp>

namespace loki::json {

Value parse_json(std::string_view text);

}  // namespace loki::json
