// Ledger loader: parse events.jsonl detail lines into a LoadedLedger.

#include <loki/version.hpp>
#include <loki/replay.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <loki/json_parse.hpp>

namespace loki {
namespace {

std::string parent_of(const std::string& path) {
  std::filesystem::path p(path);
  std::filesystem::path parent = p.parent_path();
  return parent.empty() ? std::string(".") : parent.string();
}

// Reads scenario_hash_hex + seed from a sibling manifest.json when present.
bool read_sibling_manifest(const std::string& events_path,
                           std::string& hash_out,
                           std::uint64_t& seed_out) {
  namespace fs = std::filesystem;
  fs::path manifest = fs::path(parent_of(events_path)) / "manifest.json";
  std::error_code ec;
  if (!fs::exists(manifest, ec) || ec) return false;
  std::ifstream f(manifest, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open manifest.json next to events file");
  std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  json::Value m;
  try {
    m = json::parse_json(text);
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string("sibling manifest.json is malformed: ") + e.what());
  }
  const json::Value* h = m.find("scenario_hash_hex");
  if (h != nullptr && h->type() == json::Value::Type::String) hash_out = h->as_str();
  const json::Value* s = m.find("seed");
  if (s != nullptr && s->type() == json::Value::Type::UInt) seed_out = s->as_uint();
  else if (s != nullptr && s->type() == json::Value::Type::Int && s->as_int() >= 0)
    seed_out = static_cast<std::uint64_t>(s->as_int());
  return true;
}

}  // namespace

LoadedLedger load_events_jsonl(const std::string& events_path,
                               const std::string& expected_hash_hex,
                               bool strict_hash) {
  LoadedLedger out;

  bool have_manifest = read_sibling_manifest(events_path, out.scenario_hash_hex, out.seed);

  // strict_hash compares the caller's expectation against the ledger run's
  // recorded scenario hash (manifest). The event lines themselves carry no
  // hash; the manifest is the companion check surface.
  if (strict_hash && !expected_hash_hex.empty() && have_manifest &&
      !out.scenario_hash_hex.empty() && expected_hash_hex != out.scenario_hash_hex) {
    throw std::runtime_error("ledger hash mismatch: expected " + expected_hash_hex +
                             ", run recorded " + out.scenario_hash_hex);
  }

  std::ifstream f(events_path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open events file: " + events_path);

  std::string line;
  std::uint64_t line_no = 0;
  while (std::getline(f, line)) {
    ++line_no;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;  // empty lines skipped
    try {
      json::Value v = json::parse_json(line);
      out.decisions.push_back(decision_from_json(v));
    } catch (const std::exception& e) {
      throw std::runtime_error("events file malformed at line " + std::to_string(line_no) +
                               ": " + e.what());
    }
  }
  return out;
}

}  // namespace loki
