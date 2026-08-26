// Scenario compiler: schema validation + canonical normalized JSON + hash.
#include <loki/scenario.hpp>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <loki/duration.hpp>
#include <loki/json.hpp>

#include "yaml_internal.hpp"

namespace loki {
namespace {

using cfg::YNode;

[[noreturn]] void err(const std::string& msg, int line) { throw ScenarioError(msg, line); }

// ---------------------------------------------------------------------------
// Scalar coercion
// ---------------------------------------------------------------------------

std::uint64_t as_uint(const YNode& n, const std::string& what) {
  if (n.quoted || n.scalar.empty()) err(what + " must be a non-negative integer", n.line);
  for (const char c : n.scalar) {
    if (c < '0' || c > '9') err(what + " must be a non-negative integer", n.line);
  }
  errno = 0;
  char* end = nullptr;
  const unsigned long long v = std::strtoull(n.scalar.c_str(), &end, 10);
  if (errno == ERANGE || end != n.scalar.c_str() + n.scalar.size()) {
    err(what + " is out of range", n.line);
  }
  return v;
}

double as_double(const YNode& n, const std::string& what) {
  if (n.quoted || n.scalar.empty()) err(what + " must be a number", n.line);
  errno = 0;
  char* end = nullptr;
  const double v = std::strtod(n.scalar.c_str(), &end);
  if (end != n.scalar.c_str() + n.scalar.size() || end == n.scalar.c_str()) {
    err(what + " must be a number", n.line);
  }
  if (errno == ERANGE && (v == HUGE_VAL || v == -HUGE_VAL)) err(what + " is out of range", n.line);
  return v;
}

std::uint64_t as_duration_us(const YNode& n, const std::string& what) {
  try {
    return parse_duration_us(n.scalar);
  } catch (const std::invalid_argument& e) {
    throw ScenarioError(what + ": " + e.what(), n.line);
  }
}

Dir as_dir(const YNode& n, const std::string& what) {
  const auto d = dir_from_string(n.scalar);
  if (!d) err(what + ": unknown direction '" + n.scalar + "'", n.line);
  return *d;
}

void expect_map(const YNode& n, const std::string& what) {
  if (n.kind != YNode::Kind::Map) err(what + " must be a mapping", n.line);
}
void expect_scalar(const YNode& n, const std::string& what) {
  if (n.kind != YNode::Kind::Scalar) err(what + " must be a scalar", n.line);
}

void allow_keys(const YNode& n, std::initializer_list<const char*> allowed, const std::string& what) {
  for (std::size_t i = 0; i < n.map.size(); ++i) {
    const std::string& k = n.map[i].first;
    bool ok = false;
    for (const char* a : allowed) {
      if (k == a) { ok = true; break; }
    }
    if (!ok) err(what + ": unknown key '" + k + "'", n.key_lines[i]);
  }
}

// ---------------------------------------------------------------------------
// Inject parsing
// ---------------------------------------------------------------------------

struct ParsedFault {
  FaultKind kind{};
  FaultParams params{};
};

LegSide leg_from_side(const YNode& n) {
  if (n.scalar == "client") return LegSide::Down;
  if (n.scalar == "server") return LegSide::Up;
  err("side must be 'client' or 'server'", n.line);
}

ParsedFault parse_inject(const YNode& inject) {
  expect_map(inject, "inject");
  if (inject.map.size() != 1) err("inject must contain exactly one fault key", inject.line);
  const auto& [key, val] = inject.map[0];
  expect_map(val, "inject." + key);

  if (key == "latency") {
    allow_keys(val, {"mean", "jitter", "distribution", "stddev"}, "latency");
    LatencyParams p;
    const YNode* mean = val.find("mean");
    if (!mean) err("latency requires 'mean'", val.line);
    expect_scalar(*mean, "latency.mean");
    p.mean_us = as_duration_us(*mean, "latency.mean");
    const YNode* dist = val.find("distribution");
    const YNode* stddev = val.find("stddev");
    const YNode* jitter = val.find("jitter");
    if (jitter) {
      expect_scalar(*jitter, "latency.jitter");
      p.jitter_us = as_duration_us(*jitter, "latency.jitter");
    }
    if (dist) {
      expect_scalar(*dist, "latency.distribution");
      if (dist->scalar != "normal" && dist->scalar != "uniform") {
        err("latency.distribution must be 'normal' or 'uniform'", dist->line);
      }
      if (dist->scalar == "normal") {
        p.normal = true;
        if (!stddev) err("latency distribution normal requires 'stddev'", val.line);
        expect_scalar(*stddev, "latency.stddev");
        p.stddev_us = static_cast<double>(as_duration_us(*stddev, "latency.stddev"));
        if (!(p.stddev_us > 0)) err("latency.stddev must be > 0", stddev->line);
      }
    } else if (stddev) {
      err("latency.stddev requires distribution: normal", stddev->line);
    }
    return {FaultKind::Latency, p};
  }
  if (key == "bandwidth") {
    allow_keys(val, {"rate", "burst"}, "bandwidth");
    BandwidthParams p;
    const YNode* rate = val.find("rate");
    const YNode* burst = val.find("burst");
    if (!rate || !burst) err("bandwidth requires 'rate' and 'burst'", val.line);
    expect_scalar(*rate, "bandwidth.rate");
    expect_scalar(*burst, "bandwidth.burst");
    p.rate_bytes_per_sec = as_uint(*rate, "bandwidth.rate");
    p.burst_bytes = as_uint(*burst, "bandwidth.burst");
    if (p.rate_bytes_per_sec == 0) err("bandwidth.rate must be > 0", rate->line);
    if (p.burst_bytes < 1) err("bandwidth.burst must be >= 1", burst->line);
    return {FaultKind::Bandwidth, p};
  }
  if (key == "fragment") {
    allow_keys(val, {"min", "max"}, "fragment");
    FragmentParams p;
    const YNode* mn = val.find("min");
    const YNode* mx = val.find("max");
    if (!mn || !mx) err("fragment requires 'min' and 'max'", val.line);
    expect_scalar(*mn, "fragment.min");
    expect_scalar(*mx, "fragment.max");
    p.min_bytes = as_uint(*mn, "fragment.min");
    p.max_bytes = as_uint(*mx, "fragment.max");
    if (p.min_bytes < 1) err("fragment.min must be >= 1", mn->line);
    if (p.max_bytes < p.min_bytes) err("fragment.max must be >= min", mx->line);
    return {FaultKind::Fragment, p};
  }
  if (key == "coalesce") {
    allow_keys(val, {"size", "max_delay"}, "coalesce");
    CoalesceParams p;
    const YNode* size = val.find("size");
    const YNode* delay = val.find("max_delay");
    if (!size || !delay) err("coalesce requires 'size' and 'max_delay'", val.line);
    expect_scalar(*size, "coalesce.size");
    expect_scalar(*delay, "coalesce.max_delay");
    p.size_bytes = as_uint(*size, "coalesce.size");
    if (p.size_bytes < 1) err("coalesce.size must be >= 1", size->line);
    p.max_delay_us = as_duration_us(*delay, "coalesce.max_delay");
    return {FaultKind::Coalesce, p};
  }
  if (key == "reorder") {
    allow_keys(val, {"depth", "max_hold"}, "reorder");
    ReorderParams p;
    const YNode* depth = val.find("depth");
    const YNode* hold = val.find("max_hold");
    if (!depth || !hold) err("reorder requires 'depth' and 'max_hold'", val.line);
    expect_scalar(*depth, "reorder.depth");
    expect_scalar(*hold, "reorder.max_hold");
    const std::uint64_t d = as_uint(*depth, "reorder.depth");
    if (d < 2 || d > std::numeric_limits<std::uint32_t>::max()) {
      err("reorder.depth must be an integer >= 2", depth->line);
    }
    p.depth = static_cast<std::uint32_t>(d);
    p.max_hold_us = as_duration_us(*hold, "reorder.max_hold");
    return {FaultKind::Reorder, p};
  }
  if (key == "duplicate") {
    allow_keys(val, {"count"}, "duplicate");
    DuplicateParams p;
    if (const YNode* count = val.find("count")) {
      expect_scalar(*count, "duplicate.count");
      const std::uint64_t c = as_uint(*count, "duplicate.count");
      if (c < 1 || c > std::numeric_limits<std::uint32_t>::max()) {
        err("duplicate.count must be an integer >= 1", count->line);
      }
      p.count = static_cast<std::uint32_t>(c);
    }
    return {FaultKind::Duplicate, p};
  }
  if (key == "corrupt") {
    allow_keys(val, {"mode", "offset", "value"}, "corrupt");
    CorruptParams p;
    const YNode* mode = val.find("mode");
    const YNode* offset = val.find("offset");
    const YNode* value = val.find("value");
    if (!mode || !offset || !value) err("corrupt requires 'mode', 'offset', 'value'", val.line);
    expect_scalar(*mode, "corrupt.mode");
    if (mode->scalar == "xor") p.mode = CorruptParams::Mode::XorByte;
    else if (mode->scalar == "overwrite") p.mode = CorruptParams::Mode::OverwriteByte;
    else err("corrupt.mode must be 'xor' or 'overwrite'", mode->line);
    p.stream_offset = as_uint(*offset, "corrupt.offset");
    const std::uint64_t v = as_uint(*value, "corrupt.value");
    if (v > 255) err("corrupt.value must be within 0..255", value->line);
    p.value = static_cast<std::uint8_t>(v);
    return {FaultKind::Corrupt, p};
  }
  if (key == "blackhole") {
    allow_keys(val, {"direction", "mode", "duration"}, "blackhole");
    BlackholeParams p;
    const YNode* dir = val.find("direction");
    const YNode* mode = val.find("mode");
    if (!dir || !mode) err("blackhole requires 'direction' and 'mode'", val.line);
    expect_scalar(*dir, "blackhole.direction");
    expect_scalar(*mode, "blackhole.mode");
    p.dir = as_dir(*dir, "blackhole.direction");
    if (mode->scalar == "discard") p.mode = BlackholeParams::Mode::Discard;
    else if (mode->scalar == "freeze") p.mode = BlackholeParams::Mode::Freeze;
    else err("blackhole.mode must be 'discard' or 'freeze'", mode->line);
    if (const YNode* dur = val.find("duration")) {
      expect_scalar(*dur, "blackhole.duration");
      p.duration_us = as_duration_us(*dur, "blackhole.duration");
    }
    return {FaultKind::Blackhole, p};
  }
  if (key == "reset") {
    allow_keys(val, {"after"}, "reset");
    ResetParams p;
    if (const YNode* after = val.find("after")) {
      expect_scalar(*after, "reset.after");
      p.after_us = as_duration_us(*after, "reset.after");
    }
    return {FaultKind::Reset, p};
  }
  if (key == "fin") {
    allow_keys(val, {"side"}, "fin");
    HalfCloseParams p;  // Mode::Tx sugar
    const YNode* side = val.find("side");
    if (!side) err("fin requires 'side'", val.line);
    expect_scalar(*side, "fin.side");
    p.leg = leg_from_side(*side);
    return {FaultKind::HalfClose, p};
  }
  if (key == "half_close") {
    allow_keys(val, {"side", "mode"}, "half_close");
    HalfCloseParams p;
    const YNode* side = val.find("side");
    if (!side) err("half_close requires 'side'", val.line);
    expect_scalar(*side, "half_close.side");
    p.leg = leg_from_side(*side);
    if (const YNode* mode = val.find("mode")) {
      expect_scalar(*mode, "half_close.mode");
      if (mode->scalar == "tx") p.mode = HalfCloseParams::Mode::Tx;
      else if (mode->scalar == "rx") p.mode = HalfCloseParams::Mode::Rx;
      else err("half_close.mode must be 'tx' or 'rx'", mode->line);
    }
    return {FaultKind::HalfClose, p};
  }
  if (key == "connect_delay") {
    allow_keys(val, {"delay"}, "connect_delay");
    ConnectDelayParams p;
    const YNode* delay = val.find("delay");
    if (!delay) err("connect_delay requires 'delay'", val.line);
    expect_scalar(*delay, "connect_delay.delay");
    p.delay_us = as_duration_us(*delay, "connect_delay.delay");
    return {FaultKind::ConnectDelay, p};
  }
  if (key == "refuse") {
    allow_keys(val, {"after"}, "refuse");
    RefuseParams p;
    if (const YNode* after = val.find("after")) {
      expect_scalar(*after, "refuse.after");
      p.after_us = as_duration_us(*after, "refuse.after");
    }
    return {FaultKind::Refuse, p};
  }
  if (key == "accept_stall") {
    allow_keys(val, {"stall"}, "accept_stall");
    AcceptStallParams p;
    const YNode* stall = val.find("stall");
    if (!stall) err("accept_stall requires 'stall'", val.line);
    expect_scalar(*stall, "accept_stall.stall");
    p.stall_us = as_duration_us(*stall, "accept_stall.stall");
    return {FaultKind::AcceptStall, p};
  }
  if (key == "idle_timeout") {
    allow_keys(val, {"idle", "action"}, "idle_timeout");
    IdleTimeoutParams p;
    const YNode* idle = val.find("idle");
    if (!idle) err("idle_timeout requires 'idle'", val.line);
    expect_scalar(*idle, "idle_timeout.idle");
    p.idle_us = as_duration_us(*idle, "idle_timeout.idle");
    if (const YNode* action = val.find("action")) {
      expect_scalar(*action, "idle_timeout.action");
      if (action->scalar == "reset") p.action = IdleTimeoutParams::Action::Reset;
      else if (action->scalar == "fin") p.action = IdleTimeoutParams::Action::Fin;
      else err("idle_timeout.action must be 'reset' or 'fin'", action->line);
    }
    return {FaultKind::IdleTimeout, p};
  }
  err("unknown inject fault '" + key + "'", inject.line);
}

// ---------------------------------------------------------------------------
// Match ("when") parsing
// ---------------------------------------------------------------------------

MatchSpec parse_when(const YNode& when) {
  expect_map(when, "when");
  allow_keys(when,
              {"direction", "after", "every_bytes", "every_events", "connection",
               "probability", "max_occurrences", "min_stream_offset", "sni"},
              "when");
  MatchSpec m;
  if (const YNode* n = when.find("direction")) {
    expect_scalar(*n, "when.direction");
    m.direction = as_dir(*n, "when.direction");
  }
  if (const YNode* n = when.find("after")) {
    expect_scalar(*n, "when.after");
    m.after_us = static_cast<TimeUs>(as_duration_us(*n, "when.after"));
  }
  if (const YNode* n = when.find("every_bytes")) m.every_bytes = as_uint(*n, "when.every_bytes");
  if (const YNode* n = when.find("every_events")) m.every_events = as_uint(*n, "when.every_events");
  if (const YNode* n = when.find("connection")) {
    expect_map(*n, "when.connection");
    allow_keys(*n, {"every", "equals"}, "when.connection");
    const YNode* every = n->find("every");
    if (!every) err("when.connection requires 'every'", n->line);
    m.connection.every = as_uint(*every, "when.connection.every");
    if (m.connection.every == 0) err("when.connection.every must be >= 1", every->line);
    if (const YNode* eq = n->find("equals")) m.connection.equals = as_uint(*eq, "when.connection.equals");
  }
  if (const YNode* n = when.find("probability")) {
    m.probability = as_double(*n, "when.probability");
    if (m.probability < 0.0 || m.probability > 1.0) {
      err("when.probability must be within [0, 1]", n->line);
    }
  }
  if (const YNode* n = when.find("max_occurrences")) m.max_occurrences = as_uint(*n, "when.max_occurrences");
  if (const YNode* n = when.find("min_stream_offset")) m.min_stream_offset = as_uint(*n, "when.min_stream_offset");
  if (const YNode* n = when.find("sni")) {
    expect_scalar(*n, "when.sni");
    m.sni = n->scalar;
  }
  return m;
}

LedgerMode parse_ledger(const YNode& n, std::uint32_t& sample_n) {
  expect_scalar(n, "ledger");
  if (n.scalar == "full") return LedgerMode::Full;
  if (n.scalar == "counts") return LedgerMode::Counts;
  if (n.scalar.rfind("sample:", 0) == 0) {
    YNode tmp;
    tmp.line = n.line;
    tmp.scalar = n.scalar.substr(7);
    const std::uint64_t v = as_uint(tmp, "ledger sample:N");
    if (v < 1 || v > std::numeric_limits<std::uint32_t>::max()) {
      err("ledger sample:N requires N >= 1", n.line);
    }
    sample_n = static_cast<std::uint32_t>(v);
    return LedgerMode::SampleN;
  }
  err("ledger must be 'full', 'counts', or 'sample:N'", n.line);
}

Endpoint parse_endpoint_field(const YNode& n, const std::string& what) {
  expect_scalar(n, what);
  try {
    return parse_endpoint(n.scalar);
  } catch (const std::invalid_argument& e) {
    throw ScenarioError(what + ": " + e.what(), n.line);
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// kind_of / kind_name
// ---------------------------------------------------------------------------

FaultKind kind_of(const FaultParams& p) {
  switch (p.index()) {
    case 0: return FaultKind::Latency;
    case 1: return FaultKind::Bandwidth;
    case 2: return FaultKind::Fragment;
    case 3: return FaultKind::Coalesce;
    case 4: return FaultKind::Reorder;
    case 5: return FaultKind::Duplicate;
    case 6: return FaultKind::Corrupt;
    case 7: return FaultKind::Blackhole;
    case 8: return FaultKind::Reset;
    case 9: return FaultKind::HalfClose;
    case 10: return FaultKind::ConnectDelay;
    case 11: return FaultKind::Refuse;
    case 12: return FaultKind::AcceptStall;
    case 13: return FaultKind::IdleTimeout;
  }
  return FaultKind::Latency;  // unreachable
}

const char* kind_name(FaultKind k) {
  switch (k) {
    case FaultKind::Latency: return "latency";
    case FaultKind::Bandwidth: return "bandwidth";
    case FaultKind::Fragment: return "fragment";
    case FaultKind::Coalesce: return "coalesce";
    case FaultKind::Reorder: return "reorder";
    case FaultKind::Duplicate: return "duplicate";
    case FaultKind::Corrupt: return "corrupt";
    case FaultKind::Blackhole: return "blackhole";
    case FaultKind::Reset: return "reset";
    case FaultKind::Fin: return "fin";  // never produced by compile_scenario
    case FaultKind::HalfClose: return "half_close";
    case FaultKind::ConnectDelay: return "connect_delay";
    case FaultKind::Refuse: return "refuse";
    case FaultKind::AcceptStall: return "accept_stall";
    case FaultKind::IdleTimeout: return "idle_timeout";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Canonical normalized JSON
// ---------------------------------------------------------------------------

namespace {

using json::Value;

Value sorted_object(std::vector<std::pair<std::string, Value>> members) {
  std::sort(members.begin(), members.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
  Value v = Value::object();
  for (auto& [k, val] : members) v.set(k, std::move(val));
  return v;
}

// Defensive recursive sort so canonical form holds regardless of construction.
Value sort_tree(Value v) {
  using T = json::Value::Type;
  if (v.type() == T::Object) {
    std::vector<std::pair<std::string, Value>> members;
    for (const auto& [k, child] : v.members()) members.emplace_back(k, sort_tree(child));
    return sorted_object(std::move(members));
  }
  if (v.type() == T::Array) {
    Value out = Value::array();
    for (const auto& child : v.items()) out.push(sort_tree(child));
    return out;
  }
  return v;
}

Value inject_json(const CompiledRule& r) {
  std::vector<std::pair<std::string, Value>> m;
  const auto add_u = [&m](const char* k, std::uint64_t v) { m.emplace_back(k, Value::u(v)); };
  const auto add_s = [&m](const char* k, const char* v) { m.emplace_back(k, Value::str(v)); };

  std::visit(
      [&](const auto& p) {
        using P = std::decay_t<decltype(p)>;
        if constexpr (std::is_same_v<P, LatencyParams>) {
          add_u("mean_us", p.mean_us);
          if (p.normal) {
            add_s("distribution", "normal");
            add_u("stddev_us", static_cast<std::uint64_t>(std::llround(p.stddev_us)));
          } else if (p.jitter_us != 0) {
            add_u("jitter_us", p.jitter_us);
          }
        } else if constexpr (std::is_same_v<P, BandwidthParams>) {
          add_u("burst_bytes", p.burst_bytes);
          add_u("rate_bytes_per_sec", p.rate_bytes_per_sec);
        } else if constexpr (std::is_same_v<P, FragmentParams>) {
          add_u("max_bytes", p.max_bytes);
          add_u("min_bytes", p.min_bytes);
        } else if constexpr (std::is_same_v<P, CoalesceParams>) {
          add_u("max_delay_us", p.max_delay_us);
          add_u("size_bytes", p.size_bytes);
        } else if constexpr (std::is_same_v<P, ReorderParams>) {
          add_u("depth", p.depth);
          add_u("max_hold_us", p.max_hold_us);
        } else if constexpr (std::is_same_v<P, DuplicateParams>) {
          add_u("count", p.count);
        } else if constexpr (std::is_same_v<P, CorruptParams>) {
          add_s("mode", p.mode == CorruptParams::Mode::XorByte ? "xor" : "overwrite");
          add_u("offset", p.stream_offset);
          add_u("value", p.value);
        } else if constexpr (std::is_same_v<P, BlackholeParams>) {
          add_s("direction", dir_name(p.dir));
          add_s("mode", p.mode == BlackholeParams::Mode::Discard ? "discard" : "freeze");
          if (p.duration_us != 0) add_u("duration_us", p.duration_us);
        } else if constexpr (std::is_same_v<P, ResetParams>) {
          if (p.after_us != 0) add_u("after_us", p.after_us);
        } else if constexpr (std::is_same_v<P, HalfCloseParams>) {
          add_s("mode", p.mode == HalfCloseParams::Mode::Tx ? "tx" : "rx");
          add_s("side", p.leg == LegSide::Down ? "client" : "server");
        } else if constexpr (std::is_same_v<P, ConnectDelayParams>) {
          add_u("delay_us", p.delay_us);
        } else if constexpr (std::is_same_v<P, RefuseParams>) {
          if (p.after_us != 0) add_u("after_us", p.after_us);
        } else if constexpr (std::is_same_v<P, AcceptStallParams>) {
          add_u("stall_us", p.stall_us);
        } else if constexpr (std::is_same_v<P, IdleTimeoutParams>) {
          add_s("action", p.action == IdleTimeoutParams::Action::Reset ? "reset" : "fin");
          add_u("idle_us", p.idle_us);
        }
      },
      r.params);
  return sorted_object(std::move(m));
}

Value when_json(const MatchSpec& w) {
  std::vector<std::pair<std::string, Value>> m;
  if (w.direction) m.emplace_back("direction", Value::str(dir_name(*w.direction)));
  if (w.after_us != 0) m.emplace_back("after_us", Value::u(static_cast<std::uint64_t>(w.after_us)));
  if (w.every_bytes != 0) m.emplace_back("every_bytes", Value::u(w.every_bytes));
  if (w.every_events != 0) m.emplace_back("every_events", Value::u(w.every_events));
  if (w.connection.every != 0 || w.connection.equals != 0) {
    std::vector<std::pair<std::string, Value>> c;
    if (w.connection.equals != 0) c.emplace_back("equals", Value::u(w.connection.equals));
    c.emplace_back("every", Value::u(w.connection.every));
    m.emplace_back("connection", sorted_object(std::move(c)));
  }
  if (w.probability != 1.0) m.emplace_back("probability", Value::d(w.probability));
  if (w.max_occurrences != ~std::uint64_t{0}) {
    m.emplace_back("max_occurrences", Value::u(w.max_occurrences));
  }
  if (w.min_stream_offset != 0) m.emplace_back("min_stream_offset", Value::u(w.min_stream_offset));
  if (!w.sni.empty()) m.emplace_back("sni", Value::str(w.sni));
  return sorted_object(std::move(m));
}

Value rule_json(const CompiledRule& r) {
  std::vector<std::pair<std::string, Value>> m;
  m.emplace_back("inject", inject_json(r));
  m.emplace_back("kind", Value::str(kind_name(r.kind)));
  if (r.ledger != LedgerMode::Full) {
    m.emplace_back("ledger", Value::str(ledger_mode_name(r.ledger)));
    if (r.ledger == LedgerMode::SampleN) m.emplace_back("sample_n", Value::u(r.sample_n));
  }
  const std::string default_name = "rule-" + std::to_string(r.index + 1);
  if (r.name != default_name) m.emplace_back("name", Value::str(r.name));
  m.emplace_back("when", when_json(r.when));
  return sorted_object(std::move(m));
}

}  // namespace

std::string normalized_json(const CompiledScenario& sc) {
  std::vector<std::pair<std::string, Value>> top;
  top.emplace_back(
      "limits", sorted_object({
                    {"max_connections", Value::u(sc.limits.max_connections)},
                    {"pending_bytes_per_direction", Value::u(sc.limits.pending_bytes_per_direction)},
                }));
  top.emplace_back("listen", Value::str(sc.listen.to_string()));
  Value rules = Value::array();
  for (const auto& r : sc.rules) rules.push(rule_json(r));
  top.emplace_back("rules", std::move(rules));
  top.emplace_back("seed", Value::u(sc.seed));
  top.emplace_back("upstream", Value::str(sc.upstream.to_string()));
  return sort_tree(sorted_object(std::move(top))).dump();
}

// ---------------------------------------------------------------------------
// compile_scenario
// ---------------------------------------------------------------------------

CompiledScenario compile_scenario(const std::string& yaml_text) {
  const cfg::YNode root = cfg::parse_yaml(yaml_text);
  expect_map(root, "scenario");
  allow_keys(root, {"version", "seed", "listen", "upstream", "limits", "rules"}, "scenario");

  const YNode* version = root.find("version");
  if (!version) err("scenario requires 'version'", root.line);
  if (version->kind != YNode::Kind::Scalar || version->scalar != "1") {
    err("unsupported scenario version (expected 1)", version->line);
  }

  const YNode* seed = root.find("seed");
  if (!seed) err("scenario requires 'seed'", root.line);
  expect_scalar(*seed, "seed");

  const YNode* listen = root.find("listen");
  const YNode* upstream = root.find("upstream");
  if (!listen) err("scenario requires 'listen'", root.line);
  if (!upstream) err("scenario requires 'upstream'", root.line);

  CompiledScenario sc;
  sc.seed = as_uint(*seed, "seed");
  sc.listen = parse_endpoint_field(*listen, "listen");
  sc.upstream = parse_endpoint_field(*upstream, "upstream");

  if (const YNode* limits = root.find("limits")) {
    expect_map(*limits, "limits");
    allow_keys(*limits, {"pending_bytes_per_direction", "max_connections"}, "limits");
    if (const YNode* n = limits->find("pending_bytes_per_direction")) {
      sc.limits.pending_bytes_per_direction = as_uint(*n, "limits.pending_bytes_per_direction");
      if (sc.limits.pending_bytes_per_direction == 0) {
        err("limits.pending_bytes_per_direction must be >= 1", n->line);
      }
    }
    if (const YNode* n = limits->find("max_connections")) {
      const std::uint64_t v = as_uint(*n, "limits.max_connections");
      if (v == 0 || v > std::numeric_limits<std::uint32_t>::max()) {
        err("limits.max_connections must be between 1 and 4294967295", n->line);
      }
      sc.limits.max_connections = static_cast<std::uint32_t>(v);
    }
  }

  if (const YNode* rules = root.find("rules")) {
    if (rules->kind != YNode::Kind::Seq) err("rules must be a list", rules->line);
    for (std::size_t i = 0; i < rules->seq.size(); ++i) {
      const YNode& rn = rules->seq[i];
      expect_map(rn, "rule");
      allow_keys(rn, {"name", "when", "ledger", "inject"}, "rule");
      CompiledRule cr;
      cr.index = static_cast<std::uint32_t>(i);
      cr.name = "rule-" + std::to_string(i + 1);
      bool name_defaulted = true;
      if (const YNode* name = rn.find("name")) {
        expect_scalar(*name, "rule name");
        if (name->scalar.empty()) err("rule name must not be empty", name->line);
        cr.name = name->scalar;
        name_defaulted = false;
      }
      if (const YNode* when = rn.find("when")) cr.when = parse_when(*when);
      if (const YNode* ledger = rn.find("ledger")) {
        cr.ledger = parse_ledger(*ledger, cr.sample_n);
      }
      const YNode* inject = rn.find("inject");
      if (!inject) err("rule requires 'inject'", rn.line);
      ParsedFault f = parse_inject(*inject);
      cr.kind = f.kind;
      cr.params = f.params;

      // SNI is only observable after the ClientHello is read (data phase).
      // Connection/accept-phase faults act before any SNI exists, so combining
      // them with when.sni yields an unreachable rule. Reject explicitly.
      if (!cr.when.sni.empty() &&
          (cr.kind == FaultKind::ConnectDelay || cr.kind == FaultKind::Refuse ||
           cr.kind == FaultKind::AcceptStall)) {
        err("when.sni cannot be combined with connection-phase faults "
            "(connect_delay, refuse, accept_stall)",
            rn.line);
      }

      // Track explicit-vs-default name so normalized_json can omit defaults:
      // normalized_json derives this itself by comparing against "rule-N", so
      // nothing extra to store here.
      (void)name_defaulted;
      sc.rules.push_back(std::move(cr));
    }
  }

  const std::string canonical = normalized_json(sc);
  sc.scenario_hash = sha256(canonical.data(), canonical.size());
  return sc;
}

}  // namespace loki
