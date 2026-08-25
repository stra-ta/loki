// RunStore: run directory creation, streaming evidence writers,
// decision ledger (de)serialization.

#include <loki/version.hpp>
#include <loki/evidence.hpp>

#include <sys/utsname.h>
#include <unistd.h>

#include <ctime>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include <loki/json_parse.hpp>
#include <loki/version.hpp>

namespace loki {
namespace {

// ---------------------------------------------------------------------------
// Pretty printer: 2-space indent, deterministic key order = insertion order.
// ---------------------------------------------------------------------------

void pretty_write(const json::Value& v, std::string& out, int depth) {
  const std::string pad(static_cast<std::size_t>(depth) * 2, ' ');
  const std::string pad_in(static_cast<std::size_t>(depth + 1) * 2, ' ');
  switch (v.type()) {
    case json::Value::Type::Object: {
      if (v.members().empty()) { out += "{}"; return; }
      out += "{\n";
      bool first = true;
      for (const auto& [k, m] : v.members()) {
        if (!first) out += ",\n";
        first = false;
        out += pad_in;
        out += json::escape(k);
        out += ": ";
        pretty_write(m, out, depth + 1);
      }
      out += '\n';
      out += pad;
      out += '}';
      break;
    }
    case json::Value::Type::Array: {
      if (v.items().empty()) { out += "[]"; return; }
      out += "[\n";
      bool first = true;
      for (const auto& m : v.items()) {
        if (!first) out += ",\n";
        first = false;
        out += pad_in;
        pretty_write(m, out, depth + 1);
      }
      out += '\n';
      out += pad;
      out += ']';
      break;
    }
    default:
      out += v.dump();
  }
}

std::string pretty_dump(const json::Value& v) {
  std::string out;
  pretty_write(v, out, 0);
  out += '\n';
  return out;
}

[[maybe_unused]] std::string iso8601_utc(WallUs us) {
  std::time_t secs = static_cast<std::time_t>(us / 1000000);
  std::int64_t frac = us % 1000000;
  if (frac < 0) { --secs; frac += 1000000; }
  std::tm tm{};
  gmtime_r(&secs, &tm);
  char buf[40];
  std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%06lldZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long long>(frac));
  return buf;
}

void write_file_exclusive_or_truncate(const std::filesystem::path& p, const std::string& data) {
  std::ofstream f(p, std::ios::binary | std::ios::trunc);
  if (!f) throw std::runtime_error("cannot write " + p.string());
  f.write(data.data(), static_cast<std::streamsize>(data.size()));
  if (!f) throw std::runtime_error("short write to " + p.string());
}

}  // namespace

// ---------------------------------------------------------------------------
// decision_to_json / decision_from_json - format LOCKED
// ---------------------------------------------------------------------------

json::Value decision_to_json(const FaultDecision& d) {
  json::Value v = json::Value::object();
  v.set("event", json::Value::u(d.event_index));
  v.set("connection", json::Value::u(d.conn));
  v.set("direction", json::Value::str(dir_name(d.dir)));
  v.set("stream_offset", json::Value::u(d.stream_offset));
  v.set("rule_index", json::Value::u(d.rule_index));
  v.set("rule", json::Value::str(d.rule_name));
  v.set("kind", json::Value::str(kind_name(d.kind)));
  v.set("applied", json::Value::b(d.applied));
  v.set("bytes_seen", json::Value::u(d.inputs.bytes_seen));
  v.set("elapsed_us", json::Value::u(d.inputs.elapsed_us));
  v.set("parameters", d.resolved);
  return v;
}

namespace {

const json::Value* require_field(const json::Value& v, const char* key) {
  const json::Value* f = v.find(key);
  if (f == nullptr) {
    throw std::runtime_error(std::string("decision record missing field '") + key + "'");
  }
  return f;
}

std::uint64_t require_uint(const json::Value& v, const char* key) {
  const json::Value* f = require_field(v, key);
  if (f->type() == json::Value::Type::UInt) return f->as_uint();
  if (f->type() == json::Value::Type::Int && f->as_int() >= 0) {
    return static_cast<std::uint64_t>(f->as_int());
  }
  throw std::runtime_error(std::string("decision field '") + key + "' must be an unsigned integer");
}

std::string require_str(const json::Value& v, const char* key) {
  const json::Value* f = require_field(v, key);
  if (f->type() != json::Value::Type::String) {
    throw std::runtime_error(std::string("decision field '") + key + "' must be a string");
  }
  return f->as_str();
}

}  // namespace

FaultDecision decision_from_json(const json::Value& v) {
  if (v.type() != json::Value::Type::Object) {
    throw std::runtime_error("decision record must be a JSON object");
  }
  FaultDecision d;
  d.event_index = require_uint(v, "event");
  d.conn = require_uint(v, "connection");
  std::optional<Dir> dir = dir_from_string(require_str(v, "direction"));
  if (!dir) throw std::runtime_error("decision field 'direction' is invalid");
  d.dir = *dir;
  d.stream_offset = require_uint(v, "stream_offset");
  d.rule_index = static_cast<std::uint32_t>(require_uint(v, "rule_index"));
  d.rule_name = require_str(v, "rule");
  std::string kind = require_str(v, "kind");
  // kind parsed back via the canonical names produced by kind_name().
  bool matched = false;
  for (std::uint8_t k = 0; k <= static_cast<std::uint8_t>(FaultKind::IdleTimeout); ++k) {
    auto fk = static_cast<FaultKind>(k);
    if (kind == kind_name(fk)) { d.kind = fk; matched = true; break; }
  }
  if (!matched) throw std::runtime_error("decision field 'kind' is unknown: " + kind);
  const json::Value* applied = require_field(v, "applied");
  if (applied->type() != json::Value::Type::Bool) {
    throw std::runtime_error("decision field 'applied' must be a boolean");
  }
  d.applied = applied->as_bool();
  d.inputs.bytes_seen = require_uint(v, "bytes_seen");
  d.inputs.elapsed_us = require_uint(v, "elapsed_us");
  const json::Value* params = require_field(v, "parameters");
  if (params->type() != json::Value::Type::Object) {
    throw std::runtime_error("decision field 'parameters' must be an object");
  }
  d.resolved = *params;  // opaque passthrough
  return d;
}

// ---------------------------------------------------------------------------
// RunStore
// ---------------------------------------------------------------------------

class RunStore::Impl {
 public:
  std::string run_dir;
  std::FILE* connections_f = nullptr;
  bool finished = false;
};

RunStore RunStore::create(const std::string& runs_root,
                          const ManifestInfo& info,
                          const std::string& scenario_yaml_text,
                          const std::string& normalized_json_text) {
  namespace fs = std::filesystem;

  // run-YYYYmmdd-HHMMSS-<pid> in UTC; append -2, -3... on collision.
  std::time_t secs = static_cast<std::time_t>(info.started_at / 1000000);
  std::tm tm{};
  gmtime_r(&secs, &tm);
  char stamp[16];
  std::snprintf(stamp, sizeof stamp, "%04d%02d%02d-%02d%02d%02d",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec);
  const long pid = ::getpid();
  fs::path base = fs::path(runs_root) / ("run-" + std::string(stamp) + "-" + std::to_string(pid));
  fs::path dir = base;
  int suffix = 2;
  while (fs::exists(dir)) {
    dir = base.string() + "-" + std::to_string(suffix++);
  }
  std::error_code ec;
  fs::create_directories(dir, ec);
  if (ec) throw std::runtime_error("cannot create run dir " + dir.string() + ": " + ec.message());

  // manifest.json: deterministic key order matching ManifestInfo fields.
  json::Value m = json::Value::object();
  m.set("loki_version", json::Value::str(info.loki_version.empty() ? LOKI_VERSION_STRING : info.loki_version));
  m.set("rng_version", json::Value::i(info.rng_version));
  m.set("ledger_format_version", json::Value::i(info.ledger_format_version));
  m.set("git_sha", json::Value::str(info.git_sha));
  m.set("scenario_hash_hex", json::Value::str(info.scenario_hash_hex));
  m.set("seed", json::Value::u(info.seed));
  m.set("started_at", json::Value::i(info.started_at));
  m.set("started_at_iso", json::Value::str(iso8601_utc(info.started_at)));
  m.set("platform", json::Value::str(info.platform));
  m.set("kernel", json::Value::str(info.kernel));
  m.set("backend", json::Value::str(info.backend));
  m.set("mode", json::Value::str(info.mode));

  write_file_exclusive_or_truncate(dir / "manifest.json", pretty_dump(m));
  write_file_exclusive_or_truncate(dir / "scenario.yaml", scenario_yaml_text);
  write_file_exclusive_or_truncate(dir / "scenario.normalized.json", normalized_json_text);

  RunStore rs;
  rs.impl_ = std::make_unique<Impl>();
  rs.impl_->run_dir = dir.string();

  rs.event_log_.f_ = std::fopen((dir / "events.jsonl").c_str(), "w");
  if (rs.event_log_.f_ == nullptr) throw std::runtime_error("cannot open events.jsonl");
  rs.impl_->connections_f = std::fopen((dir / "connections.jsonl").c_str(), "w");
  if (rs.impl_->connections_f == nullptr) throw std::runtime_error("cannot open connections.jsonl");
  return rs;
}

RunStore::~RunStore() {
  // Safe teardown: flush and close any logs still open. finish() already
  // closed them when it ran; FILE* nulls make this idempotent.
  if (event_log_.f_ != nullptr) {
    std::fflush(event_log_.f_);
    std::fclose(event_log_.f_);
    event_log_.f_ = nullptr;
  }
  if (impl_ && impl_->connections_f != nullptr) {
    std::fflush(impl_->connections_f);
    std::fclose(impl_->connections_f);
    impl_->connections_f = nullptr;
  }
}

RunStore::RunStore(RunStore&& other) noexcept
    : impl_(std::move(other.impl_)), event_log_(other.event_log_) {
  // Detach the source: the raw FILE* now belongs to this store only.
  other.event_log_.f_ = nullptr;
  other.event_log_.written_ = 0;
}

RunStore& RunStore::operator=(RunStore&& other) noexcept {
  if (this != &other) {
    RunStore tmp(std::move(other));
    std::swap(impl_, tmp.impl_);
    std::swap(event_log_.f_, tmp.event_log_.f_);
    std::swap(event_log_.written_, tmp.event_log_.written_);
    for (int i = 0; i < 16; ++i) std::swap(event_log_.counts_by_kind_[i], tmp.event_log_.counts_by_kind_[i]);
  }
  return *this;
}

const std::string& RunStore::run_dir() const {
  static const std::string empty;
  return impl_ ? impl_->run_dir : empty;
}

std::string RunStore::control_socket_path() const {
  return run_dir() + "/control.sock";
}

RunStore::EventLog& RunStore::events() { return event_log_; }

void RunStore::EventLog::append(const FaultDecision& d) {
  if (f_ == nullptr) throw std::runtime_error("events.jsonl is closed");
  std::string line = decision_to_json(d).dump();
  line += '\n';
  std::fwrite(line.data(), 1, line.size(), f_);
  std::fflush(f_);  // crash-safe per line
  ++written_;
}

void RunStore::EventLog::note_counts(FaultKind kind, std::uint64_t n) {
  unsigned idx = static_cast<unsigned>(kind);
  if (idx < 16) counts_by_kind_[idx] += n;
}

void RunStore::EventLog::flush() {
  if (f_ != nullptr) std::fflush(f_);
}

void RunStore::log_connection(const json::Value& record) {
  if (impl_ == nullptr || impl_->connections_f == nullptr) {
    throw std::runtime_error("connections.jsonl is closed");
  }
  std::string line = record.dump();
  line += '\n';
  std::fwrite(line.data(), 1, line.size(), impl_->connections_f);
  std::fflush(impl_->connections_f);
}

void RunStore::finish(const json::Value& metrics, const json::Value& summary) {
  if (!impl_ || impl_->finished) return;  // idempotent
  write_file_exclusive_or_truncate(std::filesystem::path(impl_->run_dir) / "metrics.json",
                                   pretty_dump(metrics));
  write_file_exclusive_or_truncate(std::filesystem::path(impl_->run_dir) / "summary.json",
                                   pretty_dump(summary));
  impl_->finished = true;
  if (event_log_.f_ != nullptr) {
    std::fflush(event_log_.f_);
    std::fclose(event_log_.f_);
    event_log_.f_ = nullptr;
  }
  if (impl_->connections_f != nullptr) {
    std::fflush(impl_->connections_f);
    std::fclose(impl_->connections_f);
    impl_->connections_f = nullptr;
  }
}

}  // namespace loki
