#pragma once

// Control plane: a nonblocking unix-domain-socket server polled by the main
// reactor. NDJSON protocol, one request line per client message:
//
//   {"cmd":"pause"}
//   {"cmd":"resume"}
//   {"cmd":"status"}                      -> {"ok":true,"status":{...}}
//   {"cmd":"inject","fault":"reset","connection":17}
//
// Manual injections are recorded into the same decision ledger as rule
// firings (rule_name "manual-ctl"), so operator actions remain evidence.

#include <memory>
#include <string>
#include <vector>

#include <loki/types.hpp>

namespace loki {

enum class ControlCmd : std::uint8_t { Pause, Resume, Status, InjectReset };

struct ControlRequest {
  ControlCmd cmd{};
  ConnId conn = 0;  // used by InjectReset; 0 otherwise
};

// Parses one request line. Throws std::runtime_error on malformed input.
ControlRequest parse_control_request(std::string_view line);

std::string control_ok_response(std::string_view status_json_or_empty);
std::string control_error_response(std::string_view message);

class ControlServer {
 public:
  // Binds a listening unix socket at socket_path (unlinks stale path first).
  // Throws std::runtime_error on failure.
  explicit ControlServer(std::string socket_path);
  ~ControlServer();

  ControlServer(const ControlServer&) = delete;
  ControlServer& operator=(const ControlServer&) = delete;

  int listen_fd() const { return listen_fd_; }

  // Nonblocking drain of the listener + connected clients.
  // Returns parsed requests in arrival order; malformed lines produce an
  // error response to that client and no request.
  std::vector<ControlRequest> poll_requests();

 private:
  int listen_fd_ = -1;
  class Impl;
  std::unique_ptr<Impl> impl_;
  std::string socket_path_;
};

}  // namespace loki
