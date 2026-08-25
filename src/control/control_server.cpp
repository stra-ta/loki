// ControlServer: nonblocking UDS NDJSON request drain.

#include <loki/control.hpp>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>

#include <loki/json_parse.hpp>

namespace loki {
namespace {

constexpr int kMaxClients = 8;
constexpr std::size_t kLineBufMax = 64 * 1024;  // per-client line buffer bound

int set_nonblock_cloexec(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0) return -1;
  if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return -1;
  int fdfl = fcntl(fd, F_GETFD, 0);
  if (fdfl < 0) return -1;
  if (fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC) < 0) return -1;
  return 0;
}

struct Client {
  int fd = -1;
  std::string inbuf;   // partial line
};

}  // namespace

ControlRequest parse_control_request(std::string_view line) {
  json::Value v;
  try {
    v = json::parse_json(line);
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string("bad control request: ") + e.what());
  }
  if (v.type() != json::Value::Type::Object) {
    throw std::runtime_error("control request must be a JSON object");
  }
  const json::Value* cmd = v.find("cmd");
  if (cmd == nullptr || cmd->type() != json::Value::Type::String) {
    throw std::runtime_error("control request missing string 'cmd'");
  }
  const std::string& c = cmd->as_str();
  ControlRequest r;
  if (c == "pause") { r.cmd = ControlCmd::Pause; return r; }
  if (c == "resume") { r.cmd = ControlCmd::Resume; return r; }
  if (c == "status") { r.cmd = ControlCmd::Status; return r; }
  if (c == "inject") {
    const json::Value* fault = v.find("fault");
    if (fault == nullptr || fault->type() != json::Value::Type::String ||
        fault->as_str() != "reset") {
      throw std::runtime_error("inject supports only fault \"reset\"");
    }
    const json::Value* conn = v.find("connection");
    if (conn == nullptr ||
        (conn->type() != json::Value::Type::UInt &&
         !(conn->type() == json::Value::Type::Int && conn->as_int() >= 0))) {
      throw std::runtime_error("inject requires unsigned 'connection'");
    }
    r.cmd = ControlCmd::InjectReset;
    r.conn = conn->type() == json::Value::Type::UInt ? conn->as_uint()
                                                     : static_cast<std::uint64_t>(conn->as_int());
    return r;
  }
  throw std::runtime_error("unknown cmd: " + c);
}

std::string control_ok_response(std::string_view status_json_or_empty) {
  std::string out = "{\"ok\":true";
  if (!status_json_or_empty.empty()) {
    out += ",\"status\":";
    out += status_json_or_empty;
  }
  out += "}";
  return out;
}

std::string control_error_response(std::string_view message) {
  // message must be a JSON-escaped string body.
  std::string out = "{\"ok\":false,\"error\":\"";
  for (const char ch : message) {
    switch (ch) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      default: out += ch;
    }
  }
  out += "\"}";
  return out;
}

class ControlServer::Impl {
 public:
  explicit Impl(std::string path) : path_(std::move(path)) {}

  bool bind_and_listen() {
    ::unlink(path_.c_str());  // stale socket from a previous run

    listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd_ < 0) { fail_ = true; return false; }
    if (set_nonblock_cloexec(listen_fd_) < 0) { fail_ = true; return false; }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path_.size() >= sizeof(addr.sun_path)) {
      errno = ENAMETOOLONG;
      fail_ = true;
      return false;
    }
    std::memcpy(addr.sun_path, path_.c_str(), path_.size());

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
      fail_ = true;
      return false;
    }
    if (::listen(listen_fd_, kMaxClients) < 0) {
      fail_ = true;
      return false;
    }
    return true;
  }

  ~Impl() {
    for (auto& c : clients_) {
      if (c.fd >= 0) ::close(c.fd);
    }
    if (listen_fd_ >= 0) ::close(listen_fd_);
    if (!fail_) ::unlink(path_.c_str());
  }

  std::vector<ControlRequest> poll_requests() {
    accept_new_clients();

    std::vector<ControlRequest> requests;

    // Build poll set: listener + clients.
    std::vector<::pollfd> pfds;
    pfds.push_back({listen_fd_, POLLIN, 0});
    for (const auto& c : clients_) pfds.push_back({c.fd, POLLIN, 0});

    int rc = ::poll(pfds.data(), static_cast<nfds_t>(pfds.size()), 0);  // nonblocking
    if (rc <= 0) return requests;

    for (std::size_t i = 1; i < pfds.size(); ++i) {
      Client& c = clients_[i - 1];
      if ((pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;
      char buf[4096];
      while (true) {
        ssize_t n = ::recv(c.fd, buf, sizeof buf, MSG_DONTWAIT);
        if (n > 0) {
          c.inbuf.append(buf, static_cast<std::size_t>(n));
          if (c.inbuf.size() > kLineBufMax) { drop(i - 1); break; }
          // Extract complete NDJSON lines.
          std::size_t pos;
          while ((pos = c.inbuf.find('\n')) != std::string::npos) {
            std::string line = c.inbuf.substr(0, pos);
            c.inbuf.erase(0, pos + 1);
            handle_line(c, line, requests);
          }
          continue;
        }
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
          drop(i - 1);
        }
        break;
      }
    }

    // Compact closed clients.
    clients_.erase(std::remove_if(clients_.begin(), clients_.end(),
                                  [](const Client& c) { return c.fd < 0; }),
                   clients_.end());
    return requests;
  }

 private:
  void handle_line(Client& c, const std::string& line, std::vector<ControlRequest>& out) {
    try {
      ControlRequest r = parse_control_request(line);
      // Responses are tiny: acknowledge inline. Status carries an empty
      // placeholder object; richer snapshots belong to the reactor layer,
      // which consumes the returned request.
      best_effort_write(c.fd,
                        control_ok_response(r.cmd == ControlCmd::Status ? "{}" : "") + "\n");
      out.push_back(r);
    } catch (const std::exception& e) {
      // Malformed line: immediate error response to this client.
      best_effort_write(c.fd, control_error_response(e.what()) + "\n");
    }
  }

  // Responses are tiny (< a few hundred bytes): blocking best-effort write,
  // documented choice over a writable-drain queue.
  static void best_effort_write(int fd, const std::string& data) {
    std::size_t off = 0;
    while (off < data.size()) {
      ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
      if (n <= 0) {
        if (n < 0 && (errno == EINTR)) continue;
        break;
      }
      off += static_cast<std::size_t>(n);
    }
  }

  void accept_new_clients() {
    while (static_cast<int>(clients_.size()) < kMaxClients) {
      int fd = ::accept(listen_fd_, nullptr, nullptr);
      if (fd < 0) break;  // EAGAIN or error: done for this poll
      if (set_nonblock_cloexec(fd) < 0) {
        ::close(fd);
        break;
      }
      clients_.push_back(Client{fd, {}});
    }
  }

  void drop(std::size_t idx) {
    if (clients_[idx].fd >= 0) {
      ::close(clients_[idx].fd);
      clients_[idx].fd = -1;
    }
  }

 public:
  int listen_fd_ = -1;
  std::vector<Client> clients_;
  std::string path_;
  bool fail_ = false;
};

ControlServer::ControlServer(std::string socket_path)
    : impl_(nullptr), socket_path_(socket_path) {
  impl_ = std::make_unique<Impl>(socket_path_);
  if (!impl_->bind_and_listen()) {
    std::string err = std::strerror(errno);
    impl_.reset();
    throw std::runtime_error("cannot bind control socket at " + socket_path_ + ": " + err);
  }
  listen_fd_ = impl_->listen_fd_;
}

ControlServer::~ControlServer() = default;

std::vector<ControlRequest> ControlServer::poll_requests() {
  return impl_->poll_requests();
}

}  // namespace loki
