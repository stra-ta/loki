// Blocking/nonblocking TCP socket helpers for the reactor.
// Internal to the transport package; not a public header.
//
// Error conventions:
// - Functions that "return an fd" (tcp_listen, tcp_connect) throw
//   std::runtime_error with strerror context on failure.
// - Per-operation functions (tcp_accept, read_some, write_some, connect_error,
//   local_port) report failure via return value / flags, never throw.
// - EINTR is retried inside read/write loops; EAGAIN/EWOULDBLOCK is reported
//   as would_block; n == 0 on read means peer EOF (closed = true).

#pragma once

#include <cstddef>
#include <cstdint>

#include <loki/endpoint.hpp>

namespace loki::sock {

struct IoResult {
  long n = 0;
  bool would_block = false;
  bool closed = false;  // read: n == 0 EOF
};

void set_nonblock_cloexec(int fd);

int tcp_listen(const Endpoint& ep, int backlog = 128);
int tcp_accept(int listen_fd, std::string* peer_out);  // -1 on would-block
int tcp_connect(const Endpoint& ep);                   // fd even on EINPROGRESS
int connect_error(int fd);                             // SO_ERROR; 0 = ok
std::uint16_t local_port(int fd);

IoResult read_some(int fd, void* buf, std::size_t len);
IoResult write_some(int fd, const void* buf, std::size_t len);

void rst_close(int fd);            // SO_LINGER {1,0} then close => RST
void shutdown_write(int fd);
void shutdown_read(int fd);

}  // namespace loki::sock
