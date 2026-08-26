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

#include <sys/socket.h>

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

// --- UDP helpers (datagram transport) ------------------------------------
// All throw std::runtime_error on setup failure; per-operation helpers use
// IoResult (would_block / closed flags), never throw.

int udp_bind(const Endpoint& ep);  // bind a datagram socket to ep, nonblock
int udp_connect(const Endpoint& ep);  // create + connect() a datagram socket
                                    // to ep (sets default peer); nonblock
IoResult recvfrom_some(int fd, void* buf, std::size_t len,
                       sockaddr_storage* from, socklen_t* fromlen);
IoResult sendto_some(int fd, const void* buf, std::size_t len,
                     const sockaddr_storage& to, socklen_t tolen);
// Stable string key/label for a datagram source address: "host:port" (IPv4)
// or "[host]:port" (IPv6). Used both for the connection peer label and for the
// client-endpoint -> ConnId mapping.
std::string sockaddr_to_str(const sockaddr_storage& sa, socklen_t len);

}  // namespace loki::sock
