// TCP socket helpers implementation.

#include "socket_util.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

namespace loki::sock {

void set_nonblock_cloexec(int fd) {
  const int fl = ::fcntl(fd, F_GETFL, 0);
  if (fl >= 0) (void)::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
  const int fdfl = ::fcntl(fd, F_GETFD, 0);
  if (fdfl >= 0) (void)::fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC);
}

int tcp_listen(const Endpoint& ep, int backlog) {
  struct addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
  hints.ai_protocol = IPPROTO_TCP;

  const std::string port = std::to_string(ep.port);
  struct addrinfo* res = nullptr;
  int rc = ::getaddrinfo(ep.host.c_str(), port.c_str(), &hints, &res);
  if (rc != 0 && (rc == EAI_NONAME || rc == EAI_FAMILY)) {
    // Hostnames are allowed for upstream-style endpoints; retry without
    // AI_NUMERICHOST so "example.com:80" resolves.
    hints.ai_flags = AI_PASSIVE;
    rc = ::getaddrinfo(ep.host.c_str(), port.c_str(), &hints, &res);
  }
  if (rc != 0) {
    throw std::runtime_error("tcp_listen: getaddrinfo(" + ep.to_string() +
                             "): " + ::gai_strerror(rc));
  }

  int fd = -1;
  std::string last_err;
  for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
    fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
      last_err = std::strerror(errno);
      continue;
    }
    int one = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (::bind(fd, ai->ai_addr, ai->ai_addrlen) < 0 || ::listen(fd, backlog) < 0) {
      last_err = std::strerror(errno);
      ::close(fd);
      fd = -1;
      continue;
    }
    break;
  }
  ::freeaddrinfo(res);
  if (fd < 0) throw std::runtime_error("tcp_listen(" + ep.to_string() + "): " + last_err);
  set_nonblock_cloexec(fd);
  return fd;
}

int tcp_accept(int listen_fd, std::string* peer_out) {
  sockaddr_storage ss{};
  socklen_t slen = sizeof ss;
  int fd;
  do {
    fd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&ss), &slen);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNABORTED) return -1;
    return -1;
  }
  set_nonblock_cloexec(fd);
  if (peer_out != nullptr) {
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    if (::getnameinfo(reinterpret_cast<sockaddr*>(&ss), slen, host, sizeof host,
                      serv, sizeof serv, NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
      if (ss.ss_family == AF_INET6) *peer_out = std::string("[") + host + "]:" + serv;
      else *peer_out = std::string(host) + ":" + serv;
    } else {
      *peer_out = "unknown";
    }
  }
  return fd;
}

int tcp_connect(const Endpoint& ep) {
  struct addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  const std::string port = std::to_string(ep.port);
  struct addrinfo* res = nullptr;
  int rc = ::getaddrinfo(ep.host.c_str(), port.c_str(), &hints, &res);
  if (rc != 0) {
    throw std::runtime_error("tcp_connect: getaddrinfo(" + ep.to_string() +
                             "): " + ::gai_strerror(rc));
  }

  int fd = -1;
  std::string last_err = "no address";
  for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
    fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
      last_err = std::strerror(errno);
      continue;
    }
    set_nonblock_cloexec(fd);  // nonblocking connect; EINPROGRESS is expected
    if (::connect(fd, ai->ai_addr, ai->ai_addrlen) < 0 && errno != EINPROGRESS) {
      last_err = std::strerror(errno);
      ::close(fd);
      fd = -1;
      continue;
    }
    break;
  }
  ::freeaddrinfo(res);
  if (fd < 0) throw std::runtime_error("tcp_connect(" + ep.to_string() + "): " + last_err);
  return fd;
}

int connect_error(int fd) {
  int err = 0;
  socklen_t len = sizeof err;
  if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) return errno;
  return err;
}

std::uint16_t local_port(int fd) {
  sockaddr_storage ss{};
  socklen_t slen = sizeof ss;
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&ss), &slen) < 0) return 0;
  if (ss.ss_family == AF_INET)
    return ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port);
  if (ss.ss_family == AF_INET6)
    return ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port);
  return 0;
}

IoResult read_some(int fd, void* buf, std::size_t len) {
  IoResult r;
  ssize_t n;
  do {
    n = ::read(fd, buf, len);
  } while (n < 0 && errno == EINTR);
  if (n > 0) {
    r.n = static_cast<long>(n);
    return r;
  }
  if (n == 0) {
    r.closed = true;
    return r;
  }
  if (errno == EAGAIN || errno == EWOULDBLOCK) {
    r.would_block = true;
    return r;
  }
  r.n = -1;  // hard error surfaced as negative count
  return r;
}

IoResult write_some(int fd, const void* buf, std::size_t len) {
  IoResult r;
  ssize_t n;
  do {
    n = ::write(fd, buf, len);
  } while (n < 0 && errno == EINTR);
  if (n >= 0) {
    r.n = static_cast<long>(n);
    return r;
  }
  if (errno == EAGAIN || errno == EWOULDBLOCK) {
    r.would_block = true;
    return r;
  }
  r.n = -1;
  return r;
}

void rst_close(int fd) {
  struct linger lg{};
  lg.l_onoff = 1;
  lg.l_linger = 0;
  (void)::setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
  (void)::close(fd);
}

void shutdown_write(int fd) { (void)::shutdown(fd, SHUT_WR); }
void shutdown_read(int fd) { (void)::shutdown(fd, SHUT_RD); }

}  // namespace loki::sock
