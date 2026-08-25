// Transport tests: poller smoke via socketpairs, socket utils on loopback.

#include <catch2/catch_test_macros.hpp>
#include <loki/endpoint.hpp>
#include <loki/poller.hpp>
#include <loki/types.hpp>

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <string>

#include "../src/transport/socket_util.hpp"

using namespace loki;
using namespace loki::sock;

namespace {

std::array<int, 2> make_socketpair() {
  std::array<int, 2> fds{-1, -1};
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data()) == 0);
  return fds;
}

Endpoint loopback_port(int port) { return Endpoint{"127.0.0.1", static_cast<std::uint16_t>(port)}; }

// Nonblocking connects may need a moment to land in the accept queue.
int accept_retry(int lfd) {
  for (int i = 0; i < 500; ++i) {
    int fd = tcp_accept(lfd, nullptr);
    if (fd >= 0) return fd;
    usleep(5000);
  }
  return -1;
}

}  // namespace

TEST_CASE("poller token roundtrip and add/mod/del/wait") {
  auto p = make_poller();
  REQUIRE(p != nullptr);
  const Token tok{FdKind::Downstream, 12345};
  REQUIRE(p->backend_name() != nullptr);

  auto [a, b] = make_socketpair();
  set_nonblock_cloexec(a);
  set_nonblock_cloexec(b);

  // Nothing written yet: a read wait must time out empty.
  std::vector<PollEvent> evs;
  CHECK(p->wait(10, evs) == 0);

  // mod to write interest: peer socket is writable immediately.
  REQUIRE(p->add(a, tok.raw(), PRead));
  REQUIRE(p->mod(a, tok.raw(), PWrite));
  evs.clear();
  REQUIRE(p->wait(50, evs) >= 1);
  bool found = false;
  for (const auto& e : evs) {
    if (e.token == tok.raw()) {
      found = true;
      CHECK((e.events & PWrite) != PNone);
    }
  }
  CHECK(found);

  // Data becomes readable; the exact raw token value comes back untouched.
  const char msg = 'x';
  REQUIRE(::write(b, &msg, 1) == 1);
  REQUIRE(p->mod(a, tok.raw(), PRead));
  evs.clear();
  REQUIRE(p->wait(50, evs) >= 1);
  found = false;
  for (const auto& e : evs) {
    if (e.token == tok.raw()) {
      found = true;
      CHECK((e.events & PRead) != PNone);
    }
  }
  CHECK(found);

  // del removes interest.
  REQUIRE(p->del(a));
  evs.clear();
  CHECK(p->wait(10, evs) == 0);

  ::close(a);
  ::close(b);
}

TEST_CASE("poller reports hup when peer closes") {
  auto p = make_poller();
  auto [a, b] = make_socketpair();
  set_nonblock_cloexec(a);
  REQUIRE(p->add(a, Token{FdKind::Upstream, 9}.raw(), PRead));
  ::close(b);
  std::vector<PollEvent> evs;
  REQUIRE(p->wait(100, evs) >= 1);
  bool hup_seen = false;
  for (const auto& e : evs) {
    if (Token::from_raw(e.token).conn == 9) hup_seen = e.hup || ((e.events & PRead) != PNone);
  }
  CHECK(hup_seen);
  ::close(a);
}

TEST_CASE("tcp_listen/tcp_connect/tcp_accept echo one byte on ephemeral port") {
  Endpoint listen_ep{"127.0.0.1", 0};  // port 0 binds an ephemeral port
  int lfd = tcp_listen(listen_ep);
  const std::uint16_t port = local_port(lfd);
  REQUIRE(port != 0);

  int cfd = tcp_connect(loopback_port(port));
  int sfd = accept_retry(lfd);
  REQUIRE(sfd >= 0);

  const char sent = 'Z';
  IoResult w = write_some(cfd, &sent, 1);
  REQUIRE(w.n == 1);
  char got = 0;
  IoResult r;
  for (int i = 0; i < 400; ++i) {  // up to ~2s for the byte to arrive
    r = read_some(sfd, &got, 1);
    if (r.n == 1 || (r.n < 0) || r.closed) break;
    usleep(5000);
  }
  REQUIRE(r.n == 1);
  CHECK(got == 'Z');

  ::close(cfd);
  ::close(sfd);
  ::close(lfd);
}

TEST_CASE("rst_close forces ECONNRESET on the peer") {
  int lfd = tcp_listen({"127.0.0.1", 0});
  int cfd = tcp_connect(loopback_port(local_port(lfd)));
  int sfd = accept_retry(lfd);
  REQUIRE(sfd >= 0);

  rst_close(cfd);
  char buf[16];
  IoResult r{};
  for (int i = 0; i < 400; ++i) {  // up to ~2s for the RST to arrive
    r = read_some(sfd, buf, sizeof buf);
    if (r.n < 0 || r.closed) break;
    usleep(5000);
  }
  INFO("errno=" << errno << " (" << std::strerror(errno) << ")");
  CHECK(r.n < 0);  // hard error: RST surfaces as ECONNRESET
  CHECK(errno == ECONNRESET);

  if (sfd >= 0) ::close(sfd);
  ::close(lfd);
}

TEST_CASE("shutdown_write yields EOF on the peer") {
  int lfd = tcp_listen({"127.0.0.1", 0});
  int cfd = tcp_connect(loopback_port(local_port(lfd)));
  int sfd = accept_retry(lfd);
  REQUIRE(sfd >= 0);

  shutdown_write(cfd);
  char buf[4];
  IoResult r{};
  for (int i = 0; i < 400; ++i) {  // up to ~2s for the FIN to arrive
    r = read_some(sfd, buf, sizeof buf);
    if (r.closed || r.n < 0) break;
    usleep(5000);
  }
  CHECK(r.closed);  // n == 0 EOF

  ::close(cfd);
  ::close(sfd);
  ::close(lfd);
}

TEST_CASE("connect_error reports success after a nonblocking connect completes") {
  int lfd = tcp_listen({"127.0.0.1", 0});
  int cfd = tcp_connect(loopback_port(local_port(lfd)));
  // Loopback connects usually finish inline; either way SO_ERROR is 0 once up.
  for (int i = 0; i < 200 && connect_error(cfd) == EINPROGRESS; ++i) usleep(5000);
  CHECK(connect_error(cfd) == 0);
  ::close(cfd);
  ::close(lfd);
}
