// Control package tests: request parsing, response shapes, live UDS round-trip.

#include <catch2/catch_test_macros.hpp>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>
#include <string>

#include <loki/control.hpp>

using namespace loki;

namespace {

std::string make_socket_path() {
  char tmpl[] = "/tmp/loki-ctl-test-XXXXXX";
  char* dir = ::mkdtemp(tmpl);
  REQUIRE(dir != nullptr);
  return std::string(dir) + "/control.sock";
}

std::string recv_line(int fd) {
  std::string out;
  char c;
  while (true) {
    ssize_t n = ::recv(fd, &c, 1, 0);
    if (n <= 0) break;
    out += c;
    if (c == '\n') break;
  }
  return out;
}

}  // namespace

TEST_CASE("parse_control_request accepts the four commands", "[control]") {
  ControlRequest r = parse_control_request("{\"cmd\":\"pause\"}");
  CHECK(r.cmd == ControlCmd::Pause);
  CHECK(r.conn == 0);

  CHECK(parse_control_request("{\"cmd\":\"resume\"}").cmd == ControlCmd::Resume);
  CHECK(parse_control_request("{\"cmd\":\"status\"}").cmd == ControlCmd::Status);

  r = parse_control_request("{\"cmd\":\"inject\",\"fault\":\"reset\",\"connection\":17}");
  CHECK(r.cmd == ControlCmd::InjectReset);
  CHECK(r.conn == 17);
}

TEST_CASE("parse_control_request rejects malformed input", "[control]") {
  CHECK_THROWS_AS(parse_control_request("{not json"), std::runtime_error);
  CHECK_THROWS_AS(parse_control_request("[]"), std::runtime_error);
  CHECK_THROWS_AS(parse_control_request("{}"), std::runtime_error);            // no cmd
  CHECK_THROWS_AS(parse_control_request("{\"cmd\":\"explode\"}"), std::runtime_error);
  CHECK_THROWS_AS(parse_control_request("{\"inject\":1}"), std::runtime_error);
  CHECK_THROWS_AS(parse_control_request(
                      "{\"cmd\":\"inject\",\"fault\":\"meteor\",\"connection\":1}"),
                  std::runtime_error);
  CHECK_THROWS_AS(parse_control_request("{\"cmd\":\"inject\",\"fault\":\"reset\"}"),
                  std::runtime_error);  // missing connection
}

TEST_CASE("response helpers produce the locked shape", "[control]") {
  CHECK(control_ok_response("") == "{\"ok\":true}");
  CHECK(control_ok_response("{\"paused\":false}") ==
        "{\"ok\":true,\"status\":{\"paused\":false}}");
  CHECK(control_error_response("bad cmd") == "{\"ok\":false,\"error\":\"bad cmd\"}");
  CHECK(control_error_response("quote\"inside") ==
        "{\"ok\":false,\"error\":\"quote\\\"inside\"}");
}

TEST_CASE("ControlServer serves requests over a real unix socket", "[control]") {
  const std::string path = make_socket_path();
  ControlServer server(path);
  REQUIRE(server.listen_fd() >= 0);

  int cfd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  REQUIRE(cfd >= 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path.c_str(), path.size());
  REQUIRE(::connect(cfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  // Send three requests in one write; responses come back on the same socket.
  const std::string batch =
      "{\"cmd\":\"pause\"}\n"
      "{\"cmd\":\"status\"}\n"
      "{\"cmd\":\"garbage\"\n"
      "{\"cmd\":\"inject\",\"fault\":\"reset\",\"connection\":4}\n";
  REQUIRE(::send(cfd, batch.data(), batch.size(), 0) ==
          static_cast<ssize_t>(batch.size()));

  auto requests = server.poll_requests();
  if (requests.empty()) {  // accept/read may need one more spin
    requests = server.poll_requests();
  }

  // Three valid requests in arrival order; the garbage line produced an
  // error response and no request.
  REQUIRE(requests.size() == 3);
  CHECK(requests[0].cmd == ControlCmd::Pause);
  CHECK(requests[1].cmd == ControlCmd::Status);
  CHECK(requests[2].cmd == ControlCmd::InjectReset);
  CHECK(requests[2].conn == 4);

  const std::string r1 = recv_line(cfd);
  const std::string r2 = recv_line(cfd);
  const std::string r_err = recv_line(cfd);
  const std::string r4 = recv_line(cfd);
  CHECK(r1 == "{\"ok\":true}\n");
  CHECK(r2 == "{\"ok\":true,\"status\":{}}\n");
  CHECK(r_err.find("\"ok\":false") != std::string::npos);
  CHECK(r4 == "{\"ok\":true}\n");
  ::close(cfd);
}

TEST_CASE("ControlServer unlinks its socket path on destruction", "[control]") {
  std::string observed = make_socket_path();
  {
    ControlServer server(observed);
    (void)server;
  }
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, observed.c_str(), observed.size());
  int cfd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  REQUIRE(::connect(cfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0);
  ::close(cfd);
}
