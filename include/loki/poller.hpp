#pragma once

// Readiness poller interface. Implementations: kqueue (macOS/BSD) and epoll
// (Linux), selected by make_poller() at compile time. Exactly one poller
// instance exists per reactor thread.

#include <cstdint>
#include <memory>
#include <vector>

namespace loki {

enum PollEvents : std::uint8_t {
  PNone = 0,
  PRead = 1,
  PWrite = 2,
};

inline PollEvents operator|(PollEvents a, PollEvents b) {
  return static_cast<PollEvents>(static_cast<std::uint8_t>(a) | static_cast<std::uint8_t>(b));
}
inline PollEvents operator&(PollEvents a, PollEvents b) {
  return static_cast<PollEvents>(static_cast<std::uint8_t>(a) & static_cast<std::uint8_t>(b));
}

struct PollEvent {
  std::uint64_t token = 0;
  PollEvents events = PNone;
  bool hup = false;   // peer hangup observed
  bool err = false;   // error condition on fd
};

class Poller {
 public:
  virtual ~Poller() = default;

  virtual bool add(int fd, std::uint64_t token, PollEvents ev) = 0;
  virtual bool mod(int fd, std::uint64_t token, PollEvents ev) = 0;
  virtual bool del(int fd) = 0;

  // Blocks up to timeout_ms (-1 blocks forever). Appends ready events.
  // Returns number appended (0 on timeout/spurious wake).
  virtual int wait(int timeout_ms, std::vector<PollEvent>& out) = 0;

  virtual const char* backend_name() const = 0;
};

std::unique_ptr<Poller> make_poller();

}  // namespace loki
