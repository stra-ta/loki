// kqueue poller backend (macOS/BSD).

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <memory>

#include <loki/poller.hpp>
#include <loki/types.hpp>

namespace loki {
namespace {

class KqueuePoller final : public Poller {
 public:
  KqueuePoller() : kq_(::kqueue()) {}
  ~KqueuePoller() override {
    if (kq_ >= 0) ::close(kq_);
  }

  bool add(int fd, std::uint64_t token, PollEvents ev) override { return arm(fd, token, ev, EV_ADD); }
  // kqueue has no separate modify: re-adding with EV_ADD updates the filter set.
  bool mod(int fd, std::uint64_t token, PollEvents ev) override { return arm(fd, token, ev, EV_ADD); }

  bool del(int fd) override {
    struct kevent ke;
    EV_SET(&ke, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    const int rc1 = ::kevent(kq_, &ke, 1, nullptr, 0, nullptr);
    EV_SET(&ke, fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    const int rc2 = ::kevent(kq_, &ke, 1, nullptr, 0, nullptr);
    // A filter that was never registered reports ENOENT; that is still "gone".
    return rc1 == 0 || rc2 == 0 || errno == ENOENT;
  }

  int wait(int timeout_ms, std::vector<PollEvent>& out) override {
    struct timespec ts;
    struct timespec* tsp = nullptr;
    if (timeout_ms >= 0) {
      ts.tv_sec = timeout_ms / 1000;
      ts.tv_nsec = static_cast<long>(timeout_ms % 1000) * 1000000L;
      tsp = &ts;
    }
    events_.resize(events_.capacity() == 0 ? 64 : events_.size());
    int n;
    do {
      n = ::kevent(kq_, nullptr, 0, events_.data(), static_cast<int>(events_.size()), tsp);
    } while (n < 0 && errno == EINTR);
    if (n <= 0) return 0;
    for (int i = 0; i < n; ++i) {
      const struct kevent& ke = events_[i];
      PollEvent pe;
      pe.token = reinterpret_cast<std::uintptr_t>(ke.udata);  // token round-trips raw
      if (ke.flags & EV_ERROR) pe.err = true;
      if (ke.flags & EV_EOF) pe.hup = true;
      // We register both filters with the same ident/token; coalesce flags.
      const PollEvents fe = (ke.filter == EVFILT_READ) ? PRead : PWrite;
      if (!out.empty() && out.back().token == pe.token) {
        PollEvent& prev = out.back();
        prev.events = prev.events | fe;
        prev.hup = prev.hup || pe.hup;
        prev.err = prev.err || pe.err;
      } else {
        pe.events = fe;
        out.push_back(pe);
      }
    }
    return static_cast<int>(out.size());
  }

  const char* backend_name() const override { return "kqueue"; }

 private:
  bool arm(int fd, std::uint64_t token, PollEvents ev, std::uint16_t op) {
    struct kevent changes[2];
    int nchanges = 0;
    const std::uintptr_t udata = static_cast<std::uintptr_t>(token);
    if ((ev & PRead) != PNone) {
      EV_SET(&changes[nchanges++], fd, EVFILT_READ, op, 0, 0,
             reinterpret_cast<void*>(udata));
    } else {
      // Drop the READ filter if present; ENOENT (never registered) is fine.
      struct kevent ke;
      EV_SET(&ke, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
      ::kevent(kq_, &ke, 1, nullptr, 0, nullptr);
    }
    if ((ev & PWrite) != PNone) {
      EV_SET(&changes[nchanges++], fd, EVFILT_WRITE, op, 0, 0,
             reinterpret_cast<void*>(udata));
    } else {
      struct kevent ke;
      EV_SET(&ke, fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
      ::kevent(kq_, &ke, 1, nullptr, 0, nullptr);
    }
    if (nchanges == 0) return true;
    return ::kevent(kq_, changes, nchanges, nullptr, 0, nullptr) >= 0;
  }

  int kq_ = -1;
  std::vector<struct kevent> events_;
};

}  // namespace

std::unique_ptr<Poller> make_poller() { return std::make_unique<KqueuePoller>(); }

}  // namespace loki

#elif !defined(__linux__)
// Neither kqueue nor epoll backend covers this platform.
#error "loki: no poller backend for this platform"

#endif  // __APPLE__ || __FreeBSD__ || __OpenBSD__
