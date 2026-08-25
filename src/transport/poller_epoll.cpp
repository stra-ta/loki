// epoll poller backend (Linux). Compiles only on Linux; kqueue covers BSD/macOS.

#if defined(__linux__)

#include <sys/epoll.h>
#include <unistd.h>

#include <cerrno>
#include <memory>

#include <loki/poller.hpp>
#include <loki/types.hpp>

namespace loki {
namespace {

class EpollPoller final : public Poller {
 public:
  EpollPoller() : epfd_(::epoll_create1(EPOLL_CLOEXEC)) {}
  ~EpollPoller() override {
    if (epfd_ >= 0) ::close(epfd_);
  }

  bool add(int fd, std::uint64_t token, PollEvents ev) override { return ctl(EPOLL_CTL_ADD, fd, token, ev); }
  bool mod(int fd, std::uint64_t token, PollEvents ev) override { return ctl(EPOLL_CTL_MOD, fd, token, ev); }

  bool del(int fd) override { return ::epoll_ctl(epfd_, EPOLL_CTL_DEL, fd, nullptr) == 0; }

  int wait(int timeout_ms, std::vector<PollEvent>& out) override {
    events_.resize(events_.capacity() == 0 ? 64 : events_.size());
    int n;
    do {
      n = ::epoll_wait(epfd_, events_.data(), static_cast<int>(events_.size()),
                       timeout_ms);
    } while (n < 0 && errno == EINTR);
    if (n <= 0) return 0;
    for (int i = 0; i < n; ++i) {
      const struct epoll_event& ee = events_[i];
      PollEvent pe;
      pe.token = static_cast<std::uint64_t>(ee.data.u64);  // token round-trips raw
      if ((ee.events & static_cast<std::uint32_t>(EPOLLHUP)) != 0) pe.hup = true;
      if ((ee.events & static_cast<std::uint32_t>(EPOLLERR)) != 0) pe.err = true;
      PollEvents ready = PNone;
      if ((ee.events & static_cast<std::uint32_t>(EPOLLIN)) != 0) ready = ready | PRead;
      if ((ee.events & static_cast<std::uint32_t>(EPOLLOUT)) != 0) ready = ready | PWrite;
      pe.events = ready;
      out.push_back(pe);
    }
    return n;
  }

  const char* backend_name() const override { return "epoll"; }

 private:
  bool ctl(int op, int fd, std::uint64_t token, PollEvents ev) {
    struct epoll_event ee{};
    std::uint32_t mask = 0;
    if ((ev & PRead) != PNone) mask |= EPOLLIN;
    if ((ev & PWrite) != PNone) mask |= EPOLLOUT;
    ee.events = mask;
    ee.data.u64 = token;
    return ::epoll_ctl(epfd_, op, fd, &ee) == 0;
  }

  int epfd_ = -1;
  std::vector<struct epoll_event> events_;
};

}  // namespace

std::unique_ptr<Poller> make_poller() { return std::make_unique<EpollPoller>(); }

}  // namespace loki

#endif  // __linux__
