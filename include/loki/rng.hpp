#pragma once

// Deterministic PRNG. HEADER-ONLY BY CONTRACT: the draw order is part of the
// determinism contract, so the implementation is frozen here and must not be
// duplicated or modified without bumping LOKI_RNG_VERSION.
//
// Discipline:
//   - Exactly one Rng stream exists per run, seeded by the scenario seed via
//     SplitMix64 expansion into xoshiro256** state.
//   - All fault randomness draws from this stream in event processing order
//     (scheduler order by (deadline, seq), then rule index within an event).
//   - Any code change that alters the number or order of draws changes every
//     schedule produced afterwards. Record resolved values in the ledger so
//     replay never depends on this stream.

#include <cmath>
#include <cstdint>

namespace loki {

class SplitMix64 {
 public:
  explicit SplitMix64(std::uint64_t seed) : state_(seed) {}
  std::uint64_t next() {
    state_ += 0x9E3779B97F4A7C15ull;
    std::uint64_t z = state_;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  }

 private:
  std::uint64_t state_;
};

class Rng {
 public:
  static Rng from_seed(std::uint64_t seed) {
    SplitMix64 sm(seed);
    Rng r;
    for (auto& x : r.s_) x = sm.next();
    return r;
  }

  std::uint64_t next_u64() {
    const std::uint64_t result = rotl(s_[1] * 5, 7) * 9;
    const std::uint64_t t = s_[1] << 17;
    s_[2] ^= s_[0];
    s_[3] ^= s_[1];
    s_[1] ^= s_[2];
    s_[0] ^= s_[3];
    s_[2] ^= t;
    s_[3] = rotl(s_[3], 45);
    return result;
  }

  // Uniform in [0, 1).
  double next_double() { return static_cast<double>(next_u64() >> 11) * 0x1.0p-53; }

  // Unbiased value in [0, bound). Lemire's multiply-shift rejection method.
  // bound must be > 0.
  std::uint64_t next_below(std::uint64_t bound) {
    std::uint64_t x = next_u64();
    __uint128_t m = static_cast<__uint128_t>(x) * static_cast<__uint128_t>(bound);
    std::uint64_t lo = static_cast<std::uint64_t>(m);
    if (lo < bound) {  // rejection region
      const std::uint64_t threshold = (~static_cast<std::uint64_t>(0)) % bound + 1;
      while (lo < threshold) {
        x = next_u64();
        m = static_cast<__uint128_t>(x) * static_cast<__uint128_t>(bound);
        lo = static_cast<std::uint64_t>(m);
      }
    }
    return static_cast<std::uint64_t>(m >> 64);
  }

  double next_uniform(double lo, double hi) {
    return lo + (hi - lo) * next_double();
  }

  double next_normal(double mean, double stddev) {
    if (has_spare_) {
      has_spare_ = false;
      return mean + stddev * spare_;
    }
    double u1 = next_double();
    if (u1 <= 0.0) u1 = 0x1.0p-53;
    const double u2 = next_double();
    const double mag = stddev * sqrt(-2.0 * log(u1));
    spare_ = mag * sin(2.0 * 3.14159265358979323846 * u2);
    has_spare_ = true;
    return mean + mag * cos(2.0 * 3.14159265358979323846 * u2);
  }

 private:
  static std::uint64_t rotl(std::uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
  std::uint64_t s_[4]{};
  bool has_spare_ = false;
  double spare_ = 0.0;
};

}  // namespace loki
