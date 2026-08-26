# Measured results

All numbers come from `scripts/bench.py`, run locally against a Python
threaded echo server over loopback TCP. No benchmark framework, no CI
runner: one script, three measured cases, raw output below.

## Environment

- Apple M1, macOS 26.5.2
- Loki built with Apple Clang 21.0.0, C++20, default `RelWithDebInfo` preset (no LTO), kqueue backend
- Client and echo server: CPython 3.11.8 in the same loopback process tree
- Loki base commit: `3b35e34`; performance changes were uncommitted at measurement time
- Date: 2026-08-26

## Methodology

Throughput cases echo 128 MiB after an 8 MiB warmup, sending and receiving
concurrently so neither kernel buffer stalls the other. Five alternating
direct/proxied rounds, median reported.
The client is Python in both the direct and proxied cases,
so client-side costs are identical and the direct-to-proxied ratio isolates
the proxy's overhead. Absolute MB/s is a bound of this harness, not a limit
of the engine.

Latency case sends single 4-byte pings with TCP_NODELAY through a rule that
stamps 50 ms mean, 20 ms jitter one-way latency on both directions. Nominal
RTT is therefore 100 ms, with a theoretical range of [60, 180] ms from the
uniform jitter draw alone. 60 round trips.

Throttle case pushes 256 KiB through a 50 KiB/s token bucket with 8 KiB
burst and measures wall-clock completion.

## Results

| case | configured | measured |
| --- | --- | --- |
| Loopback passthrough, direct client-server | - | 978 MB/s median (4.08 / 7.57 / 7.83 / 8.96 / 9.62 Gbit/s across rounds) |
| Loopback passthrough through Loki, no rules | - | 398 MB/s median (2.36 / 2.80 / 3.18 / 3.22 / 3.55 Gbit/s) |
| Latency fault RTT, 50 ms +/- 20 ms per direction | nominal RTT 100 ms, uniform bounds [60, 180] ms | median 107.2 ms, min 71.5 ms, max 139.6 ms (60 samples) |
| Bandwidth fault, rate 50 KiB/s burst 8 KiB | 50 KiB/s sustained | 50 KiB/s achieved |

## Reading these numbers

The passthrough gap is the cost of the deterministic single-threaded path:
every read chunk crosses the mutator and delivery machinery. If your workload
needs line-rate hostile traffic, run more Loki instances or shard connections;
V1 has a single I/O thread by specification.

Fault accuracy is the point: the throttle held its configured rate to the
reported integer precision, and the observed RTT distribution sits inside
the theoretical uniform-jitter envelope with scheduling slack.
