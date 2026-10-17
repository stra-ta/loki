# Loki guide

## Claim

Loki is a deterministic hostile-network engine for testing networked systems
under controlled transport failures.

It proxies TCP byte streams and UDP datagrams through a scenario-driven fault
pipeline that can delay, throttle, fragment, reorder, duplicate, or corrupt
traffic, and it records every resolved fault decision so a run can be
inspected and replayed.

The implementation is V1, pre-1.0, with a single I/O thread per proxy process.

### Transport semantics

TCP rules operate on application byte streams.
Fragmentation and reordering act on Loki's logical pieces, not IP packets.

UDP rules operate on datagrams and preserve datagram boundaries unless a
configured byte-shaping fault intentionally emits multiple datagrams.
There is one mapping per downstream client endpoint, created on the first
datagram from that endpoint and removed on a fatal socket error or at proxy
stop.

The fault vocabulary is transport-agnostic: the same six faults apply to both
transports, with datagram semantics where they differ.

Loki is a stream and datagram proxy, not a packet simulator.

## Build

```sh
./scripts/build.sh              # configure default preset, build, ctest
./scripts/build.sh release      # other presets: debug, release, asan, ubsan
./scripts/build.sh asan --no-test
```

Requirements: CMake 3.25+, a C++20 compiler, Make. Catch2 v3.8.1 is fetched at
configure time for tests.

Presets live in `CMakePresets.json`; `cmake --preset debug`, `cmake --build --preset debug`,
and `ctest --preset debug` are the direct equivalents.

## Scenarios

A scenario declares the listener, the upstream, optional limits, and a rule
list:

```yaml
version: 1
seed: 7
listen: 127.0.0.1:9000
upstream: 127.0.0.1:9001
limits:
  pending_bytes_per_direction: 1048576
  max_connections: 1024
rules:
  - name: sluggish-link
    when:
      direction: client_to_server
      every_bytes: 4096
      probability: 0.25
    inject:
      latency:
        mean: 5ms
        jitter: 2ms
```

Example scenarios live in `scenarios/`: `basic`, `fragment`, `latency`,
`reorder`, `throttle`, `composite` (composed pipeline), and `udp`.

### The six faults

| Fault | Parameters | Behavior |
| --- | --- | --- |
| `latency` | `mean`, `jitter` or `distribution: normal` + `stddev` | stamps each piece with a send deadline |
| `bandwidth` | `rate` bytes/sec, `burst` bytes | token-bucket pacing per direction, serialized so pieces leave in order |
| `fragment` | `min`, `max` | splits pieces into random sizes, order preserved |
| `reorder` | `depth >= 2`, `max_hold` | holds up to `depth` pieces and releases a Fisher-Yates permutation |
| `duplicate` | `count` | emits extra copies of every piece |
| `corrupt` | `mode: xor\|overwrite`, `offset`, `value` | rewrites one byte at an absolute pristine stream offset |

Match conditions (`when`): `direction`, `after`, `every_bytes`,
`every_events`, `connection: {every, equals}`, `probability`,
`max_occurrences`, `min_stream_offset`.

Rules evaluate in ascending index. Deterministic guards run before the
probability draw, so a rule consumes RNG only when it actually fires.

## Run, replay, inspect

```sh
loki run SCENARIO.yaml [--seed N] [--listen ADDR] [--upstream ADDR]
    [--transport tcp|udp] [--runs-dir DIR]
    [--full-ledger | --ledger-counts | --ledger-sample N]
loki validate SCENARIO.yaml
loki replay RUN_DIR [--check-only]
loki inspect RUN_DIR [--summary | --connections | --events --tail N]
```

Exit codes: 0 ok, 2 usage error, 3 scenario validation failure, 4 runtime
failure, 5 replay mismatch.

Every run writes seven artifacts under `runs/<run-id>/`: `manifest.json`,
`scenario.yaml`, `scenario.normalized.json`, `events.jsonl`,
`connections.jsonl`, `metrics.json`, `summary.json`.

Replay re-applies the recorded resolved decisions at their recorded logical
positions without drawing RNG: `replay --check-only` verifies the ledger, and
a full replay reproduces the byte stream.

## Evidence

Functional tests are the current evidence baseline: the suite covers parser
bounds, fault semantics, engine draw order, TCP and UDP end-to-end paths,
determinism, evidence writers, replay, and CLI behavior.

No current throughput or latency number is published.
The historical loopback snapshot in [docs/BENCHMARKS.md](docs/BENCHMARKS.md)
is retained with its commit, dirty-tree state, and toolchain context, and must
not be used as a current Loki number.

## Limitations

- Single I/O thread per process.
- No TLS awareness; encrypted traffic is opaque to rules.
- No connection lifecycle faults (no reset/FIN/refusal injection).
- Reordering and duplication describe Loki's logical pieces, not packets.
- Scenarios are validated against a strict YAML subset; unknown keys are
  errors.

## License

Loki is released under the [MIT License](LICENSE).
