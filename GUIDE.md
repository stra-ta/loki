# Loki

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C.svg)
![CMake 3.25+](https://img.shields.io/badge/CMake-3.25%2B-064F8C.svg)
![TCP and UDP](https://img.shields.io/badge/protocol-TCP%20%2B%20UDP-2E8B57.svg)
![Catch2 3.8.1](https://img.shields.io/badge/tests-Catch2%203.8.1-F0B323.svg)

## Claim

Loki is a deterministic hostile-network engine for testing networked systems under controlled transport failures.

It proxies TCP byte streams and UDP datagrams through a scenario-driven fault pipeline that can delay, throttle, fragment, coalesce, reorder, duplicate, corrupt, discard, or terminate traffic.

Loki records resolved fault decisions in an evidence directory so a run can be inspected and replayed.

The implementation is pre-1.0 software with a single I/O thread per proxy process.

### Transport semantics

TCP rules operate on application byte streams.
Fragmentation and reordering act on Loki's logical pieces, not IP packets.
TCP lifecycle faults such as FIN, reset, and freeze are therefore meaningful only for TCP.

UDP rules operate on datagrams and preserve datagram boundaries unless a configured byte-shaping fault intentionally emits multiple datagrams.
There is one mapping per downstream client endpoint, and mappings expire through `idle_timeout`.
UDP has no TCP half-close or connection phase, so those faults are rejected during validation.

TLS-aware TCP mode inspects the cleartext ClientHello for the `server_name` extension and exposes the result to `when.sni` rules.
This is ClientHello inspection only: Loki does not terminate TLS, decrypt records, or make claims about encrypted ClientHello names.

Loki is a stream and datagram proxy, not a packet simulator.

## Evidence

The repository's current evidence is functional and structural.
Run the test suite to exercise the live TCP and UDP paths, parser bounds, fault semantics, evidence writers, replay, and CLI behavior:

```sh
ctest --test-dir build/default --output-on-failure
```

The test suite is not a performance claim.
The previous loopback throughput snapshot was measured from an older commit with an uncommitted working tree and is retained only as historical context in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).
It must not be used as a current Loki number.

Every live run writes `manifest.json`, `scenario.yaml`, `scenario.normalized.json`, `events.jsonl`, `connections.jsonl`, `metrics.json`, and `summary.json` under `runs/<run-id>/`.
The manifest records the scenario hash, seed, software identifiers, and platform fields available to the run.

![Evidence lifecycle: scenario plus seed recorded into seven artifacts, then replayed against the same workload](docs/EVIDENCE.svg)

## Architecture

![Loki data path: reactor feeds chunks to the fault engine, scheduler releases pieces at their deadlines, evidence store records decisions](docs/ARCHITECTURE.svg)

A single-threaded reactor owns sockets, the deadline scheduler, the fault engine, evidence writers, and the Unix-domain control plane.
Each TCP direction feeds pristine bytes to the mutator.
The UDP adapter maps client endpoints to connected upstream datagram sockets and feeds each datagram through the same transport-agnostic mutator.

Rules evaluate in ascending index.
Shape faults transform pieces, timing faults stamp send deadlines, and silence or lifecycle faults queue side effects.
Pending bytes are bounded by `limits.pending_bytes_per_direction`; a full TCP direction stops reading until it drains.
The transport backend is platform-gated behind one interface: kqueue on macOS and BSD, epoll on Linux.

## Build

Requirements: CMake 3.25+, a C++20 compiler, and Make.
Catch2 v3.8.1 is fetched at configure time for tests.

```sh
./scripts/build.sh
```

Run a TCP proxy between a client and an echo or real service:

```sh
# terminal 1
python3 -m http.server 8080

# terminal 2
./build/default/src/cli/loki run scenarios/latency.yaml --seed 123
```

Run a UDP proxy with the same CLI and an explicit transport selection:

```sh
./build/default/src/cli/loki run scenarios/udp.yaml --transport udp
```

## Verification

```sh
loki validate SCENARIO.yaml                 # strict validation only
loki run SCENARIO.yaml [--seed N]           # live proxy until SIGTERM/SIGINT
    [--transport tcp|udp] [--listen ADDR] [--upstream ADDR] [--runs-dir DIR]
    [--full-ledger | --ledger-counts | --ledger-sample N]
loki replay RUN_DIR [--check-only]          # re-apply recorded decisions
loki inspect RUN_DIR [--summary | --connections | --events --tail N]
loki ctl RUN_DIR_OR_SOCK CMD [CONN]         # pause, resume, status, inject
```

Exit codes are `0` for success, `2` for usage errors, `3` for scenario validation failures, `4` for runtime failures, and `5` for replay mismatches.

### TCP scenario

```yaml
version: 1
seed: 7
listen: 127.0.0.1:17611
upstream: 127.0.0.1:17610

rules:
  - name: shred
    when:
      direction: client_to_server
    inject:
      fragment:
        min: 1
        max: 8
```

### TLS SNI matching

```yaml
version: 1
seed: 17
listen: 127.0.0.1:17711
upstream: 127.0.0.1:17710

rules:
  - name: delay-api
    when:
      direction: client_to_server
      sni: api.example.test
    inject:
      latency:
        mean: 25ms
```

`when.sni` is an exact match against a visible `host_name` entry in the client's ClientHello.
The rule is evaluated after enough initial client bytes have arrived to make a parser decision.
Non-TLS traffic, absent SNI, and encrypted ClientHello names produce no SNI match while the original bytes continue through the proxy unchanged.
See [docs/TLS.md](docs/TLS.md) for parser limits and malformed-input behavior.

### UDP scenario

Use [scenarios/udp.yaml](scenarios/udp.yaml) with `--transport udp`.
UDP mappings are keyed by the downstream source endpoint and are removed after the configured idle timeout.
See [docs/UDP.md](docs/UDP.md) for boundary, fault, and evidence semantics.

### Evidence and replay

Seed replay asks whether the same workload creates the same deterministic schedule.
Ledger replay consumes recorded decisions at recorded positions and therefore requires the workload to be enacted again.
Neither mode treats wall-clock timestamps as decision inputs.

## Limitations

Loki does not terminate TLS or inspect decrypted application bytes.
It does not emulate IP packet loss, routing, MTU behavior, congestion control, or kernel-level network queues.
UDP has no stream offsets or lifecycle half-close semantics, and one shared listener cannot freeze reads for only one UDP client.
The current process uses one I/O thread and the repository does not publish a current performance baseline.
Unix socket paths are limited to about 100 characters on macOS and 107 on Linux, so keep run roots short.

## Documentation

- [Architecture diagram](docs/ARCHITECTURE.svg) - reactor, mutator, scheduler, and evidence data path.
- [UDP semantics](docs/UDP.md) - datagram boundaries, mappings, and UDP fault behavior.
- [TLS inspection](docs/TLS.md) - ClientHello and SNI inspection without decryption.
- [Benchmark evidence policy](docs/BENCHMARKS.md) - historical measurements and current provenance requirements.
- [Roadmap](docs/ROADMAP.md) - remaining transport and protocol work.
- [Evidence lifecycle](docs/EVIDENCE.svg) - recorded decisions, artifacts, and ledger replay.

## License

[MIT](LICENSE)
