# Loki engineering guide

Loki is a deterministic hostile-network engine: a programmable TCP and UDP fault-injection proxy for testing networked systems under ugly transport behavior. One accepted TCP connection maps to one upstream connection; each direction flows through a fault pipeline that can delay, throttle, reshape, corrupt, silence, or terminate traffic according to a compiled scenario and a seed. UDP maps each downstream client endpoint to one connected upstream datagram socket and feeds each datagram through the same transport-agnostic fault engine.

Identity: a deterministic hostile-network engine for reproducing the failures that only appear when real communication goes wrong.

Status: V1. TCP and UDP proxying, single I/O thread per process, IPv4 + IPv6, byte-stream and datagram agnostic (no application protocol awareness). TLS-aware TCP mode inspects visible ClientHello SNI only; it never decrypts TLS.

## Build and verify

```sh
./scripts/build.sh              # configure default preset, build, ctest
cmake --preset asan && cmake --build --preset asan   # sanitizer builds when needed
```

Requirements: CMake 3.25+, C++20 compiler, Make. Catch2 v3.8.1 is fetched at configure time for tests.

## Non-negotiable invariants

1. Determinism contract. One RNG stream per run (xoshiro256** seeded via SplitMix64 from the scenario seed). Draws happen only inside the mutator, in rule-index order within an event, and in each parameter's documented order. The scheduler orders events by (deadline_us, seq) with monotonically assigned sequence numbers. Poller batches are processed sorted by (conn ordinal, fd kind). Wall-clock timestamps are recorded but never affect decisions.
2. Offset invariant. `stream_offset` always refers to the pristine logical byte stream of a direction, before any mutation. Matching sees pristine positions; transforms apply downstream of the decision point.
3. Composition order. Per chunk: rules evaluate in ascending index. Shape faults (corrupt, duplicate, fragment, coalesce, reorder) transform the current piece list. Timing faults (latency, bandwidth) stamp send deadlines; later stamps win (traffic never accelerates). Silence/lifecycle faults queue side effects immediately.
4. Bounded memory. Every direction's pending queue is bounded by limits.pending_bytes_per_direction. When full, the reactor disables reading the source socket until drained. No unbounded buffering anywhere.
5. Ledger carries resolved parameters. Every decision records its sampled/resolved numeric outcomes (delay_us actually applied, fragment sizes drawn, permutation chosen). Replay never re-draws randomness.
6. Strict config. Unknown keys are errors everywhere. The runtime never interprets scenario strings; it consumes CompiledScenario only. Canonical normalized JSON is integer-only with recursively sorted keys and is SHA-256 hashed.
7. Platform gating. kqueue backend on Apple/BSD, epoll on Linux, behind include/loki/poller.hpp. Core logic builds everywhere; transport backends are the only platform-gated files.
8. Transport boundaries. TCP faults operate on byte-stream pieces. UDP faults operate on datagrams; TCP lifecycle faults and UDP freeze are rejected by transport validation. Loki never claims to inject IP packet loss.
9. TLS boundary. TLS-aware mode parses only the visible ClientHello record and handshake fields needed for `server_name`. It does not terminate TLS, decrypt records, or recover names hidden by encrypted ClientHello.
10. Dependency policy. Catch2 is the only external dependency. Everything else is implemented here.
11. Exit codes: 0 ok, 2 usage error, 3 scenario validation failure, 4 runtime failure, 5 replay mismatch.
12. Evidence completeness. Every run produces manifest.json, scenario.yaml, scenario.normalized.json, events.jsonl, connections.jsonl, metrics.json, summary.json under runs/<run-id>/. Manual control-socket injections are logged into the ledger like rule firings.

## Naming honesty

Loki operates on application byte streams, not packets. Use "discard" / "freeze" / "blackhole", never "packet loss". Reordering happens between proxied chunks, not network packets. Keep this distinction in docs and comments.

## Scenario schema V1

```yaml
version: 1                       # required
seed: <uint>                     # required
listen: <endpoint>               # required; "host:port", "[v6]:port", ":port" = loopback
upstream: <endpoint>             # required
limits:                          # optional
  pending_bytes_per_direction: <uint>   # default 1048576
  max_connections: <uint>               # default 1024
rules:                           # optional list
  - name: <str>                  # optional, default "rule-N" (N = 1-based index)
    when:                        # optional; all keys optional
      direction: a_to_b|b_to_a|client_to_server|server_to_client
      after: <dur>
      every_bytes: <uint>
      every_events: <uint>
      connection:
        every: <uint>
        equals: <uint>           # default 0
      probability: <float>       # 0..1
      max_occurrences: <uint>
      min_stream_offset: <uint>
    sni: <str>              # TLS-aware TCP only: exact match against visible SNI
                              # extracted from the connection's ClientHello.
                              # Empty = any. Only observable in the data phase;
                              # cannot be combined with connection-phase faults
                              # (connect_delay, refuse, accept_stall), which are
                              # rejected at compile time. UDP has no ClientHello.
    ledger: full|counts|sample:N # optional, default full
    inject:                      # required; EXACTLY ONE key from below
      latency: {mean: <dur>, jitter: <dur>?}          # uniform +/- jitter
      latency: {mean: <dur>, distribution: normal, stddev: <dur>}
      bandwidth: {rate: <uint bytes/sec>, burst: <uint bytes>}
      fragment: {min: <uint>, max: <uint>}            # 1 <= min <= max
      coalesce: {size: <uint>, max_delay: <dur>}
      reorder: {depth: <uint >= 2>, max_hold: <dur>}
      duplicate: {count: <uint>}                      # default 1
      corrupt: {mode: xor|overwrite, offset: <uint>, value: <0..255>}
      blackhole: {direction: <dir>, mode: discard|freeze, duration: <dur>?}  # duration 0/absent = rest of run
      reset: {after: <dur>?}
      fin: {side: client|server}                      # sugar for half_close tx
      half_close: {side: client|server, mode: tx|rx}
      connect_delay: {delay: <dur>}
      refuse: {after: <dur>?}
      accept_stall: {stall: <dur>}
      idle_timeout: {idle: <dur>, action: reset|fin}
```

Duration syntax: `<number><unit>`, unit required, one of us|ms|s|m|h. Fractional allowed ("1.5s").

Direction aliases: client_to_server/c2s == a_to_b, server_to_client/s2c == b_to_a.

Match semantics:
- every_bytes fires once each time a direction's pristine byte count crosses a new multiple of N.
- every_events fires once per new multiple of chunk-read events crossed.
- probability draws AFTER deterministic guards pass (order matters for draw counts).
- max_occurrences caps total firings per rule across the run.

Fault semantics highlights:
- blackhole discard: chunks are consumed and dropped (TCP still ACKs into Loki). freeze: Loki stops reading the source leg so kernel buffers fill and sender-side backpressure stalls naturally. Both are stream-level, not packet-level.
- reorder holds up to depth pieces; releases permuted (Fisher-Yates over held pieces, seeded) when the window fills OR max_hold expires since the first hold. Bytes are preserved exactly once.
- coalesce accumulates until size reached or max_delay since first held byte expires; then emits one piece.
- corrupt targets an absolute pristine stream offset; if no current piece covers it, the decision is recorded with applied=false.
- reset closes both legs with RST (SO_LINGER 0 trick) after the optional delay.
- fin/half_close tx shuts down the write side of the named leg (that peer sees EOF); rx shuts down the read side of that leg.

## YAML subset accepted by the parser

Block style only: nested mappings via 2-space indentation, sequences with "- ", plain scalars plus single/double quoted strings, integers, floats, booleans, comments (#), blank lines. REJECTED with errors: tabs for indentation, flow style {} [], anchors & aliases *, block scalars | >, duplicate keys, documents beyond the first. Unknown keys anywhere are hard errors.

## Repository layout and package boundaries

```text
include/loki/    frozen contracts (types, rng, json, scenario, scheduler, poller,
                 engine, evidence, replay, control, reactor)
src/util/        sha256                               [config-and-util]
src/config/      YAML parser, validator, compiler     [config-and-util]
src/transport/   poller backends, socket utils, endpoint resolution [transport-core]
src/scheduler/   deadline heap                        [transport-core]
src/reactor/     event loop, registry, backpressure   [transport-core]
src/faults/      live fault engine                    [fault-engine]
src/evidence/    run store, writers                   [evidence-replay-control]
src/replay/      ledger loader, LedgerEngine          [evidence-replay-control]
src/control/     UDS control server                   [evidence-replay-control]
src/cli/         loki binary verbs                    [integration lead]
tests/<area>/    per-area Catch2 binaries, area dirs are ownership-isolated
scenarios/       example scenarios
```

include/loki is FROZEN during parallel construction: fix contract mistakes through the integration lead, never edit contracts unilaterally.

## Glossary

- leg: one of the two sockets of a proxied connection (Down faces client, Up faces server)
- logical offset: pristine byte position in a direction's stream before mutation
- piece: a transformed span of bytes with a send deadline, produced by the mutator
- discard vs freeze: consume-and-drop vs stop-reading backpressure silencing
- seed replay: same seed, same PRNG schedule given same observed order
- ledger replay: mechanically re-applied resolved decisions at recorded positions

Platform note: the control socket lives at <runs_root>/<run-id>/control.sock. Unix socket paths are limited to about 100 characters on macOS and 107 on Linux, so keep runs_root short.

## Lab-wide contracts

- See https://github.com/stra-ta/.github/blob/main/LAB_RULES.md and https://github.com/stra-ta/.github/blob/main/EVIDENCE.md and https://github.com/stra-ta/.github/blob/main/COMPATIBILITY.md for lab-wide naming, evidence, and schema contracts.
- Per https://github.com/stra-ta/.github/blob/main/CONTRIBUTING.md, contributions require the target repo's AGENTS.md, README, and relevant design note, preserve repo boundaries, add the narrowest regression test, run one-command verification, and keep performance claims tied to committed manifests.
