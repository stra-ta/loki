# Next phases

Loki's current baseline is a deterministic single-threaded TCP and UDP proxy
with a six-fault vocabulary (delay, throttle, fragment, reorder, duplicate,
corrupt), a decision ledger, and ledger replay.

## Current baseline

- TCP byte-stream faulting and evidence replay are implemented.
- UDP datagram mapping with the same transport-agnostic fault engine is implemented.
- Functional tests are the current evidence baseline.
- No current throughput or latency headline is published; the old snapshot is historical and explicitly non-current in [BENCHMARKS.md](BENCHMARKS.md).

## Phase 1: evidence and stress coverage

1. Add deterministic scenario semantic-property tests and parser fuzz targets.
2. Add evidence-ledger fuzz targets with bounded inputs.
3. Run UDP fan-in, reorder, duplicate, and corruption campaigns on Linux and macOS.
4. Add connection-churn matrices with complete environment metadata.
5. Profile passthrough and fault-heavy paths before changing the reactor.

Every performance artifact must include the source commit, dirty-tree state,
compiler, kernel, CPU, architecture, build type, seed, command line, scenario
hash, and raw evidence path.

## Phase 2: protocol-aware inspection

Protocol-aware rules belong above transport reassembly and must preserve a
mapping to pristine byte offsets.
The first protocol milestone should target one explicitly supported protocol
with malformed-frame behavior, partial-frame buffering, maximum frame size,
and replay positions specified before implementation.

## Explicitly out of scope

Loki is a stream and datagram proxy, not a packet simulator.
It does not terminate or decrypt TLS, and it does not implement connection
lifecycle injection (reset, FIN, refusal): the fault vocabulary shapes bytes
and datagrams, and the ledger replays exactly what shaped them.
