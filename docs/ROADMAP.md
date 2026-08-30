# Next phases

Loki's current baseline is a deterministic single-threaded TCP and UDP proxy with opaque TLS pass-through and visible ClientHello SNI matching.
The following work is intentionally separated by transport boundary and evidence maturity.

## Current baseline

- TCP byte-stream faulting and evidence replay are implemented.
- UDP datagram mapping, transport-compatible faults, and idle mapping expiry are implemented.
- TLS-aware SNI inspection parses fragmented ClientHello messages without decryption.
- Functional tests are the current evidence baseline.
- No current throughput or latency headline is published; the old snapshot is historical and explicitly non-current in [BENCHMARKS.md](BENCHMARKS.md).

## Phase 1: evidence and stress coverage

1. Add deterministic scenario semantic-property tests and parser fuzz targets.
2. Add TLS ClientHello and evidence-ledger fuzz targets with bounded inputs.
3. Run UDP mapping-expiry, many-client fan-in, reorder, duplicate, and corruption campaigns on Linux and macOS.
4. Add connection-churn and concurrency matrices with complete environment metadata.
5. Profile passthrough and fault-heavy paths before changing the reactor.

Every performance artifact must include the source commit, dirty-tree state, compiler, kernel, CPU, architecture, build type, seed, command line, scenario hash, and raw evidence path.

## Phase 2: protocol-aware inspection

Protocol-aware rules belong above transport reassembly and must preserve a mapping to pristine byte offsets.
The first protocol milestone should target one explicitly supported protocol with malformed-frame behavior, partial-frame buffering, maximum frame size, and replay positions specified before implementation.

HTTP/1 metadata matching may follow those invariants.
HTTP/2 requires explicit stream semantics before any matching or rewriting is attempted.

## Phase 3: optional TLS termination

Opaque TLS pass-through and ClientHello inspection do not imply TLS termination.
Termination and re-encryption would require certificate and key configuration, handshake lifecycle rules, secret-handling rules, and an explicit fault byte domain.
No termination implementation is planned until those contracts and evidence requirements exist.

## Dependency order

```text
functional TCP and UDP baseline
          |
          +--> bounded stress and evidence campaigns
          |
          +--> protocol metadata adapters
                         |
                         +--> optional TLS termination
```
