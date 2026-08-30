# Loki

<!-- CI pending: Loki has no GitHub workflow yet -->

A deterministic TCP and UDP fault-injection proxy for failures that only appear when communication goes wrong.

![Loki data path through the reactor, fault engine, scheduler, and evidence store](docs/ARCHITECTURE.svg)

A scenario and seed control latency, bandwidth, fragmentation, coalescing, reordering, duplication, corruption, silence, and connection lifecycle faults.
Every resolved decision is recorded for inspection and replay.

![Scenario, seed, run artifacts, and replay](docs/EVIDENCE.svg)

## Boundary

Loki changes application byte streams and UDP datagrams.
It does not simulate IP packets, routing, MTU behavior, congestion control, or kernel queues.

TLS-aware mode can inspect visible ClientHello SNI.
It never terminates or decrypts TLS.

The current implementation is pre-1.0 and uses one I/O thread per proxy process.

[Build, scenarios, commands, replay, and limitations](GUIDE.md).

- [TCP and system architecture](docs/ARCHITECTURE.svg)
- [UDP semantics](docs/UDP.md)
- [TLS inspection](docs/TLS.md)
- [Evidence policy](docs/BENCHMARKS.md)

## Build

See [GUIDE.md](GUIDE.md) for build presets and dependencies.

## Verification

Functional CI and performance evidence are separate. See [GUIDE.md](GUIDE.md) and `LAB_RULES.md` / `EVIDENCE.md` in `stra-ta/.github` for manifest provenance and the one-command suite (`./scripts/verify.sh` / `./scripts/confidence.sh` or `tools/verify.sh`).

## Limitations

CI is functional only. Performance evidence requires a committed manifest with machine metadata (commit, compiler, kernel, CPU, arch, build type, seed, argv) and a link from the claim to that artifact. See `stra-ta/.github` for lab-wide caveats.

