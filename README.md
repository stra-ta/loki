# Loki

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
