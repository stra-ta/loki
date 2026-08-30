# Benchmark evidence policy

The repository does not publish a current Loki throughput or latency number.
The old loopback snapshot below is retained to explain why it cannot be used as current evidence.

## Historical snapshot

The snapshot was produced by `scripts/bench.py` on 2026-08-26.
It used commit `3b35e34` with performance changes in an uncommitted working tree.
The environment was an Apple M1 running macOS 26.5.2 with Apple Clang 21.0.0, C++20, the kqueue backend, and the default `RelWithDebInfo` configuration.
The client and Python echo server ran over loopback.

| case | configured | historical observation |
| --- | --- | --- |
| Loopback direct passthrough | 128 MiB transfer, five alternating rounds | 978 MB/s median |
| Loopback through Loki without rules | 128 MiB transfer, five alternating rounds | 398 MB/s median |
| Latency fault RTT | 50 ms +/- 20 ms per direction | 107.2 ms median, 71.5 ms to 139.6 ms across 60 samples |
| Bandwidth fault | 50 KiB/s rate, 8 KiB burst | 50 KiB/s observed |

These observations are not a release baseline.
The source commit, dirty state, harness, and implementation have changed, and the old output is not a committed raw result artifact.

## Required provenance

Any new measured artifact must record all of the following alongside raw output:

- source commit SHA and dirty-tree state;
- compiler and complete build type;
- kernel, CPU model, architecture, and relevant governor or virtualization state;
- scenario hash, seed, and exact command-line arguments;
- metric schema version and evidence class (`functional` or `performance`);
- workload dimensions, warmup policy, run count, and aggregation rule;
- paths and hashes for generated tables and raw evidence.

Functional CI proves behavior and invariants.
Performance evidence requires a separately named campaign and must not be inferred from CI timing.
Percentiles must be aggregated from raw observations rather than by averaging already aggregated percentiles.

## Running the probe

The existing probe writes nothing into the repository and requires a default-preset build:

```sh
python3 scripts/bench.py build/default/src/cli/loki
```

Treat its output as an exploratory observation until it is wrapped in a campaign manifest containing the provenance fields above.
