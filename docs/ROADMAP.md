# Next phases

This note records the order for work after the V1 TCP byte-stream engine.
The current performance phase is intentionally first because the reactor and
delivery seam will be shared by every later transport.

## Phase 1: performance

Scope: the existing single-threaded TCP path, with the frozen byte-stream
engine contract and evidence format unchanged.

1. Measure the optimized `RelWithDebInfo` baseline with `scripts/bench.py`.
2. Attribute CPU time, allocations, syscalls, scheduler work, and evidence
   writes across passthrough, immediate faults, delayed faults, and full-ledger
   runs.
3. Optimize the confirmed hot path only. The first direct-delivery fast path
   is now in `src/reactor/reactor.cpp::enqueue_piece`.
4. Preserve chunk boundaries, scheduler sequence order, memory accounting,
   replay output, and fault composition.

The first production candidate is direct delivery of an immediately due piece
into an empty output direction.
If the socket accepts the whole payload, the reactor can avoid materializing an
`OutBlob`.
Partial writes and `EAGAIN` still fall back to the existing FIFO queue.

The `include/loki` contracts remain frozen during this phase.

## Phase 2: UDP transport

UDP should add a datagram-specific transport adapter rather than forcing
datagrams through TCP stream offsets or FIN/RST lifecycle actions.

The transport boundary needs explicit datagram identity, source/destination
metadata, truncation behavior, and queue accounting.
Byte faults can remain reusable where their semantics make sense, but stream
faults such as `half_close`, `fin`, and `connect_delay` need datagram-specific
definitions or must be rejected by validation.

The first UDP milestone should be an opaque datagram proxy with loss,
duplication, delay, reorder, corruption, and rate limiting.
Protocol-aware UDP rules should come later.

## Phase 3: TLS support

TLS has two distinct products and must not be conflated:

- opaque TLS pass-through, which already works as ordinary TCP traffic;
- TLS termination and re-encryption, which enables inspection of decrypted
  application bytes and requires certificate/key configuration, handshake
  lifecycle, and secret-handling rules.

The termination design should sit behind a delivery adapter after the TCP
performance seam is stable.
The fault engine must receive a clear byte-domain contract: ciphertext bytes,
plaintext bytes, or both.
Evidence must never record private key material or plaintext by default.

## Phase 4: protocol-aware faulting

Protocol-aware rules belong above transport reassembly and, when enabled, above
TLS decryption.

The parser should be an optional adapter that turns a byte stream into frames
or messages while preserving a mapping back to pristine byte offsets.
Existing byte-level faults remain the lowest layer.
Protocol rules should be able to match metadata without changing the ordering
and replay guarantees of the byte engine.

The first protocol milestone should target one explicitly supported protocol,
with malformed-frame behavior, partial-frame buffering, maximum frame size,
and replay positions specified before implementation.

## Dependency order

```text
optimized TCP delivery seam
          |
          +--> UDP datagram adapter
          |
          +--> TLS termination adapter
                         |
                         +--> protocol parser and message-level rules
```

UDP and TLS should share transport-adapter vocabulary, but neither should
generalize `StreamStats`, `OutPiece`, or `ActDeliver` speculatively before its
real semantics are known.
