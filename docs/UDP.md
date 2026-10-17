# UDP semantics

Loki's UDP adapter is a datagram proxy.
It does not turn datagrams into one shared TCP-like byte stream.

## Mapping

The listener receives a datagram from a downstream source endpoint.
The first datagram from that endpoint creates a mapping and a connected UDP socket to the configured upstream endpoint.
Subsequent datagrams from the same source endpoint use that mapping.
Responses from the connected upstream socket are sent to the mapped downstream endpoint.

Mappings are removed by a fatal socket error or when the proxy stops.
There are no connection lifecycle events in UDP.

## Datagram boundaries

Without a shaping fault, one input datagram produces one output datagram with the same payload.
The adapter preserves zero-length datagrams and records them as data events.
The `fragment` fault may intentionally emit several datagrams from one input datagram, and the `duplicate` fault may emit copies.
These transformations are explicit scenario behavior, not claims about IP packet handling.

`stream_offset` remains a cumulative logical byte offset for the shared fault engine.
It is not a wire packet number and cannot describe UDP ordering at the network layer.

## Supported fault behavior

Delay, bandwidth, fragment, reorder, duplicate, and corrupt are the whole fault vocabulary, and all six are usable with UDP when their parameters are valid.

Reordering is across Loki output datagrams held in the configured window.
Duplication produces additional datagrams with the same transformed payload.
Corruption changes a byte in the transformed payload when the configured logical offset is covered.
None of these operations provide delivery, ordering, or congestion guarantees to the application.

## Evidence

UDP runs use the same evidence directory layout as TCP runs.
The connection record identifies the client endpoint and the event ledger records resolved fault parameters, including applied or unapplied corruption decisions.
Use `loki inspect RUN_DIR --events` to inspect decisions and `loki replay RUN_DIR --check-only` to validate the recorded ledger against a re-enacted workload.

The permanent UDP tests cover passthrough, live-engine faults, duplication, corruption, large datagrams, zero-length datagrams, and idle mapping expiry.
Stress campaigns with many client endpoints and long-lived mapping churn remain measurement work rather than CI defaults.
