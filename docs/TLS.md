# TLS-aware inspection

Loki supports opaque TLS pass-through and an optional TCP SNI match predicate.
The predicate is a narrow parser boundary, not TLS termination.

## What is inspected

The parser reads TLS handshake records at the beginning of the client-to-server byte stream.
It reassembles a ClientHello handshake message split across multiple TLS records.
It walks the cleartext ClientHello structure and extracts the first `host_name` entry in the `server_name` extension.
The inspection buffer is bounded at 16 MiB per connection.

Loki does not possess or use a certificate key for this feature.
It does not decrypt application records, inspect HTTP, or infer an inner name from encrypted ClientHello.
The `encrypted_client_hello` extension therefore behaves as no visible SNI.

## Matching example

```yaml
rules:
  - name: api-delay
    when:
      sni: api.example.test
    inject:
      latency:
        mean: 25ms
```

`when.sni` is an exact, case-sensitive match against the extracted name.
SNI matching is a data-phase rule and cannot be combined with connection-phase faults.
UDP has no ClientHello and never matches `when.sni`.

## Parser outcomes

- `Incomplete` means the bytes form a valid prefix but more record or handshake bytes are required.
- `Found` means a visible `host_name` SNI was extracted.
- `NoSni` means a complete ClientHello has no visible `server_name` host name.
- `NotTls` means the prefix is not a ClientHello or violates the bounded structural checks.

Non-TLS traffic is forwarded as ordinary TCP traffic after the parser settles on `NotTls`.
Malformed records are not decrypted or repaired, and the parser never reads beyond the supplied bytes.

The transport tests include truncated prefixes, fragmented handshakes, large extension blocks, TLS 1.3-style extensions, malformed lengths, empty names, non-TLS bytes, and encrypted-ClientHello behavior.
