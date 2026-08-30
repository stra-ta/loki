#pragma once
#include <cstddef>
#include <span>
#include <string>

namespace loki::tls {

enum class ClientHelloStatus { Incomplete, NotTls, Found, NoSni };

// A ClientHello can span multiple TLS records and can be much larger than a
// normal application read.  Keep the inspection buffer bounded while leaving
// room for large extension lists and TLS 1.3 key shares.
inline constexpr std::size_t kMaxClientHelloBytes = 16U * 1024U * 1024U;

// Parse a (possibly partial) TLS ClientHello captured from the start of a
// client->server byte stream. `data` may contain several TLS records because
// TLS permits one handshake message to be fragmented across records.
// Returns:
//  Incomplete - a valid TLS prefix needs more bytes before it can be decided
//  NotTls     - data is definitively not a ClientHello, or is malformed
//  Found      - `sni_out` contains the visible host_name SNI
//  NoSni      - valid ClientHello structure but no server_name extension
//
// This function only inspects public record and handshake fields. It does not
// decrypt TLS and cannot recover an inner name hidden by encrypted ClientHello.
ClientHelloStatus parse_client_hello_sni(std::span<const std::byte> data, std::string& sni_out);

}  // namespace loki::tls
