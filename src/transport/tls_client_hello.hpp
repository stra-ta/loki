#pragma once
#include <string>
#include <span>
#include <cstddef>

namespace loki::tls {

enum class ClientHelloStatus { Incomplete, NotTls, Found, NoSni };

// Parse a (possibly partial) TLS ClientHello captured from the START of a
// client->server byte stream. data: bytes read so far.
// Returns:
//  Incomplete - valid TLS prefix so far but more bytes required to decide
//               (e.g. shorter than the 5-byte record header, or a declared
//               length extends beyond the bytes available)
//  NotTls     - data is definitively NOT a TLS ClientHello (give up parsing)
//  Found      - *sni_out is set to the host_name; decision complete
//  NoSni      - valid ClientHello structure but no server_name extension
ClientHelloStatus parse_client_hello_sni(std::span<const std::byte> data, std::string& sni_out);

}  // namespace loki::tls
