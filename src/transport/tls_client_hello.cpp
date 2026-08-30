// Pure TLS ClientHello SNI parser (no cryptography).
//
// The parser only reads the TLS record and handshake framing plus the
// cleartext server_name extension. A ClientHello may be split across several
// TLS records, so the record loop reassembles the first handshake message
// before inspecting its fields.

#include "tls_client_hello.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <vector>

namespace loki::tls {

namespace {

inline std::uint8_t u8(std::byte b) {
  return static_cast<std::uint8_t>(b);
}

ClientHelloStatus parse_client_hello_body(std::span<const std::byte> body,
                                          std::string& sni_out) {
  std::size_t pos = 0;
  const auto remaining = [&](std::size_t count) {
    return pos <= body.size() && count <= body.size() - pos;
  };
  const auto read_u8 = [&](std::uint8_t& value) {
    if (!remaining(1)) return false;
    value = u8(body[pos++]);
    return true;
  };
  const auto read_u16 = [&](std::uint16_t& value) {
    if (!remaining(2)) return false;
    value = static_cast<std::uint16_t>(u8(body[pos]) << 8U) |
            static_cast<std::uint16_t>(u8(body[pos + 1]));
    pos += 2;
    return true;
  };

  // ClientHello.fixed fields.
  std::uint16_t client_version = 0;
  if (!read_u16(client_version) || !remaining(32)) return ClientHelloStatus::NotTls;
  pos += 32;  // random

  std::uint8_t session_id_len = 0;
  if (!read_u8(session_id_len) || session_id_len > 32 ||
      !remaining(session_id_len)) {
    return ClientHelloStatus::NotTls;
  }
  pos += session_id_len;

  std::uint16_t cipher_suites_len = 0;
  if (!read_u16(cipher_suites_len) || cipher_suites_len < 2 ||
      (cipher_suites_len % 2U) != 0U || !remaining(cipher_suites_len)) {
    return ClientHelloStatus::NotTls;
  }
  pos += cipher_suites_len;

  std::uint8_t compression_methods_len = 0;
  if (!read_u8(compression_methods_len) || compression_methods_len == 0 ||
      !remaining(compression_methods_len)) {
    return ClientHelloStatus::NotTls;
  }
  pos += compression_methods_len;

  std::uint16_t extensions_len = 0;
  if (!read_u16(extensions_len) || !remaining(extensions_len) ||
      extensions_len != body.size() - pos) {
    return ClientHelloStatus::NotTls;
  }
  const std::size_t extensions_end = pos + extensions_len;

  while (pos < extensions_end) {
    if (extensions_end - pos < 4) return ClientHelloStatus::NotTls;
    const std::uint16_t extension_type =
        static_cast<std::uint16_t>(u8(body[pos]) << 8U) |
        static_cast<std::uint16_t>(u8(body[pos + 1]));
    const std::size_t extension_len =
        (static_cast<std::size_t>(u8(body[pos + 2])) << 8U) |
        static_cast<std::size_t>(u8(body[pos + 3]));
    pos += 4;
    if (extension_len > extensions_end - pos) return ClientHelloStatus::NotTls;
    const std::size_t extension_data_start = pos;
    const std::size_t extension_data_end = pos + extension_len;

    if (extension_type == 0x0000U) {
      // server_name extension: a two-byte list length followed by entries.
      if (extension_len < 2) return ClientHelloStatus::NotTls;
      const std::size_t list_len =
          (static_cast<std::size_t>(u8(body[pos])) << 8U) |
          static_cast<std::size_t>(u8(body[pos + 1]));
      pos += 2;
      if (list_len != extension_data_end - pos) return ClientHelloStatus::NotTls;
      const std::size_t list_end = pos + list_len;
      while (pos < list_end) {
        if (list_end - pos < 3) return ClientHelloStatus::NotTls;
        const std::uint8_t name_type = u8(body[pos]);
        const std::size_t name_len =
            (static_cast<std::size_t>(u8(body[pos + 1])) << 8U) |
            static_cast<std::size_t>(u8(body[pos + 2]));
        pos += 3;
        if (name_len > list_end - pos) return ClientHelloStatus::NotTls;
        if (name_type == 0x00U) {
          if (name_len == 0) return ClientHelloStatus::NotTls;
          sni_out.assign(reinterpret_cast<const char*>(body.data() + pos), name_len);
          return ClientHelloStatus::Found;
        }
        pos += name_len;
      }
      if (pos != list_end) return ClientHelloStatus::NotTls;
    }

    // Skip this extension. For the server_name branch pos may point inside
    // the extension list after walking entries, so always restore the exact
    // extension boundary before examining the next one.
    pos = extension_data_start + extension_len;
  }
  return ClientHelloStatus::NoSni;
}

}  // namespace

ClientHelloStatus parse_client_hello_sni(std::span<const std::byte> data,
                                         std::string& sni_out) {
  sni_out.clear();
  if (data.size() < 5) return ClientHelloStatus::Incomplete;

  std::vector<std::byte> handshake;
  handshake.reserve(std::min<std::size_t>(data.size(), 4096));
  std::size_t pos = 0;
  std::size_t expected_handshake_size = 0;

  while (pos < data.size()) {
    if (data.size() - pos < 5) return ClientHelloStatus::Incomplete;

    // ClientHello is carried by one or more TLS handshake records. Loki does
    // not attempt to parse application records or decrypt encrypted records.
    if (u8(data[pos]) != 0x16U) return ClientHelloStatus::NotTls;
    const std::size_t record_length =
        (static_cast<std::size_t>(u8(data[pos + 3])) << 8U) |
        static_cast<std::size_t>(u8(data[pos + 4]));
    pos += 5;
    if (record_length > data.size() - pos) return ClientHelloStatus::Incomplete;

    if (record_length > kMaxClientHelloBytes -
                             std::min(handshake.size(), kMaxClientHelloBytes)) {
      return ClientHelloStatus::NotTls;
    }
    handshake.insert(handshake.end(), data.begin() + static_cast<std::ptrdiff_t>(pos),
                     data.begin() + static_cast<std::ptrdiff_t>(pos + record_length));
    pos += record_length;

    if (expected_handshake_size == 0 && handshake.size() >= 4) {
      if (u8(handshake[0]) != 0x01U) return ClientHelloStatus::NotTls;
      const std::size_t body_length =
          (static_cast<std::size_t>(u8(handshake[1])) << 16U) |
          (static_cast<std::size_t>(u8(handshake[2])) << 8U) |
          static_cast<std::size_t>(u8(handshake[3]));
      if (body_length > kMaxClientHelloBytes - 4U) return ClientHelloStatus::NotTls;
      expected_handshake_size = 4U + body_length;
    }

    if (expected_handshake_size != 0 &&
        handshake.size() >= expected_handshake_size) {
      return parse_client_hello_body(
          std::span<const std::byte>(handshake.data() + 4,
                                     expected_handshake_size - 4),
          sni_out);
    }
  }

  return ClientHelloStatus::Incomplete;
}

}  // namespace loki::tls
