// Pure TLS ClientHello SNI parser (no cryptography).
// Parses an RFC 5246 TLSPlaintext record wrapping a Handshake ClientHello.
// Strict bounds checking: no read ever goes past `data`.

#include "tls_client_hello.hpp"

#include <cstdint>

namespace loki::tls {

namespace {

inline std::uint8_t u8(std::byte b) { return static_cast<std::uint8_t>(b); }

}  // namespace

ClientHelloStatus parse_client_hello_sni(std::span<const std::byte> data, std::string& sni_out) {
  // 1. Need at least the 5-byte record header to make any progress.
  if (data.size() < 5) return ClientHelloStatus::Incomplete;

  // 2. Content type must be handshake (0x16).
  if (u8(data[0]) != 0x16) return ClientHelloStatus::NotTls;

  // 3. Record length is the fragment size that follows the 5-byte header.
  const std::size_t record_len = (static_cast<std::size_t>(u8(data[3])) << 8) | u8(data[4]);
  // A handshake message needs at least its 4-byte header; anything less is
  // structurally invalid, not merely incomplete.
  if (record_len < 4) return ClientHelloStatus::NotTls;
  if (data.size() < 5 + record_len) return ClientHelloStatus::Incomplete;

  // 4. Handshake type must be client_hello (0x01).
  if (u8(data[5]) != 0x01) return ClientHelloStatus::NotTls;

  // 5. Handshake length (3 bytes, big-endian) covers everything after the
  //    4-byte handshake header. Need the full message available.
  const std::size_t hs_len =
      (static_cast<std::size_t>(u8(data[6])) << 16) |
      (static_cast<std::size_t>(u8(data[7])) << 8) |
      static_cast<std::size_t>(u8(data[8]));
  const std::size_t body_end = 9 + hs_len;  // exclusive end of ClientHello body
  if (data.size() < body_end) return ClientHelloStatus::Incomplete;

  // 6. Walk the ClientHello body with a cursor, bounds-checked against body_end.
  std::size_t pos = 9;

  auto need = [&](std::size_t n) -> bool { return pos + n <= body_end; };

  // client_version (2 bytes)
  if (!need(2)) return ClientHelloStatus::NotTls;
  pos += 2;

  // random (32 bytes)
  if (!need(32)) return ClientHelloStatus::NotTls;
  pos += 32;

  // session_id: 1-byte length then that many bytes
  if (!need(1)) return ClientHelloStatus::NotTls;
  {
    const std::size_t sid_len = u8(data[pos]);
    pos += 1;
    if (!need(sid_len)) return ClientHelloStatus::NotTls;
    pos += sid_len;
  }

  // cipher_suites: 2-byte length then that many bytes
  if (!need(2)) return ClientHelloStatus::NotTls;
  {
    const std::size_t cs_len = (static_cast<std::size_t>(u8(data[pos])) << 8) | u8(data[pos + 1]);
    pos += 2;
    if (!need(cs_len)) return ClientHelloStatus::NotTls;
    pos += cs_len;
  }

  // compression_methods: 1-byte length then that many bytes
  if (!need(1)) return ClientHelloStatus::NotTls;
  {
    const std::size_t cm_len = u8(data[pos]);
    pos += 1;
    if (!need(cm_len)) return ClientHelloStatus::NotTls;
    pos += cm_len;
  }

  // extensions: 2-byte length then that many bytes
  if (!need(2)) return ClientHelloStatus::NotTls;
  const std::size_t extensions_len =
      (static_cast<std::size_t>(u8(data[pos])) << 8) | u8(data[pos + 1]);
  pos += 2;
  if (!need(extensions_len)) return ClientHelloStatus::NotTls;
  const std::size_t ext_block_end = pos + extensions_len;

  // 7. Iterate extensions.
  std::size_t ext_pos = pos;
  while (ext_pos < ext_block_end) {
    if (ext_block_end - ext_pos < 4) return ClientHelloStatus::NotTls;  // type(2)+len(2)
    const std::uint16_t ext_type =
        (static_cast<std::uint16_t>(u8(data[ext_pos])) << 8) | u8(data[ext_pos + 1]);
    const std::size_t ext_len =
        (static_cast<std::size_t>(u8(data[ext_pos + 2])) << 8) | u8(data[ext_pos + 3]);
    ext_pos += 4;
    if (ext_block_end - ext_pos < ext_len) return ClientHelloStatus::NotTls;
    const std::size_t ext_data_start = ext_pos;

    if (ext_type == 0x0000) {
      // server_name extension: server_name_list is ext_data.
      const std::size_t sni_end = ext_data_start + ext_len;
      if (sni_end - ext_data_start < 2) return ClientHelloStatus::NotTls;  // list_len(2)
      const std::size_t list_len =
          (static_cast<std::size_t>(u8(data[ext_data_start])) << 8) | u8(data[ext_data_start + 1]);
      std::size_t entry_pos = ext_data_start + 2;
      if (sni_end - entry_pos < list_len) return ClientHelloStatus::NotTls;
      const std::size_t entry_end = entry_pos + list_len;

      while (entry_pos < entry_end) {
        if (entry_end - entry_pos < 3) return ClientHelloStatus::NotTls;  // type(1)+len(2)
        const std::uint8_t name_type = u8(data[entry_pos]);
        const std::size_t name_len =
            (static_cast<std::size_t>(u8(data[entry_pos + 1])) << 8) | u8(data[entry_pos + 2]);
        entry_pos += 3;
        if (entry_end - entry_pos < name_len) return ClientHelloStatus::NotTls;
        if (name_type == 0x00) {  // host_name
          sni_out.assign(reinterpret_cast<const char*>(&data[entry_pos]), name_len);
          return ClientHelloStatus::Found;
        }
        entry_pos += name_len;
      }
    }

    ext_pos = ext_data_start + ext_len;
  }

  // 8. Valid ClientHello but no server_name extension was encountered.
  return ClientHelloStatus::NoSni;
}

}  // namespace loki::tls
