// Tests for the pure TLS ClientHello SNI parser.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "../src/transport/tls_client_hello.hpp"

using namespace loki::tls;

namespace {

// ---- ClientHello construction helpers (test-only) ----

// Wrap a handshake message body in a TLS handshake record.
std::vector<std::byte> build_record(std::vector<std::byte> handshake_body) {
  std::vector<std::byte> rec;
  rec.push_back(std::byte{0x16});  // content type: handshake
  rec.push_back(std::byte{0x03});  // version major (TLS 1.0 record layer)
  rec.push_back(std::byte{0x01});  // version minor
  rec.push_back(std::byte{static_cast<unsigned char>((handshake_body.size() >> 8) & 0xff)});
  rec.push_back(std::byte{static_cast<unsigned char>(handshake_body.size() & 0xff)});
  rec.insert(rec.end(), handshake_body.begin(), handshake_body.end());
  return rec;
}

std::vector<std::byte> build_record_fragment(std::span<const std::byte> fragment) {
  std::vector<std::byte> rec;
  rec.push_back(std::byte{0x16});  // content type: handshake
  rec.push_back(std::byte{0x03});  // version major
  rec.push_back(std::byte{0x03});  // version minor
  rec.push_back(std::byte{static_cast<unsigned char>((fragment.size() >> 8) & 0xff)});
  rec.push_back(std::byte{static_cast<unsigned char>(fragment.size() & 0xff)});
  rec.insert(rec.end(), fragment.begin(), fragment.end());
  return rec;
}

std::vector<std::byte> split_into_records(const std::vector<std::byte>& handshake,
                                          std::size_t fragment_size) {
  std::vector<std::byte> records;
  for (std::size_t pos = 0; pos < handshake.size();) {
    const std::size_t count = std::min(fragment_size, handshake.size() - pos);
    auto record = build_record_fragment(
        std::span<const std::byte>(handshake.data() + pos, count));
    records.insert(records.end(), record.begin(), record.end());
    pos += count;
  }
  return records;
}

// Build a full handshake message (client_hello) from a list of extensions.
std::vector<std::byte> build_client_hello_body(std::vector<std::byte> extensions) {
  // ClientHello body proper.
  std::vector<std::byte> inner;
  // client_version (0x0303 = TLS 1.2)
  inner.push_back(std::byte{0x03});
  inner.push_back(std::byte{0x03});
  // random (32 bytes, all zero)
  for (int i = 0; i < 32; ++i) inner.push_back(std::byte{0x00});
  // session_id: length 0
  inner.push_back(std::byte{0x00});
  // cipher_suites: length 2, one suite (TLS_AES_128_GCM_SHA256 = 0x1301)
  inner.push_back(std::byte{0x00});
  inner.push_back(std::byte{0x02});
  inner.push_back(std::byte{0x13});
  inner.push_back(std::byte{0x01});
  // compression_methods: length 1, null (0x00)
  inner.push_back(std::byte{0x01});
  inner.push_back(std::byte{0x00});
  // extensions: length + bytes
  inner.push_back(std::byte{static_cast<unsigned char>((extensions.size() >> 8) & 0xff)});
  inner.push_back(std::byte{static_cast<unsigned char>(extensions.size() & 0xff)});
  inner.insert(inner.end(), extensions.begin(), extensions.end());

  // Wrap in a Handshake message: type (client_hello = 0x01) + 3-byte length.
  std::vector<std::byte> body;
  body.push_back(std::byte{0x01});
  body.push_back(std::byte{static_cast<unsigned char>((inner.size() >> 16) & 0xff)});
  body.push_back(std::byte{static_cast<unsigned char>((inner.size() >> 8) & 0xff)});
  body.push_back(std::byte{static_cast<unsigned char>(inner.size() & 0xff)});
  body.insert(body.end(), inner.begin(), inner.end());
  return body;
}

// server_name (type 0x0000) extension carrying a single host_name entry.
std::vector<std::byte> sni_extension(const std::string& host) {
  std::vector<std::byte> data;
  const std::size_t list_len = 3 + host.size();  // name_type(1) + name_len(2) + host
  data.push_back(std::byte{static_cast<unsigned char>((list_len >> 8) & 0xff)});
  data.push_back(std::byte{static_cast<unsigned char>(list_len & 0xff)});
  data.push_back(std::byte{0x00});  // name_type: host_name
  data.push_back(std::byte{static_cast<unsigned char>((host.size() >> 8) & 0xff)});
  data.push_back(std::byte{static_cast<unsigned char>(host.size() & 0xff)});
  for (char c : host) data.push_back(std::byte{static_cast<unsigned char>(c)});

  std::vector<std::byte> ext;
  ext.push_back(std::byte{0x00});  // type 0x0000
  ext.push_back(std::byte{0x00});
  ext.push_back(std::byte{static_cast<unsigned char>((data.size() >> 8) & 0xff)});
  ext.push_back(std::byte{static_cast<unsigned char>(data.size() & 0xff)});
  ext.insert(ext.end(), data.begin(), data.end());
  return ext;
}

std::vector<std::byte> extension(std::uint16_t type, std::vector<std::byte> data) {
  std::vector<std::byte> ext;
  ext.push_back(std::byte{static_cast<unsigned char>((type >> 8) & 0xff)});
  ext.push_back(std::byte{static_cast<unsigned char>(type & 0xff)});
  ext.push_back(std::byte{static_cast<unsigned char>((data.size() >> 8) & 0xff)});
  ext.push_back(std::byte{static_cast<unsigned char>(data.size() & 0xff)});
  ext.insert(ext.end(), data.begin(), data.end());
  return ext;
}

// A non-server_name extension (supported_groups, type 0x000a) with one group.
std::vector<std::byte> other_extension() {
  std::vector<std::byte> data;
  data.push_back(std::byte{0x00});  // group list length
  data.push_back(std::byte{0x02});
  data.push_back(std::byte{0x00});  // group: x25519 (0x001d)
  data.push_back(std::byte{0x1d});

  std::vector<std::byte> ext;
  ext.push_back(std::byte{0x00});  // type 0x000a
  ext.push_back(std::byte{0x0a});
  ext.push_back(std::byte{static_cast<unsigned char>((data.size() >> 8) & 0xff)});
  ext.push_back(std::byte{static_cast<unsigned char>(data.size() & 0xff)});
  ext.insert(ext.end(), data.begin(), data.end());
  return ext;
}

std::vector<std::byte> chars_to_bytes(const std::string& s) {
  std::vector<std::byte> out;
  out.reserve(s.size());
  for (char c : s) out.push_back(std::byte{static_cast<unsigned char>(c)});
  return out;
}

}  // namespace

TEST_CASE("clienthello with SNI is found") {
  auto ch = build_record(build_client_hello_body(sni_extension("example.com")));
  std::string sni;
  const auto st = parse_client_hello_sni(std::span<const std::byte>(ch.data(), ch.size()), sni);
  CHECK(st == ClientHelloStatus::Found);
  CHECK(sni == "example.com");
}

TEST_CASE("clienthello without any extension is NoSni") {
  auto ch = build_record(build_client_hello_body({}));
  std::string sni;
  const auto st = parse_client_hello_sni(std::span<const std::byte>(ch.data(), ch.size()), sni);
  CHECK(st == ClientHelloStatus::NoSni);
}

TEST_CASE("clienthello with non-sni extension is NoSni") {
  auto ch = build_record(build_client_hello_body(other_extension()));
  std::string sni;
  const auto st = parse_client_hello_sni(std::span<const std::byte>(ch.data(), ch.size()), sni);
  CHECK(st == ClientHelloStatus::NoSni);
}

TEST_CASE("three byte prefix is Incomplete") {
  std::vector<std::byte> prefix{std::byte{0x16}, std::byte{0x03}, std::byte{0x01}};
  std::string sni;
  const auto st = parse_client_hello_sni(std::span<const std::byte>(prefix.data(), prefix.size()), sni);
  CHECK(st == ClientHelloStatus::Incomplete);
}

TEST_CASE("garbage http request is NotTls") {
  auto gb = chars_to_bytes("GET / HTTP/1.1\r\n");
  std::string sni;
  const auto st = parse_client_hello_sni(std::span<const std::byte>(gb.data(), gb.size()), sni);
  CHECK(st == ClientHelloStatus::NotTls);
}

TEST_CASE("handshake type not client_hello is NotTls") {
  auto ch = build_record(build_client_hello_body(sni_extension("example.com")));
  ch[5] = std::byte{0x02};  // not client_hello
  std::string sni;
  const auto st = parse_client_hello_sni(std::span<const std::byte>(ch.data(), ch.size()), sni);
  CHECK(st == ClientHelloStatus::NotTls);
}

TEST_CASE("clienthello with long ascii SNI is found exactly") {
  auto ch = build_record(build_client_hello_body(sni_extension("a.very.long.example.com")));
  std::string sni;
  const auto st = parse_client_hello_sni(std::span<const std::byte>(ch.data(), ch.size()), sni);
  CHECK(st == ClientHelloStatus::Found);
  CHECK(sni == "a.very.long.example.com");
}

TEST_CASE("clienthello split across TLS records is found") {
  const auto handshake = build_client_hello_body(sni_extension("split.example"));
  const auto ch = split_into_records(handshake, 11);
  std::string sni;
  const auto st = parse_client_hello_sni(std::span<const std::byte>(ch.data(), ch.size()), sni);
  CHECK(st == ClientHelloStatus::Found);
  CHECK(sni == "split.example");
}

TEST_CASE("every valid clienthello prefix is incomplete until complete") {
  const auto ch = build_record(build_client_hello_body(sni_extension("prefix.example")));
  for (std::size_t size = 0; size < ch.size(); ++size) {
    std::string sni;
    CHECK(parse_client_hello_sni(std::span<const std::byte>(ch.data(), size), sni) ==
          ClientHelloStatus::Incomplete);
  }
}

TEST_CASE("large clienthello split into normal-sized records is found") {
  std::vector<std::byte> extension_data(20'000, std::byte{0x5a});
  const auto handshake =
      build_client_hello_body(extension(0x1234, std::move(extension_data)));
  const auto ch = split_into_records(handshake, 8'192);
  std::string sni;
  const auto st = parse_client_hello_sni(std::span<const std::byte>(ch.data(), ch.size()), sni);
  CHECK(st == ClientHelloStatus::NoSni);
}

TEST_CASE("TLS 1.3 ClientHello extension corpus is accepted") {
  std::vector<std::byte> supported_versions{std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
  std::vector<std::byte> key_share{
      std::byte{0x00}, std::byte{0x1d},  // x25519
      std::byte{0x00}, std::byte{0x20},  // key length
  };
  key_share.insert(key_share.end(), 32, std::byte{0x42});
  auto extensions = sni_extension("tls13.example");
  auto versions = extension(0x002b, std::move(supported_versions));
  auto share = extension(0x0033, std::move(key_share));
  extensions.insert(extensions.end(), versions.begin(), versions.end());
  extensions.insert(extensions.end(), share.begin(), share.end());

  const auto handshake = build_client_hello_body(std::move(extensions));
  const auto ch = split_into_records(handshake, 37);
  std::string sni;
  const auto st = parse_client_hello_sni(std::span<const std::byte>(ch.data(), ch.size()), sni);
  CHECK(st == ClientHelloStatus::Found);
  CHECK(sni == "tls13.example");
}

TEST_CASE("malformed ClientHello vectors are rejected") {
  const auto valid = build_record(build_client_hello_body(sni_extension("valid.example")));

  auto wrong_record_type = valid;
  wrong_record_type[0] = std::byte{0x17};
  std::string sni;
  CHECK(parse_client_hello_sni(
            std::span<const std::byte>(wrong_record_type.data(), wrong_record_type.size()), sni) ==
        ClientHelloStatus::NotTls);

  auto truncated_record = valid;
  truncated_record.pop_back();
  CHECK(parse_client_hello_sni(
            std::span<const std::byte>(truncated_record.data(), truncated_record.size()), sni) ==
        ClientHelloStatus::Incomplete);

  auto wrong_handshake_type = valid;
  wrong_handshake_type[5] = std::byte{0x02};
  CHECK(parse_client_hello_sni(
            std::span<const std::byte>(wrong_handshake_type.data(), wrong_handshake_type.size()), sni) ==
        ClientHelloStatus::NotTls);

  auto oversized_handshake = valid;
  oversized_handshake[6] = std::byte{0xff};
  oversized_handshake[7] = std::byte{0xff};
  oversized_handshake[8] = std::byte{0xff};
  CHECK(parse_client_hello_sni(
            std::span<const std::byte>(oversized_handshake.data(), oversized_handshake.size()), sni) ==
        ClientHelloStatus::NotTls);

  auto oversized_session = valid;
  oversized_session[43] = std::byte{0xff};
  CHECK(parse_client_hello_sni(
            std::span<const std::byte>(oversized_session.data(), oversized_session.size()), sni) ==
        ClientHelloStatus::NotTls);

  auto odd_cipher_list = valid;
  odd_cipher_list[45] = std::byte{0x03};
  CHECK(parse_client_hello_sni(
            std::span<const std::byte>(odd_cipher_list.data(), odd_cipher_list.size()), sni) ==
        ClientHelloStatus::NotTls);

  const auto truncated_extension = build_record(build_client_hello_body(
      {std::byte{0x12}, std::byte{0x34}}));
  CHECK(parse_client_hello_sni(
            std::span<const std::byte>(truncated_extension.data(), truncated_extension.size()), sni) ==
        ClientHelloStatus::NotTls);

  const auto empty_hostname = build_record(build_client_hello_body(sni_extension("")));
  CHECK(parse_client_hello_sni(
            std::span<const std::byte>(empty_hostname.data(), empty_hostname.size()), sni) ==
        ClientHelloStatus::NotTls);
}

TEST_CASE("SNI output is cleared for no-SNI and encrypted ClientHello cases") {
  std::string sni = "stale.example";
  const auto no_sni = build_record(build_client_hello_body({}));
  CHECK(parse_client_hello_sni(std::span<const std::byte>(no_sni.data(), no_sni.size()), sni) ==
        ClientHelloStatus::NoSni);
  CHECK(sni.empty());

  const auto encrypted_hello = build_record(build_client_hello_body(
      extension(0xfe0d, std::vector<std::byte>(32, std::byte{0xa5}))));
  CHECK(parse_client_hello_sni(
            std::span<const std::byte>(encrypted_hello.data(), encrypted_hello.size()), sni) ==
        ClientHelloStatus::NoSni);
  CHECK(sni.empty());
}
