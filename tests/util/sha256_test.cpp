// SHA-256 known-answer tests (FIPS 180-4 vectors + machine-generated digests).
#include <catch2/catch_test_macros.hpp>

#include <string>

#include <loki/sha256.hpp>

using loki::sha256;
using loki::to_hex;

static std::string hex_of(const std::string& s) {
  return to_hex(sha256(s.data(), s.size()));
}

TEST_CASE("sha256 FIPS 180-4 known answers", "[loki_util]") {
  REQUIRE(hex_of("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  REQUIRE(hex_of("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  REQUIRE(hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST_CASE("sha256 multi-block input", "[loki_util]") {
  // 1260 bytes: 19 full blocks + 52 remainder, exercising the two-final-block
  // padding path. Digest generated with `shasum -a 256` on this machine.
  std::string data;
  for (int i = 0; i < 60; ++i) data += "loki-hostile-network-";
  data.resize(1260);
  REQUIRE(data.size() == 1260);
  REQUIRE(hex_of(data) == "96ba697c84b775b3ece5af41b144f5e12fae75db82c6f5ed2f2e2ebb9486ef45");
}

TEST_CASE("sha256 padding boundary lengths", "[loki_util]") {
  // 55/56/64/119 bytes cross the one-vs-two pad block boundary and the exact
  // block edge. Expected digests from `shasum -a 256` on this machine.
  const std::string s55(55, 'a');
  const std::string s56(56, 'b');
  const std::string s64(64, 'c');
  const std::string s119(119, 'd');
  REQUIRE(hex_of(s55) == "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
  REQUIRE(hex_of(s56) == "a5fc6e203a4c2b657d0d153885932414b2ffc6a93f0f8bf8b3183315e5a7212c");
  REQUIRE(hex_of(s64) == "52b6419d27bd7f547cee3b92f8c17a908b8a49601ecbec161e5030de1dfe9e0a");
  REQUIRE(hex_of(s119) == "d75b7766811333963504f1e81158db3d0b5070c7c0a8948bd566ed622ea67f0e");
}
