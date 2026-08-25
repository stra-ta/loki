#pragma once

// SHA-256 (FIPS 180-4). Declaration only; implementation lives in
// src/util/sha256.cpp owned by the config-and-util package.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace loki {

std::array<std::uint8_t, 32> sha256(const void* data, std::size_t len);
std::string to_hex(const std::array<std::uint8_t, 32>& digest);

}  // namespace loki
