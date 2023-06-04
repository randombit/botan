/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpace.h>
#include <botan/hash.h>

namespace Botan {

PAKE_Cpace::PAKE_Cpace(std::string_view group_id, std::string_view hash_fn) {
}

PAKE_Cpace::~PAKE_Cpace() = default;

PasswordAuthenticatedKeyExchange::Status PAKE_Cpace::status() const {

}

std::vector<uint8_t>
PAKE_Cpace::begin(std::string_view password,
                  std::span<const uint8_t> channel_id,
                  std::span<const uint8_t> session_id,
                  std::span<const uint8_t> assoc_a,
                  std::span<const uint8_t> assoc_b) {
}

std::optional<std::vector<uint8_t>> PAKE_Cpace::step(std::span<const uint8_t> peer_message) {
}

std::vector<uint8_t> PAKE_Cpace::shared_secret() const {
}

}  // namespace Botan
