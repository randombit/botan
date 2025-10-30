/*
* SHAKE-128/256 as a hash
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/shake.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

constexpr auto shake128_permutation = Keccak_Permutation({.capacity_bits = 256, .padding = KeccakPadding::shake()});
constexpr auto shake256_permutation = Keccak_Permutation({.capacity_bits = 512, .padding = KeccakPadding::shake()});

SHAKE_128::SHAKE_128(size_t output_bits) : m_keccak(shake128_permutation), m_output_bits(output_bits) {
   if(output_bits % 8 != 0) {
      throw Invalid_Argument(fmt("SHAKE_128: Invalid output length {}", output_bits));
   }
}

std::string SHAKE_128::name() const {
   return fmt("SHAKE-128({})", m_output_bits);
}

void SHAKE_128::clear() {
   m_keccak = shake128_permutation;
}

std::unique_ptr<HashFunction> SHAKE_128::new_object() const {
   return std::make_unique<SHAKE_128>(m_output_bits);
}

std::unique_ptr<HashFunction> SHAKE_128::copy_state() const {
   return std::make_unique<SHAKE_128>(*this);
}

void SHAKE_128::add_data(std::span<const uint8_t> input) {
   m_keccak.absorb(input);
}

void SHAKE_128::final_result(std::span<uint8_t> output) {
   m_keccak.finish();
   m_keccak.squeeze(output);
   clear();
}

SHAKE_256::SHAKE_256(size_t output_bits) : m_keccak(shake256_permutation), m_output_bits(output_bits) {
   if(output_bits % 8 != 0) {
      throw Invalid_Argument(fmt("SHAKE_256: Invalid output length {}", output_bits));
   }
}

std::string SHAKE_256::name() const {
   return fmt("SHAKE-256({})", m_output_bits);
}

void SHAKE_256::clear() {
   m_keccak = shake256_permutation;
}

std::unique_ptr<HashFunction> SHAKE_256::new_object() const {
   return std::make_unique<SHAKE_256>(m_output_bits);
}

std::unique_ptr<HashFunction> SHAKE_256::copy_state() const {
   return std::make_unique<SHAKE_256>(*this);
}

void SHAKE_256::add_data(std::span<const uint8_t> input) {
   m_keccak.absorb(input);
}

void SHAKE_256::final_result(std::span<uint8_t> output) {
   m_keccak.finish();
   m_keccak.squeeze(output);
   clear();
}

}  // namespace Botan
