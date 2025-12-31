/*
* Keccak
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

namespace {

constexpr auto select_keccak_hash_permutation(size_t output_bits) {
   switch(output_bits) {
      case 224:
         return Keccak_Permutation({.capacity_bits = 448, .padding = KeccakPadding::keccak1600()});
      case 256:
         return Keccak_Permutation({.capacity_bits = 512, .padding = KeccakPadding::keccak1600()});
      case 384:
         return Keccak_Permutation({.capacity_bits = 768, .padding = KeccakPadding::keccak1600()});
      case 512:
         return Keccak_Permutation({.capacity_bits = 1024, .padding = KeccakPadding::keccak1600()});
      default:
         // We only support the parameters for the SHA-3 proposal
         throw Invalid_Argument(fmt("Keccak_1600: Invalid output length {}", output_bits));
   }
}

}  // namespace

std::unique_ptr<HashFunction> Keccak_1600::copy_state() const {
   return std::make_unique<Keccak_1600>(*this);
}

Keccak_1600::Keccak_1600(size_t output_bits) :
      m_keccak(select_keccak_hash_permutation(output_bits)), m_output_length(output_bits / 8) {}

std::string Keccak_1600::name() const {
   return fmt("Keccak-1600({})", m_output_length * 8);
}

std::unique_ptr<HashFunction> Keccak_1600::new_object() const {
   return std::make_unique<Keccak_1600>(m_output_length * 8);
}

void Keccak_1600::clear() {
   m_keccak = select_keccak_hash_permutation(m_output_length * 8);
}

std::string Keccak_1600::provider() const {
   return m_keccak.provider();
}

void Keccak_1600::add_data(std::span<const uint8_t> input) {
   m_keccak.absorb(input);
}

void Keccak_1600::final_result(std::span<uint8_t> output) {
   m_keccak.finish();
   m_keccak.squeeze(output);
   clear();
}

}  // namespace Botan
