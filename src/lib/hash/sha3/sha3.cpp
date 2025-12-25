/*
* SHA-3
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha3.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/keccak_perm.h>

namespace Botan {
namespace {

constexpr auto select_sha3_permutation(size_t output_bits) {
   switch(output_bits) {
      case 224:
         return Keccak_Permutation({.capacity_bits = 448, .padding = KeccakPadding::sha3()});
      case 256:
         return Keccak_Permutation({.capacity_bits = 512, .padding = KeccakPadding::sha3()});
      case 384:
         return Keccak_Permutation({.capacity_bits = 768, .padding = KeccakPadding::sha3()});
      case 512:
         return Keccak_Permutation({.capacity_bits = 1024, .padding = KeccakPadding::sha3()});
      default:
         throw Invalid_Argument(fmt("SHA_3: Invalid output length {}", output_bits));
   }
}

}  // namespace

SHA_3::SHA_3(size_t output_bits) : m_keccak(select_sha3_permutation(output_bits)), m_output_length(output_bits / 8) {}

std::string SHA_3::name() const {
   return fmt("SHA-3({})", m_output_length * 8);
}

std::string SHA_3::provider() const {
   return m_keccak.provider();
}

std::unique_ptr<HashFunction> SHA_3::copy_state() const {
   return std::make_unique<SHA_3>(*this);
}

std::unique_ptr<HashFunction> SHA_3::new_object() const {
   return std::make_unique<SHA_3>(m_output_length * 8);
}

void SHA_3::clear() {
   m_keccak = select_sha3_permutation(m_output_length * 8);
}

void SHA_3::add_data(std::span<const uint8_t> input) {
   m_keccak.absorb(input);
}

void SHA_3::final_result(std::span<uint8_t> output) {
   m_keccak.finish();
   m_keccak.squeeze(output);
   clear();
}

}  // namespace Botan
