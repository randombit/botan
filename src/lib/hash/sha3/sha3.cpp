/*
* SHA-3
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha3.h>

#include <botan/exceptn.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/fmt.h>
#include <botan/internal/keccak_perm.h>
#include <botan/internal/loadstor.h>

namespace Botan {

SHA_3::SHA_3(size_t output_bits) : m_keccak(2 * output_bits, 2, 2), m_output_length(output_bits / 8) {
   // We only support the parameters for SHA-3 in this constructor

   if(output_bits != 224 && output_bits != 256 && output_bits != 384 && output_bits != 512) {
      throw Invalid_Argument(fmt("SHA_3: Invalid output length {}", output_bits));
   }
}

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
   m_keccak.clear();
}

void SHA_3::add_data(std::span<const uint8_t> input) {
   m_keccak.absorb(input);
}

void SHA_3::final_result(std::span<uint8_t> output) {
   m_keccak.finish();
   m_keccak.squeeze(output);
   m_keccak.clear();
}

}  // namespace Botan
