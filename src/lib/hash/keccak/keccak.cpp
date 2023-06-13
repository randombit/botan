/*
* Keccak
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/sha3.h>

namespace Botan {

std::unique_ptr<HashFunction> Keccak_1600::copy_state() const {
   return std::make_unique<Keccak_1600>(*this);
}

Keccak_1600::Keccak_1600(size_t output_bits) : m_keccak(output_bits, 2 * output_bits, 0, 0) {
   // We only support the parameters for the SHA-3 proposal

   if(output_bits != 224 && output_bits != 256 && output_bits != 384 && output_bits != 512) {
      throw Invalid_Argument(fmt("Keccak_1600: Invalid output length {}", output_bits));
   }
}

std::string Keccak_1600::name() const {
   return fmt("Keccak-1600({})", m_keccak.output_bits());
}

std::unique_ptr<HashFunction> Keccak_1600::new_object() const {
   return std::make_unique<Keccak_1600>(m_keccak.output_bits());
}

void Keccak_1600::clear() {
   m_keccak.clear();
}

void Keccak_1600::add_data(const uint8_t input[], size_t length) {
   m_keccak.absorb(std::span(input, length));
}

void Keccak_1600::final_result(uint8_t output[]) {
   m_keccak.finish(std::span(output, m_keccak.output_length()));
}

}  // namespace Botan
