/*
* Ascon-Hash256 (NIST SP.800-232)
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ascon_hash256.h>

namespace Botan {

namespace {

// NIST SP.800-232 Appendix A (Table 12)
constexpr Ascon_p initial_state_of_ascon_hash_permutation({
   .init_and_final_rounds = 12,
   .processing_rounds = 12,
   .bit_rate = 64,
   .initial_state =
      {
         0x9b1e5494e934d681,
         0x4bc3a01e333751d2,
         0xae65396c6b34b81a,
         0x3c7fd4a4d56a4db3,
         0x1a5c464906c5976d,
      },
});

}  // namespace

Ascon_Hash256::Ascon_Hash256() : m_ascon_p(initial_state_of_ascon_hash_permutation) {}

void Ascon_Hash256::clear() {
   m_ascon_p = initial_state_of_ascon_hash_permutation;
}

std::unique_ptr<HashFunction> Ascon_Hash256::new_object() const {
   return std::make_unique<Ascon_Hash256>();
}

std::unique_ptr<HashFunction> Ascon_Hash256::copy_state() const {
   return std::make_unique<Ascon_Hash256>(*this);
}

void Ascon_Hash256::add_data(std::span<const uint8_t> input) {
   m_ascon_p.absorb(input);
}

void Ascon_Hash256::final_result(std::span<uint8_t> out) {
   m_ascon_p.finish();
   m_ascon_p.squeeze(out);
   clear();
}

}  // namespace Botan
