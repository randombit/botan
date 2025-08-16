/*
* Ascon-Hash256 (NIST SP.800-232)
* (C) 2025 Jack Lloyd
*.    2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/assert.h>
#include <botan/internal/ascon_hash256.h>

namespace Botan {

Ascon_Hash256::Ascon_Hash256() {
   init();
}

std::unique_ptr<HashFunction> Ascon_Hash256::new_object() const {
   return std::make_unique<Ascon_Hash256>();
}

std::unique_ptr<HashFunction> Ascon_Hash256::copy_state() const {
   return std::make_unique<Ascon_Hash256>(*this);
}

void Ascon_Hash256::init() {
   // See NIST SP.800-232, Section 5.1.1 (Initialization)
   m_ascon_p.clear();
   m_ascon_p.permute<12>();
}

std::string Ascon_Hash256::provider() const {
   return m_ascon_p.provider();
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
