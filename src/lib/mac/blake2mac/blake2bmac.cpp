/*
* BLAKE2b MAC
* (C) 1999-2007,2014 Jack Lloyd
* (C) 2020           Tom Crowley
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/blake2bmac.h>

#include <botan/exceptn.h>

namespace Botan {

void BLAKE2bMAC::start_msg(std::span<const uint8_t> nonce) {
   if(!nonce.empty()) {
      throw Invalid_IV_Length(name(), nonce.size());
   }
   assert_key_material_set();
   m_blake.state_init();
}

/*
* Clear memory of sensitive data
*/
void BLAKE2bMAC::clear() {
   m_blake.clear();
}

/*
* Return a new_object of this object
*/
std::unique_ptr<MessageAuthenticationCode> BLAKE2bMAC::new_object() const {
   return std::make_unique<BLAKE2bMAC>(m_blake.output_length() * 8);
}

/*
* BLAKE2bMAC Constructor
*/
BLAKE2bMAC::BLAKE2bMAC(size_t output_bits) : m_blake(output_bits) {}

}  // namespace Botan
