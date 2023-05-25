/*
* PKCS#11 Random Generator
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_randomgenerator.h>

namespace Botan::PKCS11 {

PKCS11_RNG::PKCS11_RNG(Session& session) : m_session(session) {}

void PKCS11_RNG::fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) {
   if(!input.empty()) {
      module()->C_SeedRandom(m_session.get().handle(), const_cast<uint8_t*>(input.data()), Ulong(input.size()));
   }

   if(!output.empty()) {
      module()->C_GenerateRandom(m_session.get().handle(), output.data(), Ulong(output.size()));
   }
}

}  // namespace Botan::PKCS11
