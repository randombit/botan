/*
* PKCS#11 Random Generator
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_randomgenerator.h>

namespace Botan {

namespace PKCS11 {

PKCS11_RNG::PKCS11_RNG(Session& session)
   : m_session(session)
   {}

void PKCS11_RNG::randomize(uint8_t output[], std::size_t length)
   {
   module()->C_GenerateRandom(m_session.get().handle(), output, Ulong(length));
   }

void PKCS11_RNG::add_entropy(const uint8_t in[], std::size_t length)
   {
   module()->C_SeedRandom(m_session.get().handle(), const_cast<uint8_t*>(in), Ulong(length));
   }

}
}

