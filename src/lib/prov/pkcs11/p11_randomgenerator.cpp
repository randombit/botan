/*
* PKCS#11 Random Generator
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_randomgenerator.h>

#include <algorithm>
#include <limits>

namespace Botan::PKCS11 {

PKCS11_RNG::PKCS11_RNG(Session& session) : m_session(session) {}

size_t PKCS11_RNG::reseed_from_sources(Entropy_Sources& /*srcs*/, size_t /*bits*/) {
   return 0;
}

void PKCS11_RNG::fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) {
   // Chunk by std::numeric_limits<Ulong>::max() so requests larger than the
   // platform's CK_ULONG (32 bits on LLP64) are not silently truncated.
   const size_t chunk_max = std::numeric_limits<Ulong>::max();

   while(!input.empty()) {
      const size_t this_chunk = std::min(input.size(), chunk_max);
      module()->C_SeedRandom(
         m_session.get().handle(), const_cast<uint8_t*>(input.data()), static_cast<Ulong>(this_chunk));
      input = input.subspan(this_chunk);
   }

   while(!output.empty()) {
      const size_t this_chunk = std::min(output.size(), chunk_max);
      module()->C_GenerateRandom(m_session.get().handle(), output.data(), static_cast<Ulong>(this_chunk));
      output = output.subspan(this_chunk);
   }
}

}  // namespace Botan::PKCS11
