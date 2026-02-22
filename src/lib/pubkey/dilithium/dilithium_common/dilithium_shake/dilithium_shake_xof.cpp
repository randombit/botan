/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/dilithium_shake_xof.h>

#include <botan/internal/loadstor.h>

namespace Botan {

DilithiumShakeXOF::~DilithiumShakeXOF() = default;

//static
std::unique_ptr<Botan::XOF> DilithiumShakeXOF::createXOF(std::string_view name,
                                                         std::span<const uint8_t> seed,
                                                         uint16_t nonce) {
   auto xof = Botan::XOF::create_or_throw(name);
   xof->update(seed);
   xof->update(store_le(nonce));
   return xof;
}

}  // namespace Botan
