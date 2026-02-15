/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/dilithium_shake_xof.h>

namespace Botan {

DilithiumShakeXOF::DilithiumShakeXOF() :
      m_xof_256(XOF::create_or_throw("SHAKE-256")), m_xof_128(XOF::create_or_throw("SHAKE-128")) {}

DilithiumShakeXOF::~DilithiumShakeXOF() = default;

}  // namespace Botan
