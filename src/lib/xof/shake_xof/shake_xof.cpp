/*
 * SHAKE-128 and SHAKE-256 as XOFs
 *
 * (C) 2016-2023 Jack Lloyd
 *     2022-2023 Fabian Albert, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/shake_xof.h>

namespace Botan {

SHAKE_XOF::SHAKE_XOF(size_t capacity) : m_keccak(capacity, 0b1111, 4), m_output_generated(false) {
   BOTAN_ASSERT_NOMSG(capacity == 256 || capacity == 512);
}

void SHAKE_XOF::reset() {
   m_keccak.clear();
   m_output_generated = false;
}

void SHAKE_XOF::add_data(std::span<const uint8_t> input) {
   BOTAN_STATE_CHECK(!m_output_generated);
   m_keccak.absorb(input);
}

void SHAKE_XOF::generate_bytes(std::span<uint8_t> output) {
   if(!m_output_generated) {
      m_output_generated = true;
      m_keccak.finish();
   }

   m_keccak.squeeze(output);
}

}  // namespace Botan
