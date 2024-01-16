/**
 * Utils for HSS/LMS
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/hss_lms_utils.h>

#include <botan/internal/stl_util.h>

namespace Botan {
PseudorandomKeyGeneration::PseudorandomKeyGeneration(std::span<const uint8_t> identifier) :
      m_input_buffer(identifier.size() + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t)),
      m_q(m_input_buffer.data() + identifier.size(), sizeof(uint32_t)),
      m_i(m_input_buffer.data() + identifier.size() + sizeof(uint32_t), sizeof(uint16_t)),
      m_j(m_input_buffer.data() + identifier.size() + sizeof(uint32_t) + sizeof(uint16_t), sizeof(uint8_t))

{
   copy_mem(m_input_buffer.data(), identifier.data(), identifier.size());
}

void PseudorandomKeyGeneration::gen(std::span<uint8_t> out, HashFunction& hash, std::span<const uint8_t> seed) const {
   hash.update(m_input_buffer);
   hash.update(seed);
   hash.final(out);
}

}  // namespace Botan
