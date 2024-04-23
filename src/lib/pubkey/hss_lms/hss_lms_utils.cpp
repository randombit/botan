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

// The magic numbers in the initializer list below reflect the structure of the
// m_input_buffer member and must be updated if any of the pre-defined
// std::span<>s are changed.
PseudorandomKeyGeneration::PseudorandomKeyGeneration(std::span<const uint8_t> identifier) :
      m_input_buffer(identifier.size() + 7),
      m_q(std::span(m_input_buffer).last<7>().first<4>()),
      m_i(std::span(m_input_buffer).last<3>().first<2>()),
      m_j(std::span(m_input_buffer).last<1>()) {
   copy_mem(std::span(m_input_buffer).first(identifier.size()), identifier);
}

void PseudorandomKeyGeneration::gen(std::span<uint8_t> out, HashFunction& hash, std::span<const uint8_t> seed) const {
   hash.update(m_input_buffer);
   hash.update(seed);
   hash.final(out);
}

}  // namespace Botan
