/**
 * Utils for HSS/LMS
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_HSS_LMS_UTILS_H_
#define BOTAN_HSS_LMS_UTILS_H_

#include <botan/hash.h>
#include <botan/internal/loadstor.h>

namespace Botan {

/**
 * @brief Helper class used to derive secret values based in the pseudorandom key generation
 * described in RFC 8554 Appendix A.
 *
 * This generation computes the following:
 *
 * Result = Hash( identifier || u32str(q) || u16str(i) || u8str(j) || SEED )
 *
 * This Key Generation procedure is also used for the seed derivation function of
 * SECRET_METHOD 2 defined in https://github.com/cisco/hash-sigs,
 */
class PseudorandomKeyGeneration final {
   public:
      /**
       * @brief Create a PseudorandomKeyGeneration instance for a fixed @p identifier
       */
      PseudorandomKeyGeneration(std::span<const uint8_t> identifier);

      /**
       * @brief Specify the value for the u32str(q) hash input field
       */
      void set_q(uint32_t q) { store_be(m_q, q); }

      /**
       * @brief Specify the value for the u16str(i) hash input field
       */
      void set_i(uint16_t i) { store_be(m_i, i); }

      /**
       * @brief Specify the value for the u8str(j) hash input field
       */
      void set_j(uint8_t j) { store_be(m_j, j); }

      /**
       * @brief Create a hash value using the preconfigured prefix and a @p seed
       */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T gen(HashFunction& hash, std::span<const uint8_t> seed) const {
         T output(hash.output_length());
         gen(output, hash, seed);
         return output;
      }

      /**
       * @brief Create a hash value using the preconfigured prefix and a @p seed
       */
      void gen(std::span<uint8_t> out, HashFunction& hash, std::span<const uint8_t> seed) const;

   private:
      /// Input buffer containing the prefix: 'identifier || u32str(q) || u16str(i) || u8str(j)'
      std::vector<uint8_t> m_input_buffer;

      std::span<uint8_t, sizeof(uint32_t)> m_q;
      std::span<uint8_t, sizeof(uint16_t)> m_i;
      std::span<uint8_t, sizeof(uint8_t)> m_j;
};

}  // namespace Botan

#endif
