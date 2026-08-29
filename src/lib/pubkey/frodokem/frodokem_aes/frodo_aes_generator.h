/*
 * FrodoKEM matrix generator based on AES
 *
 * The Fellowship of the FrodoKEM:
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_FRODOKEM_AES_GENERATOR_H_
#define BOTAN_FRODOKEM_AES_GENERATOR_H_

#include <botan/internal/aes.h>
#include <botan/internal/frodo_constants.h>
#include <botan/internal/frodo_types.h>
#include <botan/internal/loadstor.h>
#include <span>

namespace Botan {

inline auto create_aes_row_generator(const FrodoKEMConstants& constants, StrongSpan<const FrodoSeedA> seed_a) {
   BOTAN_ASSERT_NOMSG(constants.mode().is_aes());

   auto setup_aes = [](StrongSpan<const FrodoSeedA> seed) {
      AES_128 aes;
      aes.set_key(seed);
      return aes;
   };

   return [n = static_cast<uint16_t>(constants.n()), aes = setup_aes(seed_a)](
             std::span<uint8_t> out, uint16_t first_row, size_t nrows) {
      BOTAN_DEBUG_ASSERT(out.size() == nrows * (n / (AES_128::BLOCK_SIZE / 2)) * AES_128::BLOCK_SIZE);

      // Set up the to-be-encrypted 'b' values for in-place encryption:
      // each block is le16(i) || le16(j) || 0000...
      auto p = std::span{out};
      for(size_t r = 0; r != nrows; ++r) {
         const uint16_t i = static_cast<uint16_t>(first_row + r);
         for(uint16_t j = 0; j < n; j += AES_128::BLOCK_SIZE / 2) {
            constexpr uint16_t zero = 0;
            store_le(p.first<AES_128::BLOCK_SIZE>(), i, j, zero, zero, zero, zero, zero, zero);
            p = p.subspan(AES_128::BLOCK_SIZE);
         }
      }

      aes.encrypt(out);
   };
}

}  // namespace Botan

#endif
