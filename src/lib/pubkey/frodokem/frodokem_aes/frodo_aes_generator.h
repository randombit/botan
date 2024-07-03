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
#include <botan/internal/stl_util.h>

#include <functional>
#include <span>

namespace Botan {

inline auto create_aes_row_generator(const FrodoKEMConstants& constants, StrongSpan<const FrodoSeedA> seed_a) {
   BOTAN_ASSERT_NOMSG(constants.mode().is_aes());

   auto setup_aes = [](StrongSpan<const FrodoSeedA> seed) {
      AES_128 aes;
      aes.set_key(seed);
      return aes;
   };

   return [n = static_cast<uint16_t>(constants.n()), aes = setup_aes(seed_a)](std::span<uint8_t> out, uint16_t i) {
      BufferStuffer out_bs(out);

      BOTAN_DEBUG_ASSERT(out_bs.remaining_capacity() % AES_128::BLOCK_SIZE == 0);

      for(uint16_t j = 0; j < n; j += AES_128::BLOCK_SIZE / 2) {
         // set up the to-be-encrypted 'b' value in the out variable
         // for in-place encryption of the block cipher
         // b = i || j || 0000...
         out_bs.append(store_le(i, j));
         clear_mem(out_bs.next<AES_128::BLOCK_SIZE - sizeof(i) - sizeof(j)>());
      }

      BOTAN_DEBUG_ASSERT(out_bs.full());

      aes.encrypt(out);
   };
}

}  // namespace Botan

#endif
