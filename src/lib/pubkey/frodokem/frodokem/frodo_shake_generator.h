/*
 * FrodoKEM matrix generator based on SHAKE
 *
 * The Fellowship of the FrodoKEM:
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_FRODOKEM_SHAKE_GENERATOR_H_
#define BOTAN_FRODOKEM_SHAKE_GENERATOR_H_

#include <botan/internal/frodo_constants.h>
#include <botan/internal/frodo_types.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/shake_xof.h>

#include <span>

namespace Botan {

inline auto create_shake_row_generator(const FrodoKEMConstants& constants, StrongSpan<const FrodoSeedA> seed_a) {
   BOTAN_ASSERT_NOMSG(constants.mode().is_shake());

   return [xof = SHAKE_128_XOF(), a = FrodoSeedA(seed_a)](std::span<uint8_t> out, uint16_t i) mutable {
      xof.clear();
      xof.update(store_le(i));
      xof.update(a);
      xof.output(out);
   };
}

}  // namespace Botan

#endif
