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

#include <botan/internal/fmt.h>
#include <botan/internal/frodo_constants.h>
#include <botan/internal/frodo_types.h>
#include <botan/internal/hash_engine.h>
#include <botan/internal/loadstor.h>

#include <span>

namespace Botan {

inline auto create_shake_row_generator(const FrodoKEMConstants& constants, StrongSpan<const FrodoSeedA> seed_a) {
   BOTAN_ASSERT_NOMSG(constants.mode().is_shake());

   // Each row i of A is SHAKE-128(le16(i) || seed_a), n 16-bit values
   auto engine = std::shared_ptr<Hash_Engine>(Hash_Engine::create_or_throw(fmt("SHAKE-128({})", 16 * constants.n())));

   return
      [engine = std::move(engine), a = FrodoSeedA(seed_a)](std::span<uint8_t> out, uint16_t first_row, size_t nrows) {
         const size_t row_bytes = engine->output_length();
         BOTAN_ASSERT_NOMSG(out.size() == nrows * row_bytes);

         std::vector<uint8_t> row_ids(sizeof(uint16_t) * nrows);
         std::vector<std::span<uint8_t>> outputs(nrows);
         std::vector<std::span<const uint8_t>> ids(nrows);
         std::vector<std::span<const uint8_t>> seeds(nrows);

         for(size_t r = 0; r != nrows; ++r) {
            auto id_span = std::span(row_ids).subspan(sizeof(uint16_t) * r).first<sizeof(uint16_t)>();
            store_le(static_cast<uint16_t>(first_row + r), id_span);
            ids[r] = id_span;
            seeds[r] = a;
            outputs[r] = out.subspan(r * row_bytes, row_bytes);
         }

         engine->batch_hash(outputs, ids, seeds);
      };
}

}  // namespace Botan

#endif
