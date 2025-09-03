/*
* Permutation Ascon_p[rounds] as specified in NIST SP.800-232, Section 3
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ascon_perm.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <botan/internal/stl_util.h>

namespace Botan {

void Ascon_p::absorb(std::span<const uint8_t> input, std::optional<uint8_t> permutation_rounds) {
   const auto rounds = permutation_rounds.value_or(m_processing_rounds);

   process(
      input,
      [](uint64_t& state_word, uint64_t input_word) { state_word ^= input_word; },
      [](uint64_t& state_word, uint64_t input_word, PartialWordBounds) { state_word ^= input_word; },
      [this, rounds] { permute(rounds); });
}

void Ascon_p::percolate_in(std::span<uint8_t> data) {
   BufferStuffer output_stuffer(data);

   process(
      data,
      [&](uint64_t& state_word, uint64_t input_word) {
         state_word ^= input_word;
         output_stuffer.append(store_le(state_word));
      },
      [&](uint64_t& state_word, uint64_t input_word, PartialWordBounds bounds) {
         state_word ^= input_word;
         const auto state_word_bytes = store_le(state_word);
         output_stuffer.append(std::span{state_word_bytes}.subspan(bounds.offset, bounds.length));
      },
      [&] { permute(m_processing_rounds); });
}

void Ascon_p::percolate_out(std::span<uint8_t> data) {
   BufferStuffer output_stuffer(data);

   process(
      data,
      [&](uint64_t& state_word, uint64_t input_word) {
         output_stuffer.append(store_le(state_word ^ input_word));
         state_word = input_word;
      },
      [&](uint64_t& state_word, uint64_t input_word, PartialWordBounds bounds) {
         const auto pt_block = store_le(state_word ^ input_word);
         output_stuffer.append(std::span{pt_block}.subspan(bounds.offset, bounds.length));
         state_word = (state_word & ~bounds.mask()) | input_word;
      },
      [&] { permute(m_processing_rounds); });
}

void Ascon_p::squeeze(std::span<uint8_t> output) {
   BufferStuffer output_stuffer(output);

   process(
      output,
      [&](uint64_t& state_word, uint64_t) { output_stuffer.append(store_le(state_word)); },
      [&](uint64_t& state_word, uint64_t, PartialWordBounds bounds) {
         const auto out_buffer = store_le(state_word);
         output_stuffer.append(std::span{out_buffer}.subspan(bounds.offset, bounds.length));
      },
      [&] { permute(m_processing_rounds); });
}

void Ascon_p::finish() {
   // NIST SP.800-232, Section 2.1 (Algorithm 2 "pad()")

   // The padding is defined as:
   //   1. The first padding bit is set to 1
   //   2. The remaining bits are set to 0
   constexpr std::array<uint8_t, state_bytes()> padding{0x01};

   // We must always add a padded final input block, if the last verbatim
   // input block aligned with the byte rate, the final block may be just
   // padding bytes, otherwise the final block is padded as needed.

   absorb(std::span{padding}.first(byte_rate() - cursor()), m_init_final_rounds);
   BOTAN_ASSERT_NOMSG(cursor() == 0);
}

void Ascon_p::intermediate_finish() {
   // NIST SP.800-232, Section 2.1 (Algorithm 2 "pad()")

   // The padding is defined as:
   //   1. The first padding bit is set to 1
   //   2. The remaining bits are set to 0
   constexpr std::array<uint8_t, state_bytes()> padding{0x01};

   // We must always add a padded final input block, if the last verbatim
   // input block aligned with the byte rate, the final block may be just
   // padding bytes, otherwise the final block is padded as needed.

   absorb(std::span{padding}.first(byte_rate() - cursor()), m_processing_rounds);
   BOTAN_ASSERT_NOMSG(cursor() == 0);
}

void Ascon_p::permute(uint8_t rounds) {
   BOTAN_DEBUG_ASSERT(rounds <= 16);

   auto& S = state();

   // NIST SP.800-232, Table 5
   constexpr std::array<uint64_t, 16> round_constants = {
      0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

   for(uint8_t i = 0; i < rounds; ++i) {
      // Constant addition layer p_C
      // NIST SP.800-232, Section 3.2
      S[2] ^= round_constants[16 - rounds + i];

      // Substitution layer p_S
      // NIST SP.800-232, Section 3.3, most notably Figure 3
      S[0] ^= S[4];
      S[4] ^= S[3];
      S[2] ^= S[1];
      auto tmp = S;
      tmp[0] = ~tmp[0] & S[1];
      tmp[1] = ~tmp[1] & S[2];
      tmp[2] = ~tmp[2] & S[3];
      tmp[3] = ~tmp[3] & S[4];
      tmp[4] = ~tmp[4] & S[0];
      S[0] ^= tmp[1];
      S[1] ^= tmp[2];
      S[2] ^= tmp[3];
      S[3] ^= tmp[4];
      S[4] ^= tmp[0];
      S[1] ^= S[0];
      S[0] ^= S[4];
      S[3] ^= S[2];
      S[2] = ~S[2];

      // Linear diffusion layer p_L
      // NIST SP.800-232, Section 3.4
      S[0] = S[0] ^ rotr<19>(S[0]) ^ rotr<28>(S[0]);
      S[1] = S[1] ^ rotr<61>(S[1]) ^ rotr<39>(S[1]);
      S[2] = S[2] ^ rotr<1>(S[2]) ^ rotr<6>(S[2]);
      S[3] = S[3] ^ rotr<10>(S[3]) ^ rotr<17>(S[3]);
      S[4] = S[4] ^ rotr<7>(S[4]) ^ rotr<41>(S[4]);
   }
}

}  // namespace Botan
