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

namespace {

template <std::invocable<uint64_t&, uint64_t> StateModifierFnT,
          std::invocable<uint64_t&, uint64_t, size_t, size_t> PartialStateModifierFnT,
          std::invocable PermutationRoundFnT>
void process(uint8_t& inpos,
             size_t byte_rate,
             AsconState& S,
             std::span<const uint8_t> input,
             StateModifierFnT state_modifier_fn,
             PartialStateModifierFnT partial_state_modifier_fn,
             PermutationRoundFnT permutation_round_fn) {
   BufferSlicer input_slicer(input);

   constexpr uint8_t word_width = 8;

   // Block-wise incorporation of the input data into the sponge state until
   // all input bytes are processed
   while(!input_slicer.empty()) {
      const size_t to_take_this_round = std::min(input_slicer.remaining(), byte_rate - inpos);
      BufferSlicer input_this_round(input_slicer.take(to_take_this_round));

      // If necessary, try to get aligned with the sponge state's 64-bit integer array
      const auto bytes_out_of_word_alignment = static_cast<size_t>(inpos % word_width);
      if(bytes_out_of_word_alignment > 0) {
         const auto bytes_until_word_alignment = word_width - bytes_out_of_word_alignment;
         const auto bytes_from_input = std::min(input_this_round.remaining(), bytes_until_word_alignment);
         BOTAN_DEBUG_ASSERT(bytes_from_input < word_width);

         std::array<uint8_t, word_width> partial_word{};
         input_this_round.copy_into(std::span{partial_word}.subspan(bytes_out_of_word_alignment, bytes_from_input));
         partial_state_modifier_fn(
            S[inpos / word_width], load_le(partial_word), bytes_out_of_word_alignment, bytes_from_input);
         inpos += bytes_from_input;
      }

      // Process as many aligned 64-bit integer values as possible
      for(; input_this_round.remaining() >= word_width; inpos += word_width) {
         state_modifier_fn(S[inpos / word_width], load_le(input_this_round.take<word_width>()));
      }

      // Read remaining input data, causing misalignment, if necessary
      const auto remaining_bytes_out_of_word_alignment = input_this_round.remaining();
      BOTAN_DEBUG_ASSERT(remaining_bytes_out_of_word_alignment < word_width);
      if(remaining_bytes_out_of_word_alignment > 0) {
         std::array<uint8_t, word_width> partial_word{};
         input_this_round.copy_into(std::span{partial_word}.first(remaining_bytes_out_of_word_alignment));
         partial_state_modifier_fn(
            S[inpos / word_width], load_le(partial_word), 0, remaining_bytes_out_of_word_alignment);
         inpos += remaining_bytes_out_of_word_alignment;
      }

      // We reached the end of a sponge state block... permute() and start over
      if(inpos == byte_rate) {
         permutation_round_fn();
         inpos = 0;
      }
   }
}

}  // namespace

void Ascon_p::absorb(std::span<const uint8_t> input, std::optional<uint8_t> permutation_rounds) {
   process(
      m_S_inpos,
      byte_rate(),
      m_S,
      input,
      [](uint64_t& state_word, uint64_t input_word) { state_word ^= input_word; },
      [](uint64_t& state_word, uint64_t input_word, size_t, size_t) { state_word ^= input_word; },
      [&] { permute(permutation_rounds.value_or(m_processing_rounds)); });
}

void Ascon_p::percolate_in(std::span<uint8_t> data) {
   BufferStuffer output_stuffer(data);

   process(
      m_S_inpos,
      byte_rate(),
      m_S,
      data,
      [&](uint64_t& state_word, uint64_t input_word) {
         state_word ^= input_word;
         output_stuffer.append(store_le(state_word));
      },
      [&](uint64_t& state_word, uint64_t input_word, size_t offset, size_t length) {
         state_word ^= input_word;
         const auto state_word_bytes = store_le(state_word);
         output_stuffer.append(std::span{state_word_bytes}.subspan(offset, length));
      },
      [&] { permute(m_processing_rounds); });
}

void Ascon_p::percolate_out(std::span<uint8_t> data) {
   BufferStuffer output_stuffer(data);

   process(
      m_S_inpos,
      byte_rate(),
      m_S,
      data,
      [&](uint64_t& state_word, uint64_t input_word) {
         output_stuffer.append(store_le(state_word ^ input_word));
         state_word = input_word;
      },
      [&](uint64_t& state_word, uint64_t input_word, size_t offset, size_t length) {
         const auto pt_block = store_le(state_word ^ input_word);
         output_stuffer.append(std::span{pt_block}.subspan(offset, length));
         uint64_t mask = ((uint64_t(0) - 1) >> (64 - (length * 8))) << (offset * 8);
         state_word = (state_word & ~mask) | input_word;
      },
      [&] { permute(m_processing_rounds); });
}

void Ascon_p::squeeze(std::span<uint8_t> output) {
   BufferStuffer output_stuffer(output);

   process(
      m_S_outpos,
      byte_rate(),
      m_S,
      output,
      [&](uint64_t& state_word, uint64_t input_word) { output_stuffer.append(store_le(state_word ^ input_word)); },
      [&](uint64_t& state_word, uint64_t input_word, size_t offset, size_t length) {
         const auto out_buffer = store_le(state_word ^ input_word);
         output_stuffer.append(std::span{out_buffer}.subspan(offset, length));
      },
      [&] { permute(m_processing_rounds); });
}

void Ascon_p::finish() {
   // NIST SP.800-232, Section 2.1 (Algorithm 2 "pad()")

   // The padding is defined as:
   //   1. The first padding bit is set to 1
   //   2. The remaining bits are set to 0
   constexpr std::array<uint8_t, sizeof(AsconState)> padding{0x01};

   // We must always add a padded final input block, if the last verbatim
   // input block aligned with the byte rate, the final block may be just
   // padding bytes, otherwise the final block is padded as needed.

   absorb(std::span{padding}.first(byte_rate() - m_S_inpos), m_init_final_rounds);
   BOTAN_ASSERT_NOMSG(m_S_inpos == 0);
}

void Ascon_p::intermediate_finish() {
   // NIST SP.800-232, Section 2.1 (Algorithm 2 "pad()")

   // The padding is defined as:
   //   1. The first padding bit is set to 1
   //   2. The remaining bits are set to 0
   constexpr std::array<uint8_t, sizeof(AsconState)> padding{0x01};

   // We must always add a padded final input block, if the last verbatim
   // input block aligned with the byte rate, the final block may be just
   // padding bytes, otherwise the final block is padded as needed.

   absorb(std::span{padding}.first(byte_rate() - m_S_inpos));
   BOTAN_ASSERT_NOMSG(m_S_inpos == 0);
}

void Ascon_p::permute(uint8_t rounds) {
   BOTAN_DEBUG_ASSERT(rounds <= 16);

   // NIST SP.800-232, Table 5
   constexpr std::array<uint64_t, 16> round_constants = {
      0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

   for(uint8_t i = 0; i < rounds; ++i) {
      // Constant addition layer p_C
      // NIST SP.800-232, Section 3.2
      m_S[2] ^= round_constants[16 - rounds + i];

      // Substitution layer p_S
      // NIST SP.800-232, Section 3.3, most notably Figure 3
      m_S[0] ^= m_S[4];
      m_S[4] ^= m_S[3];
      m_S[2] ^= m_S[1];
      auto tmp = m_S;
      tmp[0] = ~tmp[0] & m_S[1];
      tmp[1] = ~tmp[1] & m_S[2];
      tmp[2] = ~tmp[2] & m_S[3];
      tmp[3] = ~tmp[3] & m_S[4];
      tmp[4] = ~tmp[4] & m_S[0];
      m_S[0] ^= tmp[1];
      m_S[1] ^= tmp[2];
      m_S[2] ^= tmp[3];
      m_S[3] ^= tmp[4];
      m_S[4] ^= tmp[0];
      m_S[1] ^= m_S[0];
      m_S[0] ^= m_S[4];
      m_S[3] ^= m_S[2];
      m_S[2] = ~m_S[2];

      // Linear diffusion layer p_L
      // NIST SP.800-232, Section 3.4
      m_S[0] = m_S[0] ^ rotr<19>(m_S[0]) ^ rotr<28>(m_S[0]);
      m_S[1] = m_S[1] ^ rotr<61>(m_S[1]) ^ rotr<39>(m_S[1]);
      m_S[2] = m_S[2] ^ rotr<1>(m_S[2]) ^ rotr<6>(m_S[2]);
      m_S[3] = m_S[3] ^ rotr<10>(m_S[3]) ^ rotr<17>(m_S[3]);
      m_S[4] = m_S[4] ^ rotr<7>(m_S[4]) ^ rotr<41>(m_S[4]);
   }
}

}  // namespace Botan
