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
   BufferSlicer input_slicer(input);

   // Block-wise incorporation of the input data into the sponge state until
   // all input bytes are processed
   while(!input_slicer.empty()) {
      const size_t to_take_this_round = std::min(input_slicer.remaining(), byte_rate() - m_S_inpos);
      BufferSlicer input_this_round(input_slicer.take(to_take_this_round));

      // If necessary, try to get aligned with the sponge state's 64-bit integer array
      for(; !input_this_round.empty() && m_S_inpos % 8 > 0; ++m_S_inpos) {
         m_S[m_S_inpos / 8] ^= static_cast<uint64_t>(input_this_round.take_byte()) << (8 * (m_S_inpos % 8));
      }

      // Process as many aligned 64-bit integer values as possible
      for(; input_this_round.remaining() >= 8; m_S_inpos += 8) {
         m_S[m_S_inpos / 8] ^= load_le(input_this_round.take<8>());
      }

      // Read remaining input data, causing misalignment, if necessary
      for(; !input_this_round.empty(); ++m_S_inpos) {
         m_S[m_S_inpos / 8] ^= static_cast<uint64_t>(input_this_round.take_byte()) << (8 * (m_S_inpos % 8));
      }

      // We reached the end of a sponge state block... permute() and start over
      if(m_S_inpos == byte_rate()) {
         permute(permutation_rounds.value_or(m_processing_rounds));
         m_S_inpos = 0;
      }
   }
}

void Ascon_p::squeeze(std::span<uint8_t> output) {
   BufferStuffer output_stuffer(output);

   // Block-wise readout of the sponge state until enough bytes
   // were filled into the output buffer
   while(!output_stuffer.full()) {
      const size_t bytes_in_this_round = std::min(output_stuffer.remaining_capacity(), byte_rate() - m_S_outpos);
      BufferStuffer output_this_round(output_stuffer.next(bytes_in_this_round));

      // If necessary, try to get aligned with the sponge state's 64-bit integer array
      for(; !output_this_round.full() && m_S_outpos % 8 != 0; ++m_S_outpos) {
         output_this_round.next_byte() = static_cast<uint8_t>(m_S[m_S_outpos / 8] >> (8 * (m_S_outpos % 8)));
      }

      // Read out as many aligned 64-bit integer values as possible
      for(; output_this_round.remaining_capacity() >= 8; m_S_outpos += 8) {
         store_le(m_S[m_S_outpos / 8], output_this_round.next<8>());
      }

      // Read remaining output data, causing misalignment, if necessary
      for(; !output_this_round.full(); ++m_S_outpos) {
         output_this_round.next_byte() = static_cast<uint8_t>(m_S[m_S_outpos / 8] >> (8 * (m_S_outpos % 8)));
      }

      // We reached the end of a sponge state block... permute() and start over
      // TODO: Currently this might perform an unnecessary permutation if the
      //       to-be-generated output length is divisible by the byte rate,
      //       for instance with Ascon-Hash256 this is always the case.
      if(m_S_outpos == byte_rate()) {
         permute(m_processing_rounds);
         m_S_outpos = 0;
      }
   }
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
