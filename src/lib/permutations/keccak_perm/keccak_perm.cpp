/*
* Keccak Permutation
* (C) 2010,2016 Jack Lloyd
* (C) 2023 Falko Strenzke
* (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak_perm.h>

#include <botan/exceptn.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/fmt.h>
#include <botan/internal/keccak_perm_round.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

Keccak_Permutation::Keccak_Permutation(size_t capacity, uint64_t custom_padding, uint8_t custom_padding_bit_len) :
      m_capacity(capacity),
      m_byterate((1600 - capacity) / 8),
      m_custom_padding(custom_padding),
      m_custom_padding_bit_len(custom_padding_bit_len),
      m_S(25),  // 1600 bit
      m_S_inpos(0),
      m_S_outpos(0) {
   BOTAN_ARG_CHECK(capacity % 64 == 0, "capacity must be a multiple of 64");
}

std::string Keccak_Permutation::provider() const {
#if defined(BOTAN_HAS_KECCAK_PERM_BMI2)
   if(CPUID::has_bmi2()) {
      return "bmi2";
   }
#endif

   return "base";
}

void Keccak_Permutation::clear() {
   zeroise(m_S);
   m_S_inpos = 0;
   m_S_outpos = 0;
}

void Keccak_Permutation::absorb(std::span<const uint8_t> input) {
   BufferSlicer input_slicer(input);

   // Block-wise incorporation of the input data into the sponge state until
   // all input bytes are processed
   while(!input_slicer.empty()) {
      const size_t to_take_this_round = std::min(input_slicer.remaining(), m_byterate - m_S_inpos);
      BufferSlicer input_this_round(input_slicer.take(to_take_this_round));

      // If necessary, try to get aligned with the sponge state's 64-bit integer array
      for(; !input_this_round.empty() && m_S_inpos % 8; ++m_S_inpos) {
         m_S[m_S_inpos / 8] ^= static_cast<uint64_t>(input_this_round.take_byte()) << (8 * (m_S_inpos % 8));
      }

      // Process as many aligned 64-bit integer values as possible
      for(; input_this_round.remaining() >= 8; m_S_inpos += 8) {
         m_S[m_S_inpos / 8] ^= load_le<uint64_t>(input_this_round.take(8).data(), 0);
      }

      // Read remaining output data, causing misalignment, if necessary
      for(; !input_this_round.empty(); ++m_S_inpos) {
         m_S[m_S_inpos / 8] ^= static_cast<uint64_t>(input_this_round.take_byte()) << (8 * (m_S_inpos % 8));
      }

      // We reached the end of a sponge state block... permute() and start over
      if(m_S_inpos == m_byterate) {
         permute();
         m_S_inpos = 0;
      }
   }
}

void Keccak_Permutation::squeeze(std::span<uint8_t> output) {
   BufferStuffer output_stuffer(output);

   // Block-wise readout of the sponge state until enough bytes
   // were filled into the output buffer
   while(!output_stuffer.full()) {
      const size_t bytes_in_this_round = std::min(output_stuffer.remaining_capacity(), m_byterate - m_S_outpos);
      BufferStuffer output_this_round(output_stuffer.next(bytes_in_this_round));

      // If necessary, try to get aligned with the sponge state's 64-bit integer array
      for(; !output_this_round.full() && m_S_outpos % 8 != 0; ++m_S_outpos) {
         output_this_round.next_byte() = static_cast<uint8_t>(m_S[m_S_outpos / 8] >> (8 * (m_S_outpos % 8)));
      }

      // Read out as many aligned 64-bit integer values as possible
      for(; output_this_round.remaining_capacity() >= 8; m_S_outpos += 8) {
         store_le(m_S[m_S_outpos / 8], output_this_round.next(8).data());
      }

      // Read remaining output data, causing misalignment, if necessary
      for(; !output_this_round.full(); ++m_S_outpos) {
         output_this_round.next_byte() = static_cast<uint8_t>(m_S[m_S_outpos / 8] >> (8 * (m_S_outpos % 8)));
      }

      // We reached the end of a sponge state block... permute() and start over
      if(m_S_outpos == m_byterate) {
         permute();
         m_S_outpos = 0;
      }
   }
}

void Keccak_Permutation::finish() {
   // append the first bit of the final padding after the custom padding
   uint8_t init_pad = static_cast<uint8_t>(m_custom_padding | uint64_t(1) << m_custom_padding_bit_len);
   m_S[m_S_inpos / 8] ^= static_cast<uint64_t>(init_pad) << (8 * (m_S_inpos % 8));

   // final bit of the padding of the last block
   m_S[(m_byterate / 8) - 1] ^= static_cast<uint64_t>(0x80) << 56;

   permute();
}

void Keccak_Permutation::permute() {
#if defined(BOTAN_HAS_KECCAK_PERM_BMI2)
   if(CPUID::has_bmi2()) {
      return permute_bmi2();
   }
#endif

   static const uint64_t RC[24] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
                                   0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                                   0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                                   0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
                                   0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
                                   0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

   uint64_t T[25];

   for(size_t i = 0; i != 24; i += 2) {
      Keccak_Permutation_round(T, m_S.data(), RC[i + 0]);
      Keccak_Permutation_round(m_S.data(), T, RC[i + 1]);
   }
}

}  // namespace Botan
