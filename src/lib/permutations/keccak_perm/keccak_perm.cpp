/*
* Keccak Permutation
* (C) 2010,2016 Jack Lloyd
* (C) 2023 Falko Strenzke
* (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak_perm.h>

#include <botan/internal/keccak_perm_round.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

std::string Keccak_Permutation::provider() const {
#if defined(BOTAN_HAS_KECCAK_PERM_BMI2)
   if(auto feat = CPUID::check(CPUID::Feature::BMI)) {
      return *feat;
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
      for(; !input_this_round.empty() && m_S_inpos % 8 > 0; ++m_S_inpos) {
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
   // The padding for Keccak[c]-based functions spans the entire remaining
   // byterate until the next permute() call. At most that could be an entire
   // byterate. First are a few bits of "custom" padding defined by the using
   // function (e.g. SHA-3 uses "01"), then the remaining space is filled with
   // "pad10*1" (see NIST FIPS 202 Section 5.1) followed by a final permute().

   // Apply the custom padding + the left-most 1-bit of "pad10*1" to the current
   // (partial) word of the sponge state
   const uint64_t start_of_padding = (m_padding.padding | uint64_t(1) << m_padding.bit_len);
   m_S[m_S_inpos / 8] ^= start_of_padding << (8 * (m_S_inpos % 8));

   // XOR'ing the 0-bits of "pad10*1" into the state is a NOOP

   // If the custom padding + the left-most 1-bit of "pad10*1" had resulted in a
   // byte-aligned "partial padding", the final 1-bit of of "pad10*1" could
   // potentially override parts of the already-appended "start_of_padding".
   // In case we ever introduce a Keccak-based function with such a need, we
   // have to modify this padding algorithm.
   BOTAN_DEBUG_ASSERT(m_padding.bit_len % 8 != 7);

   // Append the final bit of "pad10*1" into the last word of the input range
   m_S[(m_byterate / 8) - 1] ^= uint64_t(0x8000000000000000);

   // Perform the final permutation
   permute();
}

void Keccak_Permutation::permute() {
#if defined(BOTAN_HAS_KECCAK_PERM_BMI2)
   if(CPUID::has(CPUID::Feature::BMI)) {
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
