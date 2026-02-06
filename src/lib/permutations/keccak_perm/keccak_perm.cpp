/*
* Keccak Permutation
* (C) 2010,2016 Jack Lloyd
* (C) 2023 Falko Strenzke
* (C) 2023,2025 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak_perm.h>

#include <botan/internal/keccak_perm_round.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/sponge_processing.h>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

std::string Keccak_Permutation::provider() const {
#if defined(BOTAN_HAS_KECCAK_PERM_AVX512)
   if(auto feat = CPUID::check(CPUID::Feature::AVX512)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_KECCAK_PERM_BMI2)
   if(auto feat = CPUID::check(CPUID::Feature::BMI)) {
      return *feat;
   }
#endif

   return "base";
}

void Keccak_Permutation::clear() {
   state() = {};
   reset_cursor();
}

void Keccak_Permutation::absorb(std::span<const uint8_t> input) {
   absorb_into_sponge(*this, input);
}

void Keccak_Permutation::squeeze(std::span<uint8_t> output) {
   squeeze_from_sponge(*this, output);
}

void Keccak_Permutation::finish() {
   // The padding for Keccak[c]-based functions spans the entire remaining
   // byterate until the next permute() call. At most that could be an entire
   // byterate. First are a few bits of "custom" padding defined by the using
   // function (e.g. SHA-3 uses "01"), then the remaining space is filled with
   // "pad10*1" (see NIST FIPS 202 Section 5.1) followed by a final permute().

   auto& S = state();

   // Apply the custom padding + the left-most 1-bit of "pad10*1" to the current
   // (partial) word of the sponge state

   const uint64_t start_of_padding = (m_padding.padding | uint64_t(1) << m_padding.bit_len);
   S[cursor() / word_bytes] ^= start_of_padding << (8 * (cursor() % word_bytes));

   // XOR'ing the 0-bits of "pad10*1" into the state is a NOOP

   // If the custom padding + the left-most 1-bit of "pad10*1" had resulted in a
   // byte-aligned "partial padding", the final 1-bit of of "pad10*1" could
   // potentially override parts of the already-appended "start_of_padding".
   // In case we ever introduce a Keccak-based function with such a need, we
   // have to modify this padding algorithm.
   BOTAN_DEBUG_ASSERT(m_padding.bit_len % 8 != 7);

   // Append the final bit of "pad10*1" into the last word of the input range
   S[(byte_rate() / word_bytes) - 1] ^= uint64_t(0x8000000000000000);

   // Perform the final permutation and reset the state cursor
   permute();
   reset_cursor();

   BOTAN_DEBUG_ASSERT(cursor() == 0);
}

void Keccak_Permutation::permute() {
#if defined(BOTAN_HAS_KECCAK_PERM_AVX512)
   if(CPUID::has(CPUID::Feature::AVX512)) {
      return permute_avx512();
   }
#endif

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
      Keccak_Permutation_round(T, state().data(), RC[i + 0]);
      Keccak_Permutation_round(state().data(), T, RC[i + 1]);
   }
}

}  // namespace Botan
