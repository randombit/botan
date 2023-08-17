/*
* Keccak-FIPS
* (C) 2010,2016 Jack Lloyd
* (C) 2023 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak_perm.h>

#include <botan/exceptn.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/fmt.h>
#include <botan/internal/keccak_perm_round.h>
#include <botan/internal/loadstor.h>

namespace Botan {

// static
void Keccak_Permutation::permute(uint64_t A[25]) {
#if defined(BOTAN_HAS_KECCKAK_FIPS_BMI2)
   if(CPUID::has_bmi2()) {
      return permute_bmi2(A);
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
      Keccak_Permutation_round(T, A, RC[i + 0]);
      Keccak_Permutation_round(A, T, RC[i + 1]);
   }
}

void Keccak_Permutation::permute() {
   Keccak_Permutation::permute(m_S.data());
}

//static

uint32_t Keccak_Permutation::absorb(size_t bitrate,
                             secure_vector<uint64_t>& S,
                             size_t S_pos,
                             std::span<const uint8_t> input_span) {
   const uint8_t* input = input_span.data();
   size_t length = input_span.size();

   while(length > 0) {
      size_t to_take = std::min(length, bitrate / 8 - S_pos);

      length -= to_take;

      while(to_take && S_pos % 8) {
         S[S_pos / 8] ^= static_cast<uint64_t>(input[0]) << (8 * (S_pos % 8));

         ++S_pos;
         ++input;
         --to_take;
      }

      while(to_take && to_take % 8 == 0) {
         S[S_pos / 8] ^= load_le<uint64_t>(input, 0);
         S_pos += 8;
         input += 8;
         to_take -= 8;
      }

      while(to_take) {
         S[S_pos / 8] ^= static_cast<uint64_t>(input[0]) << (8 * (S_pos % 8));

         ++S_pos;
         ++input;
         --to_take;
      }

      if(S_pos == bitrate / 8) {
         Keccak_Permutation::permute(S.data());
         S_pos = 0;
      }
   }

   return static_cast<uint32_t>(S_pos);
}

//static

void Keccak_Permutation::finish(
   size_t bitrate, secure_vector<uint64_t>& S, size_t S_pos, uint64_t custom_padd, uint8_t custom_padd_bit_len) {
   BOTAN_ARG_CHECK(bitrate % 64 == 0, "Keccak-FIPS bitrate must be multiple of 64");
   // append the first bit of the final padding after the custom padding
   uint8_t init_pad = static_cast<uint8_t>(custom_padd | uint64_t(1) << custom_padd_bit_len);
   S[S_pos / 8] ^= static_cast<uint64_t>(init_pad) << (8 * (S_pos % 8));
   // final bit of the padding of the last block
   S[(bitrate / 64) - 1] ^= static_cast<uint64_t>(0x80) << 56;
   Keccak_Permutation::permute(S.data());
}

//static

void Keccak_Permutation::expand(size_t bitrate, secure_vector<uint64_t>& S, std::span<uint8_t> output_span) {
   uint8_t* output = output_span.data();
   size_t output_length = output_span.size();
   BOTAN_ARG_CHECK(bitrate % 64 == 0, "Keccak-FIPS bitrate must be multiple of 64");

   const size_t byterate = bitrate / 8;

   while(output_length > 0) {
      const size_t copying = std::min(byterate, output_length);

      copy_out_vec_le(output, copying, S);

      output += copying;
      output_length -= copying;

      if(output_length > 0) {
         Keccak_Permutation::permute(S.data());
      }
   }
}

void Keccak_Permutation::expand(std::span<uint8_t> output_span) {
   expand(m_bitrate, m_S, output_span);
}

Keccak_Permutation::Keccak_Permutation(size_t output_bits, size_t capacity, uint64_t custom_padd, uint8_t custom_padd_bit_len) :
      m_output_bits(output_bits),
      m_capacity(static_cast<uint32_t>(capacity)),
      m_bitrate(static_cast<uint32_t>(1600 - capacity)),
      m_custom_padd(custom_padd),
      m_custom_padd_bit_len(custom_padd_bit_len),
      m_S(25),  // 1600 bit
      m_S_pos(0) {
   // We only support the parameters for Keccak-FIPS in this constructor
   BOTAN_ASSERT_NOMSG(output_bits % 8 == 0);
   if(output_bits > 1600) {
      throw Invalid_Argument("Keccak_Permutation: Invalid output length " + std::to_string(output_bits));
   }
}

std::string Keccak_Permutation::provider() const {
#if defined(BOTAN_HAS_KECCKAK_FIPS_BMI2)
   if(CPUID::has_bmi2()) {
      return "bmi2";
   }
#endif

   return "base";
}

void Keccak_Permutation::clear() {
   zeroise(m_S);
   m_S_pos = 0;
}

void Keccak_Permutation::absorb(std::span<const uint8_t> input) {
   m_S_pos = Keccak_Permutation::absorb(m_bitrate, m_S, m_S_pos, input);
}

void Keccak_Permutation::finish(std::span<uint8_t> output) {
   Keccak_Permutation::finish(m_bitrate, m_S, m_S_pos, m_custom_padd, m_custom_padd_bit_len);

   BOTAN_ASSERT_NOMSG(output.size() >= m_output_bits / 8);

   /*
   * We never have to run the permutation again because we only support
   * limited output lengths
   */
   copy_out_vec_le(output.data(), m_output_bits / 8, m_S);
   clear();
}

}  // namespace Botan
