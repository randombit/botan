/*
* SHA-3
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha3.h>

#include <botan/exceptn.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/sha3_round.h>

namespace Botan {

//static
void SHA_3::permute(uint64_t A[25]) {
#if defined(BOTAN_HAS_SHA3_BMI2)
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
      SHA3_round(T, A, RC[i + 0]);
      SHA3_round(A, T, RC[i + 1]);
   }
}

//static
size_t SHA_3::absorb(size_t bitrate, secure_vector<uint64_t>& S, size_t S_pos, const uint8_t input[], size_t length) {
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
         SHA_3::permute(S.data());
         S_pos = 0;
      }
   }

   return S_pos;
}

//static
void SHA_3::finish(size_t bitrate, secure_vector<uint64_t>& S, size_t S_pos, uint8_t init_pad, uint8_t fini_pad) {
   BOTAN_ARG_CHECK(bitrate % 64 == 0, "SHA-3 bitrate must be multiple of 64");

   S[S_pos / 8] ^= static_cast<uint64_t>(init_pad) << (8 * (S_pos % 8));
   S[(bitrate / 64) - 1] ^= static_cast<uint64_t>(fini_pad) << 56;
   SHA_3::permute(S.data());
}

//static
void SHA_3::expand(size_t bitrate, secure_vector<uint64_t>& S, uint8_t output[], size_t output_length) {
   BOTAN_ARG_CHECK(bitrate % 64 == 0, "SHA-3 bitrate must be multiple of 64");

   const size_t byterate = bitrate / 8;

   while(output_length > 0) {
      const size_t copying = std::min(byterate, output_length);

      copy_out_vec_le(output, copying, S);

      output += copying;
      output_length -= copying;

      if(output_length > 0) {
         SHA_3::permute(S.data());
      }
   }
}

SHA_3::SHA_3(size_t output_bits) : m_output_bits(output_bits), m_bitrate(1600 - 2 * output_bits), m_S(25), m_S_pos(0) {
   // We only support the parameters for SHA-3 in this constructor

   if(output_bits != 224 && output_bits != 256 && output_bits != 384 && output_bits != 512) {
      throw Invalid_Argument(fmt("SHA_3: Invalid output length {}", output_bits));
   }
}

std::string SHA_3::name() const { return fmt("SHA-3({})", m_output_bits); }

std::string SHA_3::provider() const {
#if defined(BOTAN_HAS_SHA3_BMI2)
   if(CPUID::has_bmi2()) {
      return "bmi2";
   }
#endif

   return "base";
}

std::unique_ptr<HashFunction> SHA_3::copy_state() const { return std::make_unique<SHA_3>(*this); }

std::unique_ptr<HashFunction> SHA_3::new_object() const { return std::make_unique<SHA_3>(m_output_bits); }

void SHA_3::clear() {
   zeroise(m_S);
   m_S_pos = 0;
}

void SHA_3::add_data(const uint8_t input[], size_t length) {
   m_S_pos = SHA_3::absorb(m_bitrate, m_S, m_S_pos, input, length);
}

void SHA_3::final_result(uint8_t output[]) {
   SHA_3::finish(m_bitrate, m_S, m_S_pos, 0x06, 0x80);

   /*
   * We never have to run the permutation again because we only support
   * limited output lengths
   */
   copy_out_vec_le(output, m_output_bits / 8, m_S);

   clear();
}

}  // namespace Botan
