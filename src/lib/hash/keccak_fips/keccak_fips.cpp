/*
* Keccak-FIPS
* (C) 2010,2016 Jack Lloyd
* (C) 2023 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak_fips.h>

#include <botan/internal/keccak_fips_round.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/fmt.h>
#include <botan/exceptn.h>

namespace Botan {

//static
void Keccak_FIPS_generic::permute(uint64_t A[25])
   {
#if defined(BOTAN_HAS_KECCKAK_FIPS_BMI2)
   if(CPUID::has_bmi2())
      {
      return permute_bmi2(A);
      }
#endif

   static const uint64_t RC[24] = {
      0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
      0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
      0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
      0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
      0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
      0x8000000000008080, 0x0000000080000001, 0x8000000080008008
   };

   uint64_t T[25];

   for(size_t i = 0; i != 24; i += 2)
      {
      Keccak_FIPS_round(T, A, RC[i+0]);
      Keccak_FIPS_round(A, T, RC[i+1]);
      }
   }

//static

size_t Keccak_FIPS_generic::absorb(size_t bitrate,
                     secure_vector<uint64_t>& S, size_t S_pos,
                     const uint8_t input[], size_t length)
   {
   while(length > 0)
      {
      size_t to_take = std::min(length, bitrate / 8 - S_pos);

      length -= to_take;

      while(to_take && S_pos % 8)
         {
         S[S_pos / 8] ^= static_cast<uint64_t>(input[0]) << (8 * (S_pos % 8));

         ++S_pos;
         ++input;
         --to_take;
         }

      while(to_take && to_take % 8 == 0)
         {
         S[S_pos / 8] ^= load_le<uint64_t>(input, 0);
         S_pos += 8;
         input += 8;
         to_take -= 8;
         }

      while(to_take)
         {
         S[S_pos / 8] ^= static_cast<uint64_t>(input[0]) << (8 * (S_pos % 8));

         ++S_pos;
         ++input;
         --to_take;
         }

      if(S_pos == bitrate / 8)
         {
         Keccak_FIPS_generic::permute(S.data());
         S_pos = 0;
         }
      }

   return S_pos;
   }

//static

void Keccak_FIPS_generic::finish(size_t bitrate,
                                 secure_vector<uint64_t>& S, size_t S_pos, uint64_t custom_padd, uint8_t custom_padd_bit_len)
   {
   BOTAN_ARG_CHECK(bitrate % 64 == 0, "Keccak-FIPS bitrate must be multiple of 64");
   // append the first bit of the final padding after the custom padding
   uint8_t init_pad = custom_padd | (1 << custom_padd_bit_len);
   S[S_pos / 8] ^= static_cast<uint64_t>(init_pad) << (8 * (S_pos % 8));
   // final bit of the padding of the last block
   S[(bitrate / 64) - 1] ^= static_cast<uint64_t>(0x80) << 56;
   Keccak_FIPS_generic::permute(S.data());
   }

//static

void Keccak_FIPS_generic::expand(size_t bitrate,
                   secure_vector<uint64_t>& S,
                   uint8_t output[], size_t output_length)
   {
   BOTAN_ARG_CHECK(bitrate % 64 == 0, "Keccak-FIPS bitrate must be multiple of 64");

   const size_t byterate = bitrate / 8;

   while(output_length > 0)
      {
      const size_t copying = std::min(byterate, output_length);

      copy_out_vec_le(output, copying, S);

      output += copying;
      output_length -= copying;

      if(output_length > 0)
         {
         Keccak_FIPS_generic::permute(S.data());
         }
      }
   }


Keccak_FIPS_generic::Keccak_FIPS_generic(std::string const& base_name, size_t output_bits, size_t capacity,
      uint64_t custom_padd,
      uint8_t custom_padd_bit_len) :
   m_output_bits(output_bits),
   m_bitrate(1600 - capacity),
   m_capacity(capacity),
   m_custom_padd(custom_padd),
   m_custom_padd_bit_len(custom_padd_bit_len),
   m_base_name(base_name),
   m_S(25), // 1600 bit
   m_S_pos(0)
   {
   // We only support the parameters for Keccak-FIPS in this constructor

   if(output_bits > 1600 )
      throw Invalid_Argument("Keccak_FIPS_generic: Invalid output length " +
                             std::to_string(output_bits));
   }


std::string Keccak_FIPS_generic::name() const
   {
   return m_base_name + "(" + std::to_string(m_output_bits) + ")";
   }


std::string Keccak_FIPS_generic::provider() const
   {
#if defined(BOTAN_HAS_KECCKAK_FIPS_BMI2)
   if(CPUID::has_bmi2())
      {
      return "bmi2";
      }
#endif

   return "base";
   }


std::unique_ptr<HashFunction> Keccak_FIPS_generic::copy_state() const
   {
   return std::make_unique<Keccak_FIPS_generic>(*this);
   }


std::unique_ptr<HashFunction> Keccak_FIPS_generic::new_object() const
   {
   return std::make_unique<Keccak_FIPS_generic>(m_base_name, m_output_bits, m_capacity, m_custom_padd,
          m_custom_padd_bit_len);
   }


void Keccak_FIPS_generic::clear()
   {
   zeroise(m_S);
   m_S_pos = 0;
   }


void Keccak_FIPS_generic::add_data(const uint8_t input[], size_t length)
   {
   m_S_pos = Keccak_FIPS_generic::absorb(m_bitrate, m_S, m_S_pos, input, length);
   }


void Keccak_FIPS_generic::final_result(uint8_t output[])
   {
   Keccak_FIPS_generic::finish(m_bitrate, m_S, m_S_pos, m_custom_padd, m_custom_padd_bit_len);

   /*
   * We never have to run the permutation again because we only support
   * limited output lengths
   */
   copy_out_vec_le(output, m_output_bits/8, m_S);

   clear();
   }

    Keccak_FIPS_generic::~Keccak_FIPS_generic()
    {

    }

Keccak_FIPS_512::Keccak_FIPS_512(size_t output_bits)
   :Keccak_FIPS_generic("Keccak_FIPS[512]", output_bits, 512, 0, 0)
   {

   }


Keccak_FIPS_256::Keccak_FIPS_256(size_t output_bits)
   :Keccak_FIPS_generic("Keccak_FIPS[256]", output_bits, 256, 0, 0)
   {

   }
}
