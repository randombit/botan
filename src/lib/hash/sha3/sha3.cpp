/*
* SHA-3
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sha3.h>
#include <botan/exceptn.h>

namespace Botan {

std::unique_ptr<HashFunction> SHA_3::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new SHA_3(*this));
   }

//static
void SHA_3::permute(uint64_t A[25])
   {
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

   for(size_t i = 0; i != 24; ++i)
      {
      const uint64_t C0 = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
      const uint64_t C1 = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
      const uint64_t C2 = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
      const uint64_t C3 = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
      const uint64_t C4 = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

      const uint64_t D0 = rotate_left(C0, 1) ^ C3;
      const uint64_t D1 = rotate_left(C1, 1) ^ C4;
      const uint64_t D2 = rotate_left(C2, 1) ^ C0;
      const uint64_t D3 = rotate_left(C3, 1) ^ C1;
      const uint64_t D4 = rotate_left(C4, 1) ^ C2;

      const uint64_t B00 = A[ 0] ^ D1;
      const uint64_t B10 = rotate_left(A[ 1] ^ D2, 1);
      const uint64_t B20 = rotate_left(A[ 2] ^ D3, 62);
      const uint64_t B05 = rotate_left(A[ 3] ^ D4, 28);
      const uint64_t B15 = rotate_left(A[ 4] ^ D0, 27);
      const uint64_t B16 = rotate_left(A[ 5] ^ D1, 36);
      const uint64_t B01 = rotate_left(A[ 6] ^ D2, 44);
      const uint64_t B11 = rotate_left(A[ 7] ^ D3, 6);
      const uint64_t B21 = rotate_left(A[ 8] ^ D4, 55);
      const uint64_t B06 = rotate_left(A[ 9] ^ D0, 20);
      const uint64_t B07 = rotate_left(A[10] ^ D1, 3);
      const uint64_t B17 = rotate_left(A[11] ^ D2, 10);
      const uint64_t B02 = rotate_left(A[12] ^ D3, 43);
      const uint64_t B12 = rotate_left(A[13] ^ D4, 25);
      const uint64_t B22 = rotate_left(A[14] ^ D0, 39);
      const uint64_t B23 = rotate_left(A[15] ^ D1, 41);
      const uint64_t B08 = rotate_left(A[16] ^ D2, 45);
      const uint64_t B18 = rotate_left(A[17] ^ D3, 15);
      const uint64_t B03 = rotate_left(A[18] ^ D4, 21);
      const uint64_t B13 = rotate_left(A[19] ^ D0, 8);
      const uint64_t B14 = rotate_left(A[20] ^ D1, 18);
      const uint64_t B24 = rotate_left(A[21] ^ D2, 2);
      const uint64_t B09 = rotate_left(A[22] ^ D3, 61);
      const uint64_t B19 = rotate_left(A[23] ^ D4, 56);
      const uint64_t B04 = rotate_left(A[24] ^ D0, 14);

      A[ 0] = B00 ^ (~B01 & B02);
      A[ 1] = B01 ^ (~B02 & B03);
      A[ 2] = B02 ^ (~B03 & B04);
      A[ 3] = B03 ^ (~B04 & B00);
      A[ 4] = B04 ^ (~B00 & B01);
      A[ 5] = B05 ^ (~B06 & B07);
      A[ 6] = B06 ^ (~B07 & B08);
      A[ 7] = B07 ^ (~B08 & B09);
      A[ 8] = B08 ^ (~B09 & B05);
      A[ 9] = B09 ^ (~B05 & B06);
      A[10] = B10 ^ (~B11 & B12);
      A[11] = B11 ^ (~B12 & B13);
      A[12] = B12 ^ (~B13 & B14);
      A[13] = B13 ^ (~B14 & B10);
      A[14] = B14 ^ (~B10 & B11);
      A[15] = B15 ^ (~B16 & B17);
      A[16] = B16 ^ (~B17 & B18);
      A[17] = B17 ^ (~B18 & B19);
      A[18] = B18 ^ (~B19 & B15);
      A[19] = B19 ^ (~B15 & B16);
      A[20] = B20 ^ (~B21 & B22);
      A[21] = B21 ^ (~B22 & B23);
      A[22] = B22 ^ (~B23 & B24);
      A[23] = B23 ^ (~B24 & B20);
      A[24] = B24 ^ (~B20 & B21);

      A[0] ^= RC[i];
      }
   }

SHA_3::SHA_3(size_t output_bits) :
   m_output_bits(output_bits),
   m_bitrate(1600 - 2*output_bits),
   m_S(25),
   m_S_pos(0)
   {
   // We only support the parameters for SHA-3 in this constructor

   if(output_bits != 224 && output_bits != 256 &&
      output_bits != 384 && output_bits != 512)
      throw Invalid_Argument("SHA_3: Invalid output length " +
                             std::to_string(output_bits));
   }

std::string SHA_3::name() const
   {
   return "SHA-3(" + std::to_string(m_output_bits) + ")";
   }

HashFunction* SHA_3::clone() const
   {
   return new SHA_3(m_output_bits);
   }

void SHA_3::clear()
   {
   zeroise(m_S);
   m_S_pos = 0;
   }

//static
size_t SHA_3::absorb(size_t bitrate,
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
         SHA_3::permute(S.data());
         S_pos = 0;
         }
      }

   return S_pos;
   }

//static
void SHA_3::expand(size_t bitrate,
                   secure_vector<uint64_t>& S,
                   uint8_t output[], size_t output_length)
   {
   BOTAN_ARG_CHECK(bitrate % 8 == 0);

   size_t Si = 0;

   for(size_t i = 0; i != output_length; ++i)
      {
      if(i > 0)
         {
         if(i % (bitrate / 8) == 0)
            {
            SHA_3::permute(S.data());
            Si = 0;
            }
         else if(i % 8 == 0)
            {
            Si += 1;
            }
         }

      output[i] = get_byte(7 - (i % 8), S[Si]);
      }
   }

void SHA_3::add_data(const uint8_t input[], size_t length)
   {
   m_S_pos = SHA_3::absorb(m_bitrate, m_S, m_S_pos, input, length);
   }

void SHA_3::final_result(uint8_t output[])
   {
   std::vector<uint8_t> padding(m_bitrate / 8 - m_S_pos);

   padding[0] = 0x06;
   padding[padding.size()-1] |= 0x80;

   add_data(padding.data(), padding.size());

   /*
   * We never have to run the permutation again because we only support
   * limited output lengths
   */
   for(size_t i = 0; i != m_output_bits/8; ++i)
      output[i] = get_byte(7 - (i % 8), m_S[i/8]);

   clear();
   }

}
