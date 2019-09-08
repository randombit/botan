/*
* Whirlpool
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/whrlpool.h>
#include <botan/loadstor.h>

namespace Botan {

std::unique_ptr<HashFunction> Whirlpool::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new Whirlpool(*this));
   }

/*
* Whirlpool Compression Function
*/
void Whirlpool::compress_n(const uint8_t in[], size_t blocks)
   {
   static const uint64_t RC[10] = {
      0x1823C6E887B8014F, 0x36A6D2F5796F9152,
      0x60BC9B8EA30C7B35, 0x1DE0D7C22E4BFE57,
      0x157737E59FF04ADA, 0x58C9290AB1A06B85,
      0xBD5D10F4CB3E0567, 0xE427418BA77D95D8,
      0xFBEE7C66DD17479E, 0xCA2DBF07AD5A8333
   };

   for(size_t i = 0; i != blocks; ++i)
      {
      load_be(m_M.data(), in, m_M.size());

      uint64_t K0, K1, K2, K3, K4, K5, K6, K7;
      K0 = m_digest[0]; K1 = m_digest[1]; K2 = m_digest[2]; K3 = m_digest[3];
      K4 = m_digest[4]; K5 = m_digest[5]; K6 = m_digest[6]; K7 = m_digest[7];

      uint64_t B0, B1, B2, B3, B4, B5, B6, B7;
      B0 = K0 ^ m_M[0]; B1 = K1 ^ m_M[1]; B2 = K2 ^ m_M[2]; B3 = K3 ^ m_M[3];
      B4 = K4 ^ m_M[4]; B5 = K5 ^ m_M[5]; B6 = K6 ^ m_M[6]; B7 = K7 ^ m_M[7];

      for(size_t j = 0; j != 10; ++j)
         {
         uint64_t T0, T1, T2, T3, T4, T5, T6, T7;
         T0 = C0[get_byte(0, K0)] ^ C1[get_byte(1, K7)] ^
              C2[get_byte(2, K6)] ^ C3[get_byte(3, K5)] ^
              C4[get_byte(4, K4)] ^ C5[get_byte(5, K3)] ^
              C6[get_byte(6, K2)] ^ C7[get_byte(7, K1)] ^ RC[j];
         T1 = C0[get_byte(0, K1)] ^ C1[get_byte(1, K0)] ^
              C2[get_byte(2, K7)] ^ C3[get_byte(3, K6)] ^
              C4[get_byte(4, K5)] ^ C5[get_byte(5, K4)] ^
              C6[get_byte(6, K3)] ^ C7[get_byte(7, K2)];
         T2 = C0[get_byte(0, K2)] ^ C1[get_byte(1, K1)] ^
              C2[get_byte(2, K0)] ^ C3[get_byte(3, K7)] ^
              C4[get_byte(4, K6)] ^ C5[get_byte(5, K5)] ^
              C6[get_byte(6, K4)] ^ C7[get_byte(7, K3)];
         T3 = C0[get_byte(0, K3)] ^ C1[get_byte(1, K2)] ^
              C2[get_byte(2, K1)] ^ C3[get_byte(3, K0)] ^
              C4[get_byte(4, K7)] ^ C5[get_byte(5, K6)] ^
              C6[get_byte(6, K5)] ^ C7[get_byte(7, K4)];
         T4 = C0[get_byte(0, K4)] ^ C1[get_byte(1, K3)] ^
              C2[get_byte(2, K2)] ^ C3[get_byte(3, K1)] ^
              C4[get_byte(4, K0)] ^ C5[get_byte(5, K7)] ^
              C6[get_byte(6, K6)] ^ C7[get_byte(7, K5)];
         T5 = C0[get_byte(0, K5)] ^ C1[get_byte(1, K4)] ^
              C2[get_byte(2, K3)] ^ C3[get_byte(3, K2)] ^
              C4[get_byte(4, K1)] ^ C5[get_byte(5, K0)] ^
              C6[get_byte(6, K7)] ^ C7[get_byte(7, K6)];
         T6 = C0[get_byte(0, K6)] ^ C1[get_byte(1, K5)] ^
              C2[get_byte(2, K4)] ^ C3[get_byte(3, K3)] ^
              C4[get_byte(4, K2)] ^ C5[get_byte(5, K1)] ^
              C6[get_byte(6, K0)] ^ C7[get_byte(7, K7)];
         T7 = C0[get_byte(0, K7)] ^ C1[get_byte(1, K6)] ^
              C2[get_byte(2, K5)] ^ C3[get_byte(3, K4)] ^
              C4[get_byte(4, K3)] ^ C5[get_byte(5, K2)] ^
              C6[get_byte(6, K1)] ^ C7[get_byte(7, K0)];

         K0 = T0; K1 = T1; K2 = T2; K3 = T3;
         K4 = T4; K5 = T5; K6 = T6; K7 = T7;

         T0 = C0[get_byte(0, B0)] ^ C1[get_byte(1, B7)] ^
              C2[get_byte(2, B6)] ^ C3[get_byte(3, B5)] ^
              C4[get_byte(4, B4)] ^ C5[get_byte(5, B3)] ^
              C6[get_byte(6, B2)] ^ C7[get_byte(7, B1)] ^ K0;
         T1 = C0[get_byte(0, B1)] ^ C1[get_byte(1, B0)] ^
              C2[get_byte(2, B7)] ^ C3[get_byte(3, B6)] ^
              C4[get_byte(4, B5)] ^ C5[get_byte(5, B4)] ^
              C6[get_byte(6, B3)] ^ C7[get_byte(7, B2)] ^ K1;
         T2 = C0[get_byte(0, B2)] ^ C1[get_byte(1, B1)] ^
              C2[get_byte(2, B0)] ^ C3[get_byte(3, B7)] ^
              C4[get_byte(4, B6)] ^ C5[get_byte(5, B5)] ^
              C6[get_byte(6, B4)] ^ C7[get_byte(7, B3)] ^ K2;
         T3 = C0[get_byte(0, B3)] ^ C1[get_byte(1, B2)] ^
              C2[get_byte(2, B1)] ^ C3[get_byte(3, B0)] ^
              C4[get_byte(4, B7)] ^ C5[get_byte(5, B6)] ^
              C6[get_byte(6, B5)] ^ C7[get_byte(7, B4)] ^ K3;
         T4 = C0[get_byte(0, B4)] ^ C1[get_byte(1, B3)] ^
              C2[get_byte(2, B2)] ^ C3[get_byte(3, B1)] ^
              C4[get_byte(4, B0)] ^ C5[get_byte(5, B7)] ^
              C6[get_byte(6, B6)] ^ C7[get_byte(7, B5)] ^ K4;
         T5 = C0[get_byte(0, B5)] ^ C1[get_byte(1, B4)] ^
              C2[get_byte(2, B3)] ^ C3[get_byte(3, B2)] ^
              C4[get_byte(4, B1)] ^ C5[get_byte(5, B0)] ^
              C6[get_byte(6, B7)] ^ C7[get_byte(7, B6)] ^ K5;
         T6 = C0[get_byte(0, B6)] ^ C1[get_byte(1, B5)] ^
              C2[get_byte(2, B4)] ^ C3[get_byte(3, B3)] ^
              C4[get_byte(4, B2)] ^ C5[get_byte(5, B1)] ^
              C6[get_byte(6, B0)] ^ C7[get_byte(7, B7)] ^ K6;
         T7 = C0[get_byte(0, B7)] ^ C1[get_byte(1, B6)] ^
              C2[get_byte(2, B5)] ^ C3[get_byte(3, B4)] ^
              C4[get_byte(4, B3)] ^ C5[get_byte(5, B2)] ^
              C6[get_byte(6, B1)] ^ C7[get_byte(7, B0)] ^ K7;

         B0 = T0; B1 = T1; B2 = T2; B3 = T3;
         B4 = T4; B5 = T5; B6 = T6; B7 = T7;
         }

      m_digest[0] ^= B0 ^ m_M[0];
      m_digest[1] ^= B1 ^ m_M[1];
      m_digest[2] ^= B2 ^ m_M[2];
      m_digest[3] ^= B3 ^ m_M[3];
      m_digest[4] ^= B4 ^ m_M[4];
      m_digest[5] ^= B5 ^ m_M[5];
      m_digest[6] ^= B6 ^ m_M[6];
      m_digest[7] ^= B7 ^ m_M[7];

      in += hash_block_size();
      }
   }

/*
* Copy out the digest
*/
void Whirlpool::copy_out(uint8_t output[])
   {
   copy_out_vec_be(output, output_length(), m_digest);
   }

/*
* Clear memory of sensitive data
*/
void Whirlpool::clear()
   {
   MDx_HashFunction::clear();
   zeroise(m_M);
   zeroise(m_digest);
   }

}
