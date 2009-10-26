/*
* XTEA SSE2
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/xtea_sse2.h>
#include <botan/loadstor.h>
#include <botan/simd_32.h>

namespace Botan {

namespace {

void xtea_encrypt_8(const byte in[64], byte out[64], const u32bit EK[64])
   {
   SIMD_32 L0 = SIMD_32::load_be(in     );
   SIMD_32 R0 = SIMD_32::load_be(in + 16);
   SIMD_32 L1 = SIMD_32::load_be(in + 32);
   SIMD_32 R1 = SIMD_32::load_be(in + 48);

   SIMD_32::transpose(L0, R0, L1, R1);

   for(u32bit i = 0; i != 32; i += 2)
      {
      SIMD_32 K0(EK[2*i]), K1(EK[2*i+1]), K2(EK[2*i+2]), K3(EK[2*i+3]);

      L0 += (((R0 << 4) ^ (R0 >> 5)) + R0) ^ K0;
      L1 += (((R1 << 4) ^ (R1 >> 5)) + R1) ^ K0;

      R0 += (((L0 << 4) ^ (L0 >> 5)) + L0) ^ K1;
      R1 += (((L1 << 4) ^ (L1 >> 5)) + L1) ^ K1;

      L0 += (((R0 << 4) ^ (R0 >> 5)) + R0) ^ K2;
      L1 += (((R1 << 4) ^ (R1 >> 5)) + R1) ^ K2;

      R0 += (((L0 << 4) ^ (L0 >> 5)) + L0) ^ K3;
      R1 += (((L1 << 4) ^ (L1 >> 5)) + L1) ^ K3;
      }

   SIMD_32::transpose(L0, R0, L1, R1);

   L0.store_be(out);
   R0.store_be(out + 16);
   L1.store_be(out + 32);
   R1.store_be(out + 48);
   }

}

/*
* XTEA Encryption
*/
void XTEA_SSE2::encrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   memset(out, 0, blocks * BLOCK_SIZE);

   while(blocks >= 8)
      {
      xtea_encrypt_8(in, out, this->EK);
      in += 8 * BLOCK_SIZE;
      out += 8 * BLOCK_SIZE;
      blocks -= 8;
      }

   XTEA::encrypt_n(in, out, blocks);
   }

/*
* XTEA Decryption
*/
void XTEA_SSE2::decrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
#if 0
   while(blocks >= 4)
      {
      xtea_decrypt_4(in, out, this->EK);
      in += 4 * BLOCK_SIZE;
      out += 4 * BLOCK_SIZE;
      blocks -= 4;
      }
#endif

   XTEA::decrypt_n(in, out, blocks);
   }

}
