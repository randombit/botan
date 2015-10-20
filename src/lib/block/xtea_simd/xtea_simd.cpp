/*
* XTEA in SIMD
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/xtea_simd.h>
#include <botan/internal/simd_32.h>

namespace Botan {

namespace {

void xtea_encrypt_8(const byte in[64], byte out[64], const u32bit EK[64])
   {
   SIMD_32 L0 = SIMD_32::load_be(in     );
   SIMD_32 R0 = SIMD_32::load_be(in + 16);
   SIMD_32 L1 = SIMD_32::load_be(in + 32);
   SIMD_32 R1 = SIMD_32::load_be(in + 48);

   SIMD_32::transpose(L0, R0, L1, R1);

   for(size_t i = 0; i != 32; i += 2)
      {
      SIMD_32 K0(EK[2*i  ]);
      SIMD_32 K1(EK[2*i+1]);
      SIMD_32 K2(EK[2*i+2]);
      SIMD_32 K3(EK[2*i+3]);

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

void xtea_decrypt_8(const byte in[64], byte out[64], const u32bit EK[64])
   {
   SIMD_32 L0 = SIMD_32::load_be(in     );
   SIMD_32 R0 = SIMD_32::load_be(in + 16);
   SIMD_32 L1 = SIMD_32::load_be(in + 32);
   SIMD_32 R1 = SIMD_32::load_be(in + 48);

   SIMD_32::transpose(L0, R0, L1, R1);

   for(size_t i = 0; i != 32; i += 2)
      {
      SIMD_32 K0(EK[63 - 2*i]);
      SIMD_32 K1(EK[62 - 2*i]);
      SIMD_32 K2(EK[61 - 2*i]);
      SIMD_32 K3(EK[60 - 2*i]);

      R0 -= (((L0 << 4) ^ (L0 >> 5)) + L0) ^ K0;
      R1 -= (((L1 << 4) ^ (L1 >> 5)) + L1) ^ K0;

      L0 -= (((R0 << 4) ^ (R0 >> 5)) + R0) ^ K1;
      L1 -= (((R1 << 4) ^ (R1 >> 5)) + R1) ^ K1;

      R0 -= (((L0 << 4) ^ (L0 >> 5)) + L0) ^ K2;
      R1 -= (((L1 << 4) ^ (L1 >> 5)) + L1) ^ K2;

      L0 -= (((R0 << 4) ^ (R0 >> 5)) + R0) ^ K3;
      L1 -= (((R1 << 4) ^ (R1 >> 5)) + R1) ^ K3;
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
void XTEA_SIMD::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const u32bit* KS = &(this->get_EK()[0]);

   while(blocks >= 8)
      {
      xtea_encrypt_8(in, out, KS);
      in += 8 * BLOCK_SIZE;
      out += 8 * BLOCK_SIZE;
      blocks -= 8;
      }

   if(blocks)
     XTEA::encrypt_n(in, out, blocks);
   }

/*
* XTEA Decryption
*/
void XTEA_SIMD::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const u32bit* KS = &(this->get_EK()[0]);

   while(blocks >= 8)
      {
      xtea_decrypt_8(in, out, KS);
      in += 8 * BLOCK_SIZE;
      out += 8 * BLOCK_SIZE;
      blocks -= 8;
      }

   if(blocks)
     XTEA::decrypt_n(in, out, blocks);
   }

}
