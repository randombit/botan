/*
* Camellia
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/camellia.h>
#include <botan/loadstor.h>

namespace Botan {

namespace Camellia_F {

u64bit F(u64bit v, u64bit K)
   {
   static const byte SBOX[256] = {
      0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5, 0xE4, 0x85, 0x57,
      0x35, 0xEA, 0x0C, 0xAE, 0x41, 0x23, 0xEF, 0x6B, 0x93, 0x45, 0x19,
      0xA5, 0x21, 0xED, 0x0E, 0x4F, 0x4E, 0x1D, 0x65, 0x92, 0xBD, 0x86,
      0xB8, 0xAF, 0x8F, 0x7C, 0xEB, 0x1F, 0xCE, 0x3E, 0x30, 0xDC, 0x5F,
      0x5E, 0xC5, 0x0B, 0x1A, 0xA6, 0xE1, 0x39, 0xCA, 0xD5, 0x47, 0x5D,
      0x3D, 0xD9, 0x01, 0x5A, 0xD6, 0x51, 0x56, 0x6C, 0x4D, 0x8B, 0x0D,
      0x9A, 0x66, 0xFB, 0xCC, 0xB0, 0x2D, 0x74, 0x12, 0x2B, 0x20, 0xF0,
      0xB1, 0x84, 0x99, 0xDF, 0x4C, 0xCB, 0xC2, 0x34, 0x7E, 0x76, 0x05,
      0x6D, 0xB7, 0xA9, 0x31, 0xD1, 0x17, 0x04, 0xD7, 0x14, 0x58, 0x3A,
      0x61, 0xDE, 0x1B, 0x11, 0x1C, 0x32, 0x0F, 0x9C, 0x16, 0x53, 0x18,
      0xF2, 0x22, 0xFE, 0x44, 0xCF, 0xB2, 0xC3, 0xB5, 0x7A, 0x91, 0x24,
      0x08, 0xE8, 0xA8, 0x60, 0xFC, 0x69, 0x50, 0xAA, 0xD0, 0xA0, 0x7D,
      0xA1, 0x89, 0x62, 0x97, 0x54, 0x5B, 0x1E, 0x95, 0xE0, 0xFF, 0x64,
      0xD2, 0x10, 0xC4, 0x00, 0x48, 0xA3, 0xF7, 0x75, 0xDB, 0x8A, 0x03,
      0xE6, 0xDA, 0x09, 0x3F, 0xDD, 0x94, 0x87, 0x5C, 0x83, 0x02, 0xCD,
      0x4A, 0x90, 0x33, 0x73, 0x67, 0xF6, 0xF3, 0x9D, 0x7F, 0xBF, 0xE2,
      0x52, 0x9B, 0xD8, 0x26, 0xC8, 0x37, 0xC6, 0x3B, 0x81, 0x96, 0x6F,
      0x4B, 0x13, 0xBE, 0x63, 0x2E, 0xE9, 0x79, 0xA7, 0x8C, 0x9F, 0x6E,
      0xBC, 0x8E, 0x29, 0xF5, 0xF9, 0xB6, 0x2F, 0xFD, 0xB4, 0x59, 0x78,
      0x98, 0x06, 0x6A, 0xE7, 0x46, 0x71, 0xBA, 0xD4, 0x25, 0xAB, 0x42,
      0x88, 0xA2, 0x8D, 0xFA, 0x72, 0x07, 0xB9, 0x55, 0xF8, 0xEE, 0xAC,
      0x0A, 0x36, 0x49, 0x2A, 0x68, 0x3C, 0x38, 0xF1, 0xA4, 0x40, 0x28,
      0xD3, 0x7B, 0xBB, 0xC9, 0x43, 0xC1, 0x15, 0xE3, 0xAD, 0xF4, 0x77,
      0xC7, 0x80, 0x9E };

   const u64bit x = v ^ K;

   const byte t1 = SBOX[get_byte(0, x)];
   const byte t2 = rotate_left(SBOX[get_byte(1, x)], 1);
   const byte t3 = rotate_left(SBOX[get_byte(2, x)], 7);
   const byte t4 = SBOX[rotate_left(get_byte(3, x), 1)];
   const byte t5 = rotate_left(SBOX[get_byte(4, x)], 1);
   const byte t6 = rotate_left(SBOX[get_byte(5, x)], 7);
   const byte t7 = SBOX[rotate_left(get_byte(6, x), 1)];
   const byte t8 = SBOX[get_byte(7, x)];

   const byte y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
   const byte y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
   const byte y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
   const byte y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
   const byte y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
   const byte y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
   const byte y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
   const byte y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

   return make_u64bit(y1, y2, y3, y4, y5, y6, y7, y8);
   }

u64bit FL(u64bit v, u64bit K)
   {
   u32bit x1 = (v >> 32);
   u32bit x2 = (v & 0xFFFFFFFF);

   const u32bit k1 = (K >> 32);
   const u32bit k2 = (K & 0xFFFFFFFF);

   x2 ^= rotate_left(x1 & k1, 1);
   x1 ^= (x2 | k2);

   return ((static_cast<u64bit>(x1) << 32) | x2);
   }

u64bit FLINV(u64bit v, u64bit K)
   {
   u32bit x1 = (v >> 32);
   u32bit x2 = (v & 0xFFFFFFFF);

   const u32bit k1 = (K >> 32);
   const u32bit k2 = (K & 0xFFFFFFFF);

   x1 ^= (x2 | k2);
   x2 ^= rotate_left(x1 & k1, 1);

   return ((static_cast<u64bit>(x1) << 32) | x2);
   }

u64bit left_rot_hi(u64bit h, u64bit l, size_t shift)
   {
   return (h << shift) | ((l >> (64-shift)));
   }

u64bit left_rot_lo(u64bit h, u64bit l, size_t shift)
   {
   return (h >> (64-shift)) | (l << shift);
   }

}

/*
* Camellia Encryption
*/
void Camellia::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   using namespace Camellia_F;

   for(size_t i = 0; i != blocks; ++i)
      {
      u64bit D1 = load_be<u64bit>(in, 0);
      u64bit D2 = load_be<u64bit>(in, 1);

      D1 ^= K[0];
      D2 ^= K[1];
      D2 ^= F(D1, K[2]);
      D1 ^= F(D2, K[3]);
      D2 ^= F(D1, K[4]);
      D1 ^= F(D2, K[5]);
      D2 ^= F(D1, K[6]);
      D1 ^= F(D2, K[7]);
      D1 = FL   (D1, K[8]);
      D2 = FLINV(D2, K[9]);

      D2 ^= F(D1, K[10]);
      D1 ^= F(D2, K[11]);
      D2 ^= F(D1, K[12]);
      D1 ^= F(D2, K[13]);
      D2 ^= F(D1, K[14]);
      D1 ^= F(D2, K[15]);
      D1 = FL   (D1, K[16]);
      D2 = FLINV(D2, K[17]);

      D2 ^= F(D1, K[18]);
      D1 ^= F(D2, K[19]);
      D2 ^= F(D1, K[20]);
      D1 ^= F(D2, K[21]);
      D2 ^= F(D1, K[22]);
      D1 ^= F(D2, K[23]);

      if(K.size() == 34)
         {
         D1 = FL   (D1, K[24]);
         D2 = FLINV(D2, K[25]);
         D2 ^= F(D1, K[26]);
         D1 ^= F(D2, K[27]);
         D2 ^= F(D1, K[28]);
         D1 ^= F(D2, K[29]);
         D2 ^= F(D1, K[30]);
         D1 ^= F(D2, K[31]);
         D2 ^= K[32];
         D1 ^= K[33];
         }
      else
         {
         D2 ^= K[24];
         D1 ^= K[25];
         }

      store_be(out, D2, D1);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Camellia Decryption
*/
void Camellia::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   using namespace Camellia_F;

   for(size_t i = 0; i != blocks; ++i)
      {
      u64bit D1 = load_be<u64bit>(in, 0);
      u64bit D2 = load_be<u64bit>(in, 1);

      if(K.size() == 34)
         {
         D1 ^= K[32];
         D2 ^= K[33];

         D2 ^= F(D1, K[31]);
         D1 ^= F(D2, K[30]);
         D2 ^= F(D1, K[29]);
         D1 ^= F(D2, K[28]);
         D2 ^= F(D1, K[27]);
         D1 ^= F(D2, K[26]);
         D1 = FL   (D1, K[25]);
         D2 = FLINV(D2, K[24]);
         }
      else
         {
         D1 ^= K[24];
         D2 ^= K[25];
         }

      D2 ^= F(D1, K[23]);
      D1 ^= F(D2, K[22]);
      D2 ^= F(D1, K[21]);
      D1 ^= F(D2, K[20]);
      D2 ^= F(D1, K[19]);
      D1 ^= F(D2, K[18]);
      D1 = FL   (D1, K[17]);
      D2 = FLINV(D2, K[16]);

      D2 ^= F(D1, K[15]);
      D1 ^= F(D2, K[14]);
      D2 ^= F(D1, K[13]);
      D1 ^= F(D2, K[12]);
      D2 ^= F(D1, K[11]);
      D1 ^= F(D2, K[10]);
      D1 = FL   (D1, K[ 9]);
      D2 = FLINV(D2, K[ 8]);

      D2 ^= F(D1, K[ 7]);
      D1 ^= F(D2, K[ 6]);
      D2 ^= F(D1, K[ 5]);
      D1 ^= F(D2, K[ 4]);
      D2 ^= F(D1, K[ 3]);
      D1 ^= F(D2, K[ 2]);
      D2 ^= K[0];
      D1 ^= K[1];

      store_be(out, D2, D1);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Camellia Key Schedule
*/
void Camellia::key_schedule(const byte key[], size_t length)
   {
   using namespace Camellia_F;

   const u64bit Sigma1 = 0xA09E667F3BCC908B;
   const u64bit Sigma2 = 0xB67AE8584CAA73B2;
   const u64bit Sigma3 = 0xC6EF372FE94F82BE;
   const u64bit Sigma4 = 0x54FF53A5F1D36F1C;
   const u64bit Sigma5 = 0x10E527FADE682D1D;
   const u64bit Sigma6 = 0xB05688C2B3E6C1FD;

   const u64bit KL_H = load_be<u64bit>(key, 0);
   const u64bit KL_L = load_be<u64bit>(key, 1);

   const u64bit KR_H = (length >= 24) ? load_be<u64bit>(key, 2) : 0;
   const u64bit KR_L =
      (length == 32) ? load_be<u64bit>(key, 3) : ((length == 24) ? ~KR_H : 0);

   u64bit D1 = KL_H ^ KR_H;
   u64bit D2 = KL_L ^ KR_L;
   D2 ^= F(D1, Sigma1);
   D1 ^= F(D2, Sigma2);
   D1 ^= KL_H;
   D2 ^= KL_L;
   D2 ^= F(D1, Sigma3);
   D1 ^= F(D2, Sigma4);

   const u64bit KA_H = D1;
   const u64bit KA_L = D2;

   D1 = KA_H ^ KR_H;
   D2 = KA_L ^ KR_L;
   D2 ^= F(D1, Sigma5);
   D1 ^= F(D2, Sigma6);

   const u64bit KB_H = D1;
   const u64bit KB_L = D2;

   if(length == 16)
      {
      K.resize(26);

      K[ 0] = KL_H;
      K[ 1] = KL_L;
      K[ 2] = KA_H;
      K[ 3] = KA_L;
      K[ 4] = left_rot_hi(KL_H, KL_L, 15);
      K[ 5] = left_rot_lo(KL_H, KL_L, 15);
      K[ 6] = left_rot_hi(KA_H, KA_L, 15);
      K[ 7] = left_rot_lo(KA_H, KA_L, 15);
      K[ 8] = left_rot_hi(KA_H, KA_L, 30);
      K[ 9] = left_rot_lo(KA_H, KA_L, 30);
      K[10] = left_rot_hi(KL_H, KL_L, 45);
      K[11] = left_rot_lo(KL_H, KL_L, 45);
      K[12] = left_rot_hi(KA_H, KA_L,  45);
      K[13] = left_rot_lo(KL_H, KL_L,  60);
      K[14] = left_rot_hi(KA_H, KA_L,  60);
      K[15] = left_rot_lo(KA_H, KA_L,  60);
      K[16] = left_rot_lo(KL_H, KL_L,  77-64);
      K[17] = left_rot_hi(KL_H, KL_L,  77-64);
      K[18] = left_rot_lo(KL_H, KL_L,  94-64);
      K[19] = left_rot_hi(KL_H, KL_L,  94-64);
      K[20] = left_rot_lo(KA_H, KA_L,  94-64);
      K[21] = left_rot_hi(KA_H, KA_L,  94-64);
      K[22] = left_rot_lo(KL_H, KL_L, 111-64);
      K[23] = left_rot_hi(KL_H, KL_L, 111-64);
      K[24] = left_rot_lo(KA_H, KA_L, 111-64);
      K[25] = left_rot_hi(KA_H, KA_L, 111-64);
      }
   else
      {
      K.resize(34);

      K[ 0] = KL_H;
      K[ 1] = KL_L;
      K[ 2] = KB_H;
      K[ 3] = KB_L;

      K[ 4] = left_rot_hi(KR_H, KR_L, 15);
      K[ 5] = left_rot_lo(KR_H, KR_L, 15);
      K[ 6] = left_rot_hi(KA_H, KA_L, 15);
      K[ 7] = left_rot_lo(KA_H, KA_L, 15);

      K[ 8] = left_rot_hi(KR_H, KR_L, 30);
      K[ 9] = left_rot_lo(KR_H, KR_L, 30);
      K[10] = left_rot_hi(KB_H, KB_L, 30);
      K[11] = left_rot_lo(KB_H, KB_L, 30);

      K[12] = left_rot_hi(KL_H, KL_L, 45);
      K[13] = left_rot_lo(KL_H, KL_L, 45);
      K[14] = left_rot_hi(KA_H, KA_L, 45);
      K[15] = left_rot_lo(KA_H, KA_L, 45);

      K[16] = left_rot_hi(KL_H, KL_L, 60);
      K[17] = left_rot_lo(KL_H, KL_L, 60);
      K[18] = left_rot_hi(KR_H, KR_L, 60);
      K[19] = left_rot_lo(KR_H, KR_L, 60);
      K[20] = left_rot_hi(KB_H, KB_L, 60);
      K[21] = left_rot_lo(KB_H, KB_L, 60);

      K[22] = left_rot_lo(KL_H, KL_L,  77-64);
      K[23] = left_rot_hi(KL_H, KL_L,  77-64);
      K[24] = left_rot_lo(KA_H, KA_L,  77-64);
      K[25] = left_rot_hi(KA_H, KA_L,  77-64);

      K[26] = left_rot_lo(KR_H, KR_L,  94-64);
      K[27] = left_rot_hi(KR_H, KR_L,  94-64);
      K[28] = left_rot_lo(KA_H, KA_L,  94-64);
      K[29] = left_rot_hi(KA_H, KA_L,  94-64);
      K[30] = left_rot_lo(KL_H, KL_L, 111-64);
      K[31] = left_rot_hi(KL_H, KL_L, 111-64);
      K[32] = left_rot_lo(KB_H, KB_L, 111-64);
      K[33] = left_rot_hi(KB_H, KB_L, 111-64);
      }
   }

}
