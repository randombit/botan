/*************************************************
* KASUMI Source File                             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/kasumi.h>
#include <botan/loadstor.h>
#include <botan/bit_ops.h>

namespace Botan {

namespace {

/*************************************************
* KASUMI FI Function                             *
*************************************************/
u16bit FI(u16bit I, u16bit K)
   {
   u16bit D9 = (I >> 7);
   byte D7 = (I & 0x7F);
   D9 = KASUMI_SBOX_S9[D9] ^ D7;
   D7 = KASUMI_SBOX_S7[D7] ^ (D9 & 0x7F);

   D7 ^= (K >> 9);
   D9 = KASUMI_SBOX_S9[D9 ^ (K & 0x1FF)] ^ D7;
   D7 = KASUMI_SBOX_S7[D7] ^ (D9 & 0x7F);
   return (D7 << 9) | D9;
   }

}

/*************************************************
* KASUMI Encryption                              *
*************************************************/
void KASUMI::enc(const byte in[], byte out[]) const
   {
   u16bit B0 = load_be<u16bit>(in, 0);
   u16bit B1 = load_be<u16bit>(in, 1);
   u16bit B2 = load_be<u16bit>(in, 2);
   u16bit B3 = load_be<u16bit>(in, 3);

   for(u32bit j = 0; j != 8; j += 2)
      {
      const u16bit* K = EK + 8*j;

      u16bit R = B1 ^ (rotate_left(B0, 1) & K[0]);
      u16bit L = B0 ^ (rotate_left(R, 1) | K[1]);

      L = FI(L ^ K[ 2], K[ 3]) ^ R;
      R = FI(R ^ K[ 4], K[ 5]) ^ L;
      L = FI(L ^ K[ 6], K[ 7]) ^ R;

      R = B2 ^= R;
      L = B3 ^= L;

      R = FI(R ^ K[10], K[11]) ^ L;
      L = FI(L ^ K[12], K[13]) ^ R;
      R = FI(R ^ K[14], K[15]) ^ L;

      R ^= (rotate_left(L, 1) & K[8]);
      L ^= (rotate_left(R, 1) | K[9]);

      B0 ^= L;
      B1 ^= R;
      }

   store_be(out, B0, B1, B2, B3);
   }

/*************************************************
* KASUMI Decryption                              *
*************************************************/
void KASUMI::dec(const byte in[], byte out[]) const
   {
   u16bit B0 = load_be<u16bit>(in, 0);
   u16bit B1 = load_be<u16bit>(in, 1);
   u16bit B2 = load_be<u16bit>(in, 2);
   u16bit B3 = load_be<u16bit>(in, 3);

   for(u32bit j = 0; j != 8; j += 2)
      {
      const u16bit* K = EK + 8*(6-j);

      u16bit L = B2, R = B3;

      L = FI(L ^ K[10], K[11]) ^ R;
      R = FI(R ^ K[12], K[13]) ^ L;
      L = FI(L ^ K[14], K[15]) ^ R;

      L ^= (rotate_left(R, 1) & K[8]);
      R ^= (rotate_left(L, 1) | K[9]);

      R = B0 ^= R;
      L = B1 ^= L;

      L ^= (rotate_left(R, 1) & K[0]);
      R ^= (rotate_left(L, 1) | K[1]);

      R = FI(R ^ K[2], K[3]) ^ L;
      L = FI(L ^ K[4], K[5]) ^ R;
      R = FI(R ^ K[6], K[7]) ^ L;

      B2 ^= L;
      B3 ^= R;
      }

   store_be(out, B0, B1, B2, B3);
   }

/*************************************************
* KASUMI Key Schedule                            *
*************************************************/
void KASUMI::key(const byte key[], u32bit)
   {
   static const u16bit RC[] = { 0x0123, 0x4567, 0x89AB, 0xCDEF,
                                0xFEDC, 0xBA98, 0x7654, 0x3210 };

   SecureBuffer<u16bit, 16> K;
   for(u32bit j = 0; j != 8; ++j)
      {
      K[j] = load_be<u16bit>(key, j);
      K[j+8] = K[j] ^ RC[j];
      }

   for(u32bit j = 0; j != 8; ++j)
      {
      EK[8*j  ] = rotate_left(K[(j+0) % 8    ], 2);
      EK[8*j+1] = rotate_left(K[(j+2) % 8 + 8], 1);
      EK[8*j+2] = rotate_left(K[(j+1) % 8    ], 5);
      EK[8*j+3] = K[(j+4) % 8 + 8];
      EK[8*j+4] = rotate_left(K[(j+5) % 8    ], 8);
      EK[8*j+5] = K[(j+3) % 8 + 8];
      EK[8*j+6] = rotate_left(K[(j+6) % 8    ], 13);
      EK[8*j+7] = K[(j+7) % 8 + 8];
      }
   }

}
