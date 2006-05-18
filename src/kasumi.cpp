/*************************************************
* KASUMI Source File                             *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/kasumi.h>
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
   u16bit B0 = make_u16bit(in[0], in[1]), B1 = make_u16bit(in[2], in[3]),
          B2 = make_u16bit(in[4], in[5]), B3 = make_u16bit(in[6], in[7]);

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

   out[0] = get_byte(0, B0); out[1] = get_byte(1, B0);
   out[2] = get_byte(0, B1); out[3] = get_byte(1, B1);
   out[4] = get_byte(0, B2); out[5] = get_byte(1, B2);
   out[6] = get_byte(0, B3); out[7] = get_byte(1, B3);
   }

/*************************************************
* KASUMI Decryption                              *
*************************************************/
void KASUMI::dec(const byte in[], byte out[]) const
   {
   u16bit B0 = make_u16bit(in[0], in[1]), B1 = make_u16bit(in[2], in[3]),
          B2 = make_u16bit(in[4], in[5]), B3 = make_u16bit(in[6], in[7]);

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

   out[0] = get_byte(0, B0); out[1] = get_byte(1, B0);
   out[2] = get_byte(0, B1); out[3] = get_byte(1, B1);
   out[4] = get_byte(0, B2); out[5] = get_byte(1, B2);
   out[6] = get_byte(0, B3); out[7] = get_byte(1, B3);
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
      K[j] = make_u16bit(key[2*j], key[2*j+1]);
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
