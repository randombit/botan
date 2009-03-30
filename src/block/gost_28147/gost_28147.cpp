/*
* GOST 28147-89
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/gost_28147.h>
#include <botan/loadstor.h>

namespace Botan {

/*
* GOST Constructor
*/
GOST_28147_89::GOST_28147_89() : BlockCipher(8, 32)
   {

   // GostR3411_94_TestParamSet (OID 1.2.643.2.2.31.0)
   const byte sbox[8][16] = {
      {0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3},
      {0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9},
      {0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB},
      {0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3},
      {0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2},
      {0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE},
      {0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC},
      {0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC},
   };

   for(size_t i = 0; i != 4; ++i)
      for(size_t j = 0; j != 256; ++j)
         {
         u32bit T = sbox[2*i][j%16] | (sbox[2*i+1][j/16] << 4);
         SBOX[256*i+j] = rotate_left(T, (11+8*i) % 32);
         }
   }

/*
* GOST Encryption
*/
void GOST_28147_89::enc(const byte in[], byte out[]) const
   {
   u32bit N1 = load_le<u32bit>(in, 0), N2 = load_le<u32bit>(in, 1);

   for(u32bit j = 0; j != 32; j += 2)
      {
      u32bit T0;

      T0 = N1 + EK[j];
      N2 ^= SBOX[get_byte(3, T0)] |
            SBOX[get_byte(2, T0)+256] |
            SBOX[get_byte(1, T0)+512] |
            SBOX[get_byte(0, T0)+768];

      T0 = N2 + EK[j+1];
      N1 ^= SBOX[get_byte(3, T0)] |
            SBOX[get_byte(2, T0)+256] |
            SBOX[get_byte(1, T0)+512] |
            SBOX[get_byte(0, T0)+768];
      }

   store_le(out, N2, N1);
   }

/*
* GOST Decryption
*/
void GOST_28147_89::dec(const byte in[], byte out[]) const
   {
   u32bit N1 = load_le<u32bit>(in, 0), N2 = load_le<u32bit>(in, 1);

   for(u32bit j = 0; j != 32; j += 2)
      {
      u32bit T0;

      T0 = N1 + EK[31-j];
      N2 ^= SBOX[get_byte(3, T0)] |
            SBOX[get_byte(2, T0)+256] |
            SBOX[get_byte(1, T0)+512] |
            SBOX[get_byte(0, T0)+768];

      T0 = N2 + EK[30-j];
      N1 ^= SBOX[get_byte(3, T0)] |
            SBOX[get_byte(2, T0)+256] |
            SBOX[get_byte(1, T0)+512] |
            SBOX[get_byte(0, T0)+768];
      }

   store_le(out, N2, N1);
   }

/*
* GOST Key Schedule
*/
void GOST_28147_89::key_schedule(const byte key[], u32bit)
   {
   for(u32bit j = 0; j != 8; ++j)
      {
      u32bit K = load_le<u32bit>(key, j);
      EK[j] = EK[j+8] = EK[j+16] = K;
      }

   for(u32bit j = 24; j != 32; ++j)
      EK[j] = EK[7-(j-24)];
   }

}
