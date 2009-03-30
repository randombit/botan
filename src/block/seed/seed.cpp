/*
* SEED
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/seed.h>
#include <botan/loadstor.h>

namespace Botan {

/*
* SEED G Function
*/
u32bit SEED::G_FUNC::operator()(u32bit X) const
   {
   return (S0[get_byte(3, X)] ^ S1[get_byte(2, X)] ^
           S2[get_byte(1, X)] ^ S3[get_byte(0, X)]);
   }

/*
* SEED Encryption
*/
void SEED::enc(const byte in[], byte out[]) const
   {
   u32bit B0 = load_be<u32bit>(in, 0);
   u32bit B1 = load_be<u32bit>(in, 1);
   u32bit B2 = load_be<u32bit>(in, 2);
   u32bit B3 = load_be<u32bit>(in, 3);

   G_FUNC G;

   for(u32bit j = 0; j != 16; j += 2)
      {
      u32bit T0, T1;

      T0 = B2 ^ K[2*j];
      T1 = G(B2 ^ B3 ^ K[2*j+1]);
      T0 = G(T1 + T0);
      T1 = G(T1 + T0);
      B1 ^= T1;
      B0 ^= T0 + T1;

      T0 = B0 ^ K[2*j+2];
      T1 = G(B0 ^ B1 ^ K[2*j+3]);
      T0 = G(T1 + T0);
      T1 = G(T1 + T0);
      B3 ^= T1;
      B2 ^= T0 + T1;
      }

   store_be(out, B2, B3, B0, B1);
   }

/*
* SEED Decryption
*/
void SEED::dec(const byte in[], byte out[]) const
   {
   u32bit B0 = load_be<u32bit>(in, 0);
   u32bit B1 = load_be<u32bit>(in, 1);
   u32bit B2 = load_be<u32bit>(in, 2);
   u32bit B3 = load_be<u32bit>(in, 3);

   G_FUNC G;

   for(u32bit j = 0; j != 16; j += 2)
      {
      u32bit T0, T1;

      T0 = B2 ^ K[30-2*j];
      T1 = G(B2 ^ B3 ^ K[31-2*j]);
      T0 = G(T1 + T0);
      T1 = G(T1 + T0);
      B1 ^= T1;
      B0 ^= T0 + T1;

      T0 = B0 ^ K[28-2*j];
      T1 = G(B0 ^ B1 ^ K[29-2*j]);
      T0 = G(T1 + T0);
      T1 = G(T1 + T0);
      B3 ^= T1;
      B2 ^= T0 + T1;
      }

   store_be(out, B2, B3, B0, B1);
   }

/*
* SEED Key Schedule
*/
void SEED::key_schedule(const byte key[], u32bit)
   {
   const u32bit RC[16] = {
      0x9E3779B9, 0x3C6EF373, 0x78DDE6E6, 0xF1BBCDCC,
      0xE3779B99, 0xC6EF3733, 0x8DDE6E67, 0x1BBCDCCF,
      0x3779B99E, 0x6EF3733C, 0xDDE6E678, 0xBBCDCCF1,
      0x779B99E3, 0xEF3733C6, 0xDE6E678D, 0xBCDCCF1B
   };

   SecureBuffer<u32bit, 4> WK;

   for(u32bit j = 0; j != 4; ++j)
      WK[j] = load_be<u32bit>(key, j);

   G_FUNC G;

   for(u32bit j = 0; j != 16; j += 2)
      {
      K[2*j  ] = G(WK[0] + WK[2] - RC[j]);
      K[2*j+1] = G(WK[1] - WK[3] + RC[j]) ^ K[2*j];

      byte T = get_byte(3, WK[0]);
      WK[0] = (WK[0] >> 8) | (get_byte(3, WK[1]) << 24);
      WK[1] = (WK[1] >> 8) | (T << 24);

      K[2*j+2] = G(WK[0] + WK[2] - RC[j+1]);
      K[2*j+3] = G(WK[1] - WK[3] + RC[j+1]) ^ K[2*j+2];

      T = get_byte(0, WK[3]);
      WK[3] = (WK[3] << 8) | get_byte(0, WK[2]);
      WK[2] = (WK[2] << 8) | T;
      }
   }

}
