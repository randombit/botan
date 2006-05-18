/*************************************************
* SEED Source File                               *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/seed.h>
#include <botan/bit_ops.h>

namespace Botan {

/*************************************************
* SEED G Function                                *
*************************************************/
u32bit SEED::G_FUNC::operator()(u32bit X) const
   {
   return (S0[get_byte(3, X)] ^ S1[get_byte(2, X)] ^
           S2[get_byte(1, X)] ^ S3[get_byte(0, X)]);
   }


/*************************************************
* SEED Encryption                                *
*************************************************/
void SEED::enc(const byte in[], byte out[]) const
   {
   u32bit B0 = make_u32bit(in[ 0], in[ 1], in[ 2], in[ 3]),
          B1 = make_u32bit(in[ 4], in[ 5], in[ 6], in[ 7]),
          B2 = make_u32bit(in[ 8], in[ 9], in[10], in[11]),
          B3 = make_u32bit(in[12], in[13], in[14], in[15]);

   G_FUNC G;

   for(u32bit j = 0; j != 16; j += 2)
      {
      u32bit T0, T1;

      T0 = B2 ^ K[2*j];
      T1 = G(T0 ^ B3 ^ K[2*j+1]);
      T0 = G(T1 + T0);
      B1 ^= (T1 = G(T1 + T0));

      T0 = (B0 ^= T0 + T1) ^ K[2*j+2];
      T1 = G(T0 ^ B1 ^ K[2*j+3]);
      T0 = G(T1 + T0);
      B3 ^= (T1 = G(T1 + T0));
      B2 ^= T0 + T1;
      }

   out[ 0] = get_byte(0, B2); out[ 1] = get_byte(1, B2);
   out[ 2] = get_byte(2, B2); out[ 3] = get_byte(3, B2);
   out[ 4] = get_byte(0, B3); out[ 5] = get_byte(1, B3);
   out[ 6] = get_byte(2, B3); out[ 7] = get_byte(3, B3);
   out[ 8] = get_byte(0, B0); out[ 9] = get_byte(1, B0);
   out[10] = get_byte(2, B0); out[11] = get_byte(3, B0);
   out[12] = get_byte(0, B1); out[13] = get_byte(1, B1);
   out[14] = get_byte(2, B1); out[15] = get_byte(3, B1);
   }

/*************************************************
* SEED Decryption                                *
*************************************************/
void SEED::dec(const byte in[], byte out[]) const
   {
   u32bit B0 = make_u32bit(in[ 0], in[ 1], in[ 2], in[ 3]),
          B1 = make_u32bit(in[ 4], in[ 5], in[ 6], in[ 7]),
          B2 = make_u32bit(in[ 8], in[ 9], in[10], in[11]),
          B3 = make_u32bit(in[12], in[13], in[14], in[15]);

   G_FUNC G;

   for(u32bit j = 0; j != 16; j += 2)
      {
      u32bit T0, T1;

      T0 = B2 ^ K[30-2*j];
      T1 = G(T0 ^ B3 ^ K[31-2*j]);
      T0 = G(T1 + T0);
      B1 ^= (T1 = G(T1 + T0));

      T0 = (B0 ^= T0 + T1) ^ K[28-2*j];
      T1 = G(T0 ^ B1 ^ K[29-2*j]);
      T0 = G(T1 + T0);
      B3 ^= (T1 = G(T1 + T0));
      B2 ^= T0 + T1;
      }

   out[ 0] = get_byte(0, B2); out[ 1] = get_byte(1, B2);
   out[ 2] = get_byte(2, B2); out[ 3] = get_byte(3, B2);
   out[ 4] = get_byte(0, B3); out[ 5] = get_byte(1, B3);
   out[ 6] = get_byte(2, B3); out[ 7] = get_byte(3, B3);
   out[ 8] = get_byte(0, B0); out[ 9] = get_byte(1, B0);
   out[10] = get_byte(2, B0); out[11] = get_byte(3, B0);
   out[12] = get_byte(0, B1); out[13] = get_byte(1, B1);
   out[14] = get_byte(2, B1); out[15] = get_byte(3, B1);
   }

/*************************************************
* SEED Key Schedule                              *
*************************************************/
void SEED::key(const byte key[], u32bit)
   {
   const u32bit RC[16] = {
      0x9E3779B9, 0x3C6EF373, 0x78DDE6E6, 0xF1BBCDCC,
      0xE3779B99, 0xC6EF3733, 0x8DDE6E67, 0x1BBCDCCF,
      0x3779B99E, 0x6EF3733C, 0xDDE6E678, 0xBBCDCCF1,
      0x779B99E3, 0xEF3733C6, 0xDE6E678D, 0xBCDCCF1B
   };

   SecureBuffer<u32bit, 4> WK;

   for(u32bit j = 0; j != 4; ++j)
      WK[j] = make_u32bit(key[4*j], key[4*j+1], key[4*j+2], key[4*j+3]);

   G_FUNC G;

   for(u32bit j = 0; j != 16; j += 2)
      {
      K[2*j  ] = G(WK[0] + WK[2] - RC[j]);
      K[2*j+1] = G(WK[1] - WK[3] + RC[j]);

      byte T = get_byte(3, WK[0]);
      WK[0] = (WK[0] >> 8) | (get_byte(3, WK[1]) << 24);
      WK[1] = (WK[1] >> 8) | (T << 24);

      K[2*j+2] = G(WK[0] + WK[2] - RC[j+1]);
      K[2*j+3] = G(WK[1] - WK[3] + RC[j+1]);

      T = get_byte(0, WK[3]);
      WK[3] = (WK[3] << 8) | get_byte(0, WK[2]);
      WK[2] = (WK[2] << 8) | T;
      }
   }

}
