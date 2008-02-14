/*************************************************
* GOST Source File                               *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#include <botan/gost.h>
#include <botan/loadstor.h>

namespace Botan {

/*************************************************
* GOST Encryption                                *
*************************************************/
void GOST::enc(const byte in[], byte out[]) const
   {
   u32bit N1 = load_le<u32bit>(in, 0), N2 = load_le<u32bit>(in, 1);

   for(u32bit j = 0; j != 32; j += 2)
      {
      u32bit T0;

      T0 = N1 + EK[j];
      N2 ^= SBOX1[get_byte(0, T0)] | SBOX2[get_byte(1, T0)] |
            SBOX3[get_byte(2, T0)] | SBOX4[get_byte(3, T0)];

      T0 = N2 + EK[j+1];
      N1 ^= SBOX1[get_byte(0, T0)] | SBOX2[get_byte(1, T0)] |
            SBOX3[get_byte(2, T0)] | SBOX4[get_byte(3, T0)];
      }

   store_le(out, N2, N1);
   }

/*************************************************
* GOST Decryption                                *
*************************************************/
void GOST::dec(const byte in[], byte out[]) const
   {
   u32bit N1 = load_le<u32bit>(in, 0), N2 = load_le<u32bit>(in, 1);

   for(u32bit j = 0; j != 32; j += 2)
      {
      u32bit T0;

      T0 = N1 + EK[31-j];
      N2 ^= SBOX1[get_byte(0, T0)] | SBOX2[get_byte(1, T0)] |
            SBOX3[get_byte(2, T0)] | SBOX4[get_byte(3, T0)];

      T0 = N2 + EK[30-j];
      N1 ^= SBOX1[get_byte(0, T0)] | SBOX2[get_byte(1, T0)] |
            SBOX3[get_byte(2, T0)] | SBOX4[get_byte(3, T0)];
      }

   store_le(out, N2, N1);
   }

/*************************************************
* GOST Key Schedule                              *
*************************************************/
void GOST::key(const byte key[], u32bit)
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
