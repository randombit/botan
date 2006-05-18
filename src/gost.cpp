/*************************************************
* GOST Source File                               *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/gost.h>
#include <botan/bit_ops.h>

namespace Botan {

/*************************************************
* GOST Encryption                                *
*************************************************/
void GOST::enc(const byte in[], byte out[]) const
   {
   u32bit N1 = make_u32bit(in[3], in[2], in[1], in[0]),
          N2 = make_u32bit(in[7], in[6], in[5], in[4]);

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

   out[0] = get_byte(3, N2); out[1] = get_byte(2, N2);
   out[2] = get_byte(1, N2); out[3] = get_byte(0, N2);
   out[4] = get_byte(3, N1); out[5] = get_byte(2, N1);
   out[6] = get_byte(1, N1); out[7] = get_byte(0, N1);
   }

/*************************************************
* GOST Decryption                                *
*************************************************/
void GOST::dec(const byte in[], byte out[]) const
   {
   u32bit N1 = make_u32bit(in[3], in[2], in[1], in[0]),
          N2 = make_u32bit(in[7], in[6], in[5], in[4]);

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

   out[0] = get_byte(3, N2); out[1] = get_byte(2, N2);
   out[2] = get_byte(1, N2); out[3] = get_byte(0, N2);
   out[4] = get_byte(3, N1); out[5] = get_byte(2, N1);
   out[6] = get_byte(1, N1); out[7] = get_byte(0, N1);
   }

/*************************************************
* GOST Key Schedule                              *
*************************************************/
void GOST::key(const byte key[], u32bit)
   {
   for(u32bit j = 0; j != 8; ++j)
      {
      u32bit K = make_u32bit(key[4*j+3], key[4*j+2], key[4*j+1], key[4*j]);
      EK[j] = EK[j+8] = EK[j+16] = K;
      }

   for(u32bit j = 24; j != 32; ++j)
      EK[j] = EK[7-(j-24)];
   }

}
