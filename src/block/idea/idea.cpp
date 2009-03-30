/*
* IDEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/idea.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

/*
* Multiplication modulo 65537
*/
inline u16bit mul(u16bit x, u16bit y)
   {
   if(x && y)
      {
      u32bit T = static_cast<u32bit>(x) * y;
      x = static_cast<u16bit>(T >> 16);
      y = static_cast<u16bit>(T & 0xFFFF);
      return static_cast<u16bit>(y - x + ((y < x) ? 1 : 0));
      }
   else
      return static_cast<u16bit>(1 - x - y);
   }

/*
* Find multiplicative inverses modulo 65537
*/
u16bit mul_inv(u16bit x)
   {
   if(x <= 1)
      return x;

   u16bit t0 = static_cast<u16bit>(65537 / x), t1 = 1;
   u16bit y = static_cast<u16bit>(65537 % x);

   while(y != 1)
      {
      u16bit q = x / y;
      x %= y;
      t1 += q * t0;

      if(x == 1)
         return t1;

      q = y / x;
      y %= x;
      t0 += q * t1;
      }
   return (1 - t0);
   }

}

/*
* IDEA Encryption
*/
void IDEA::enc(const byte in[], byte out[]) const
   {
   u16bit X1 = load_be<u16bit>(in, 0);
   u16bit X2 = load_be<u16bit>(in, 1);
   u16bit X3 = load_be<u16bit>(in, 2);
   u16bit X4 = load_be<u16bit>(in, 3);

   for(u32bit j = 0; j != 8; ++j)
      {
      X1 = mul(X1, EK[6*j+0]);
      X2 += EK[6*j+1];
      X3 += EK[6*j+2];
      X4 = mul(X4, EK[6*j+3]);

      u16bit T0 = X3;
      X3 = mul(X3 ^ X1, EK[6*j+4]);

      u16bit T1 = X2;
      X2 = mul((X2 ^ X4) + X3, EK[6*j+5]);
      X3 += X2;

      X1 ^= X2;
      X4 ^= X3;
      X2 ^= T0;
      X3 ^= T1;
      }

   X1  = mul(X1, EK[48]);
   X2 += EK[50];
   X3 += EK[49];
   X4  = mul(X4, EK[51]);

   store_be(out, X1, X3, X2, X4);
   }

/*
* IDEA Decryption
*/
void IDEA::dec(const byte in[], byte out[]) const
   {
   u16bit X1 = load_be<u16bit>(in, 0);
   u16bit X2 = load_be<u16bit>(in, 1);
   u16bit X3 = load_be<u16bit>(in, 2);
   u16bit X4 = load_be<u16bit>(in, 3);

   for(u32bit j = 0; j != 8; ++j)
      {
      X1 = mul(X1, DK[6*j+0]);
      X2 += DK[6*j+1];
      X3 += DK[6*j+2];
      X4 = mul(X4, DK[6*j+3]);

      u16bit T0 = X3;
      X3 = mul(X3 ^ X1, DK[6*j+4]);

      u16bit T1 = X2;
      X2 = mul((X2 ^ X4) + X3, DK[6*j+5]);
      X3 += X2;

      X1 ^= X2;
      X4 ^= X3;
      X2 ^= T0;
      X3 ^= T1;
      }

   X1  = mul(X1, DK[48]);
   X2 += DK[50];
   X3 += DK[49];
   X4  = mul(X4, DK[51]);

   store_be(out, X1, X3, X2, X4);
   }

/*
* IDEA Key Schedule
*/
void IDEA::key_schedule(const byte key[], u32bit)
   {
   for(u32bit j = 0; j != 8; ++j)
      EK[j] = load_be<u16bit>(key, j);

   for(u32bit j = 1, k = 8, offset = 0; k != 52; j %= 8, ++j, ++k)
      {
      EK[j+7+offset] = static_cast<u16bit>((EK[(j     % 8) + offset] << 9) |
                                           (EK[((j+1) % 8) + offset] >> 7));
      offset += (j == 8) ? 8 : 0;
      }

   DK[51] = mul_inv(EK[3]);
   DK[50] = -EK[2];
   DK[49] = -EK[1];
   DK[48] = mul_inv(EK[0]);

   for(u32bit j = 1, k = 4, counter = 47; j != 8; ++j, k += 6)
      {
      DK[counter--] = EK[k+1];
      DK[counter--] = EK[k];
      DK[counter--] = mul_inv(EK[k+5]);
      DK[counter--] = -EK[k+3];
      DK[counter--] = -EK[k+4];
      DK[counter--] = mul_inv(EK[k+2]);
      }

   DK[5] = EK[47];
   DK[4] = EK[46];
   DK[3] = mul_inv(EK[51]);
   DK[2] = -EK[50];
   DK[1] = -EK[49];
   DK[0] = mul_inv(EK[48]);
   }

}
