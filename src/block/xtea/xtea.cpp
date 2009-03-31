/*
* XTEA
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/xtea.h>
#include <botan/loadstor.h>
#include <botan/parsing.h>

namespace Botan {

/*
* XTEA Encryption
*/
void XTEA::enc(const byte in[], byte out[]) const
   {
   u32bit L = load_be<u32bit>(in, 0), R = load_be<u32bit>(in, 1);

   for(u32bit j = 0; j != 32; ++j)
      {
      L += (((R << 4) ^ (R >> 5)) + R) ^ EK[2*j];
      R += (((L << 4) ^ (L >> 5)) + L) ^ EK[2*j+1];
      }

   store_be(out, L, R);
   }

/*
* XTEA Decryption
*/
void XTEA::dec(const byte in[], byte out[]) const
   {
   u32bit L = load_be<u32bit>(in, 0), R = load_be<u32bit>(in, 1);

   for(u32bit j = 0; j != 32; ++j)
      {
      R -= (((L << 4) ^ (L >> 5)) + L) ^ EK[63 - 2*j];
      L -= (((R << 4) ^ (R >> 5)) + R) ^ EK[62 - 2*j];
      }

   store_be(out, L, R);
   }

/*
* XTEA Key Schedule
*/
void XTEA::key_schedule(const byte key[], u32bit)
   {
   SecureBuffer<u32bit, 4> UK;
   for(u32bit i = 0; i != 4; ++i)
      UK[i] = load_be<u32bit>(key, i);

   u32bit D = 0;
   for(u32bit i = 0; i != 64; i += 2)
      {
      EK[i  ] = D + UK[D % 4];
      D += 0x9E3779B9;
      EK[i+1] = D + UK[(D >> 11) % 4];
      }
   }

}
