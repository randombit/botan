/*
* TEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/tea.h>
#include <botan/loadstor.h>

namespace Botan {

/*
* TEA Encryption
*/
void TEA::enc(const byte in[], byte out[]) const
   {
   u32bit L = load_be<u32bit>(in, 0), R = load_be<u32bit>(in, 1);

   u32bit S = 0;
   for(u32bit j = 0; j != 32; ++j)
      {
      S += 0x9E3779B9;
      L += ((R << 4) + K[0]) ^ (R + S) ^ ((R >> 5) + K[1]);
      R += ((L << 4) + K[2]) ^ (L + S) ^ ((L >> 5) + K[3]);
      }

   store_be(out, L, R);
   }

/*
* TEA Decryption
*/
void TEA::dec(const byte in[], byte out[]) const
   {
   u32bit L = load_be<u32bit>(in, 0), R = load_be<u32bit>(in, 1);

   u32bit S = 0xC6EF3720;
   for(u32bit j = 0; j != 32; ++j)
      {
      R -= ((L << 4) + K[2]) ^ (L + S) ^ ((L >> 5) + K[3]);
      L -= ((R << 4) + K[0]) ^ (R + S) ^ ((R >> 5) + K[1]);
      S -= 0x9E3779B9;
      }

   store_be(out, L, R);
   }

/*
* TEA Key Schedule
*/
void TEA::key_schedule(const byte key[], u32bit)
   {
   for(u32bit j = 0; j != 4; ++j)
      K[j] = load_be<u32bit>(key, j);
   }

}
