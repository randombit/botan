/*
* WiderWake
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/wid_wake.h>
#include <botan/loadstor.h>
#include <botan/xor_buf.h>

namespace Botan {

/*
* Combine cipher stream with message
*/
void WiderWake_41_BE::cipher(const byte in[], byte out[], u32bit length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, buffer + position, buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      generate(buffer.size());
      }
   xor_buf(out, in, buffer + position, length);
   position += length;
   }

/*
* Generate cipher stream
*/
void WiderWake_41_BE::generate(u32bit length)
   {
   u32bit R0 = state[0], R1 = state[1],
          R2 = state[2], R3 = state[3],
          R4 = state[4];

   for(u32bit j = 0; j != length; j += 8)
      {
      u32bit R0a;

      store_be(R3, buffer + j);

      R0a = R4 + R3; R3 += R2; R2 += R1; R1 += R0;
      R0a = (R0a >> 8) ^ T[(R0a & 0xFF)];
      R1  = (R1  >> 8) ^ T[(R1  & 0xFF)];
      R2  = (R2  >> 8) ^ T[(R2  & 0xFF)];
      R3  = (R3  >> 8) ^ T[(R3  & 0xFF)];
      R4 = R0; R0 = R0a;

      store_be(R3, buffer + j + 4);

      R0a = R4 + R3; R3 += R2; R2 += R1; R1 += R0;
      R0a = (R0a >> 8) ^ T[(R0a & 0xFF)];
      R1  = (R1  >> 8) ^ T[(R1  & 0xFF)];
      R2  = (R2  >> 8) ^ T[(R2  & 0xFF)];
      R3  = (R3  >> 8) ^ T[(R3  & 0xFF)];
      R4 = R0; R0 = R0a;
      }

   state[0] = R0;
   state[1] = R1;
   state[2] = R2;
   state[3] = R3;
   state[4] = R4;

   position = 0;
   }

/*
* WiderWake Key Schedule
*/
void WiderWake_41_BE::key_schedule(const byte key[], u32bit)
   {
   for(u32bit j = 0; j != 4; ++j)
      t_key[j] = load_be<u32bit>(key, j);

   static const u32bit MAGIC[8] = {
      0x726A8F3B, 0xE69A3B5C, 0xD3C71FE5, 0xAB3C73D2,
      0x4D3A8EB3, 0x0396D6E8, 0x3D4C2F7A, 0x9EE27CF3 };

   for(u32bit j = 0; j != 4; ++j)
      T[j] = t_key[j];
   for(u32bit j = 4; j != 256; ++j)
      {
      u32bit X = T[j-1] + T[j-4];
      T[j] = (X >> 3) ^ MAGIC[X % 8];
      }
   for(u32bit j = 0; j != 23; ++j)
      T[j] += T[j+89];

   u32bit X = T[33];
   u32bit Z = (T[59] | 0x01000001) & 0xFF7FFFFF;
   for(u32bit j = 0; j != 256; ++j)
      {
      X = (X & 0xFF7FFFFF) + Z;
      T[j] = (T[j] & 0x00FFFFFF) ^ X;
      }
   X = (T[X & 0xFF] ^ X) & 0xFF;
   Z = T[0];
   T[0] = T[X];
   for(u32bit j = 1; j != 256; ++j)
      {
      T[X] = T[j];
      X = (T[j ^ X] ^ X) & 0xFF;
      T[j] = T[X];
      }
   T[X] = Z;

   position = 0;
   const byte iv[8] = { 0 };
   resync(iv, 8);
   }

/*
* Resynchronization
*/
void WiderWake_41_BE::resync(const byte iv[], u32bit length)
   {
   if(length != 8)
      throw Invalid_IV_Length(name(), length);

   for(u32bit j = 0; j != 4; ++j)
      state[j] = t_key[j];
   state[4] = load_be<u32bit>(iv, 0);
   state[0] ^= state[4];
   state[2] ^= load_be<u32bit>(iv, 1);

   generate(8*4);
   generate(buffer.size());
   }

/*
* Clear memory of sensitive data
*/
void WiderWake_41_BE::clear() throw()
   {
   position = 0;
   t_key.clear();
   state.clear();
   T.clear();
   buffer.clear();
   }

}
