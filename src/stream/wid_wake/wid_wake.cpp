/*
* WiderWake
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/wid_wake.h>
#include <botan/loadstor.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

/*
* Combine cipher stream with message
*/
void WiderWake_41_BE::cipher(const byte in[], byte out[], size_t length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, &buffer[position], buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      generate(buffer.size());
      }
   xor_buf(out, in, &buffer[position], length);
   position += length;
   }

/*
* Generate cipher stream
*/
void WiderWake_41_BE::generate(size_t length)
   {
   u32bit R0 = state[0], R1 = state[1],
          R2 = state[2], R3 = state[3],
          R4 = state[4];

   for(size_t i = 0; i != length; i += 8)
      {
      u32bit R0a;

      store_be(R3, &buffer[i]);

      R0a = R4 + R3; R3 += R2; R2 += R1; R1 += R0;
      R0a = (R0a >> 8) ^ T[(R0a & 0xFF)];
      R1  = (R1  >> 8) ^ T[(R1  & 0xFF)];
      R2  = (R2  >> 8) ^ T[(R2  & 0xFF)];
      R3  = (R3  >> 8) ^ T[(R3  & 0xFF)];
      R4 = R0; R0 = R0a;

      store_be(R3, &buffer[i + 4]);

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
void WiderWake_41_BE::key_schedule(const byte key[], size_t)
   {
   for(size_t i = 0; i != 4; ++i)
      t_key[i] = load_be<u32bit>(key, i);

   static const u32bit MAGIC[8] = {
      0x726A8F3B, 0xE69A3B5C, 0xD3C71FE5, 0xAB3C73D2,
      0x4D3A8EB3, 0x0396D6E8, 0x3D4C2F7A, 0x9EE27CF3 };

   for(size_t i = 0; i != 4; ++i)
      T[i] = t_key[i];

   for(size_t i = 4; i != 256; ++i)
      {
      u32bit X = T[i-1] + T[i-4];
      T[i] = (X >> 3) ^ MAGIC[X % 8];
      }

   for(size_t i = 0; i != 23; ++i)
      T[i] += T[i+89];

   u32bit X = T[33];
   u32bit Z = (T[59] | 0x01000001) & 0xFF7FFFFF;
   for(size_t i = 0; i != 256; ++i)
      {
      X = (X & 0xFF7FFFFF) + Z;
      T[i] = (T[i] & 0x00FFFFFF) ^ X;
      }

   X = (T[X & 0xFF] ^ X) & 0xFF;
   Z = T[0];
   T[0] = T[X];
   for(size_t i = 1; i != 256; ++i)
      {
      T[X] = T[i];
      X = (T[i ^ X] ^ X) & 0xFF;
      T[i] = T[X];
      }
   T[X] = Z;

   position = 0;

   const byte ZEROS[8] = { 0 };
   set_iv(ZEROS, sizeof(ZEROS));
   }

/*
* Resynchronization
*/
void WiderWake_41_BE::set_iv(const byte iv[], size_t length)
   {
   if(!valid_iv_length(length))
      throw Invalid_IV_Length(name(), length);

   for(size_t i = 0; i != 4; ++i)
      state[i] = t_key[i];

   state[4] = load_be<u32bit>(iv, 0);
   state[0] ^= state[4];
   state[2] ^= load_be<u32bit>(iv, 1);

   generate(8*4);
   generate(buffer.size());
   }

/*
* Clear memory of sensitive data
*/
void WiderWake_41_BE::clear()
   {
   position = 0;
   zeroise(t_key);
   zeroise(state);
   zeroise(T);
   zeroise(buffer);
   }

}
