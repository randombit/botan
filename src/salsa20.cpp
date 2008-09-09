/*************************************************
* Salsa20 Source File                            *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/salsa20.h>
#include <botan/mem_ops.h>
#include <botan/xor_buf.h>
#include <botan/loadstor.h>
#include <botan/parsing.h>

namespace Botan {

namespace {

/*************************************************
* Generate Salsa20 cipher stream                 *
*************************************************/
void salsa20(byte output[64], u32bit input[16])
   {
   u32bit x[16];

   copy_mem(x, input, 16);

   for(u32bit i = 0; i != 10; ++i)
      {
      x[ 4] ^= rotate_left(x[ 0] + x[12],  7);
      x[ 8] ^= rotate_left(x[ 4] + x[ 0],  9);
      x[12] ^= rotate_left(x[ 8] + x[ 4], 13);
      x[ 0] ^= rotate_left(x[12] + x[ 8], 18);
      x[ 9] ^= rotate_left(x[ 5] + x[ 1],  7);
      x[13] ^= rotate_left(x[ 9] + x[ 5],  9);
      x[ 1] ^= rotate_left(x[13] + x[ 9], 13);
      x[ 5] ^= rotate_left(x[ 1] + x[13], 18);
      x[14] ^= rotate_left(x[10] + x[ 6],  7);
      x[ 2] ^= rotate_left(x[14] + x[10],  9);
      x[ 6] ^= rotate_left(x[ 2] + x[14], 13);
      x[10] ^= rotate_left(x[ 6] + x[ 2], 18);
      x[ 3] ^= rotate_left(x[15] + x[11],  7);
      x[ 7] ^= rotate_left(x[ 3] + x[15],  9);
      x[11] ^= rotate_left(x[ 7] + x[ 3], 13);
      x[15] ^= rotate_left(x[11] + x[ 7], 18);
      x[ 1] ^= rotate_left(x[ 0] + x[ 3],  7);
      x[ 2] ^= rotate_left(x[ 1] + x[ 0],  9);
      x[ 3] ^= rotate_left(x[ 2] + x[ 1], 13);
      x[ 0] ^= rotate_left(x[ 3] + x[ 2], 18);
      x[ 6] ^= rotate_left(x[ 5] + x[ 4],  7);
      x[ 7] ^= rotate_left(x[ 6] + x[ 5],  9);
      x[ 4] ^= rotate_left(x[ 7] + x[ 6], 13);
      x[ 5] ^= rotate_left(x[ 4] + x[ 7], 18);
      x[11] ^= rotate_left(x[10] + x[ 9],  7);
      x[ 8] ^= rotate_left(x[11] + x[10],  9);
      x[ 9] ^= rotate_left(x[ 8] + x[11], 13);
      x[10] ^= rotate_left(x[ 9] + x[ 8], 18);
      x[12] ^= rotate_left(x[15] + x[14],  7);
      x[13] ^= rotate_left(x[12] + x[15],  9);
      x[14] ^= rotate_left(x[13] + x[12], 13);
      x[15] ^= rotate_left(x[14] + x[13], 18);
      }

   for(u32bit i = 0; i != 16; ++i)
      store_le(x[i] + input[i], output + 4 * i);

   ++input[8];
   if(!input[8])
      ++input[9];
   }

}

/*************************************************
* Combine cipher stream with message             *
*************************************************/
void Salsa20::cipher(const byte in[], byte out[], u32bit length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, buffer.begin() + position, buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      salsa20(buffer.begin(), state);
      position = 0;
      }

   xor_buf(out, in, buffer.begin() + position, length);

   position += length;
   }

/*************************************************
* Salsa20 Key Schedule                           *
*************************************************/
void Salsa20::key(const byte key[], u32bit length)
   {
   clear();

   if(length == 16)
      {
      const u32bit TAU[] = { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

      state[0] = TAU[0];
      state[1] = load_le<u32bit>(key, 0);
      state[2] = load_le<u32bit>(key, 1);
      state[3] = load_le<u32bit>(key, 2);
      state[4] = load_le<u32bit>(key, 3);
      state[5] = TAU[1];
      state[10] = TAU[2];
      state[11] = load_le<u32bit>(key, 0);
      state[12] = load_le<u32bit>(key, 1);
      state[13] = load_le<u32bit>(key, 2);
      state[14] = load_le<u32bit>(key, 3);
      state[15] = TAU[3];
      }
   else if(length == 32)
      {
      const u32bit SIGMA[] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

      state[0] = SIGMA[0];
      state[1] = load_le<u32bit>(key, 0);
      state[2] = load_le<u32bit>(key, 1);
      state[3] = load_le<u32bit>(key, 2);
      state[4] = load_le<u32bit>(key, 3);
      state[5] = SIGMA[1];
      state[10] = SIGMA[2];
      state[11] = load_le<u32bit>(key, 4);
      state[12] = load_le<u32bit>(key, 5);
      state[13] = load_le<u32bit>(key, 6);
      state[14] = load_le<u32bit>(key, 7);
      state[15] = SIGMA[3];
      }

   const byte ZERO[8] = { 0 };
   resync(ZERO, sizeof(ZERO));
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
void Salsa20::resync(const byte iv[], u32bit length)
   {
   if(length != IV_LENGTH)
      throw Invalid_IV_Length(name(), length);

   state[6] = load_le<u32bit>(iv, 0);
   state[7] = load_le<u32bit>(iv, 1);
   state[8] = 0;
   state[9] = 0;

   salsa20(buffer.begin(), state);
   position = 0;
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string Salsa20::name() const
   {
   return "Salsa20";
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void Salsa20::clear() throw()
   {
   state.clear();
   buffer.clear();
   position = 0;
   }

/*************************************************
* Salsa20 Constructor                            *
*************************************************/
Salsa20::Salsa20() : StreamCipher(16, 32, 16, 8)
   {
   clear();
   }

}
