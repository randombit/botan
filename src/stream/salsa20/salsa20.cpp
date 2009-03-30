/*
* Salsa20
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/salsa20.h>
#include <botan/mem_ops.h>
#include <botan/xor_buf.h>
#include <botan/loadstor.h>
#include <botan/parsing.h>

namespace Botan {

namespace {

/*
* Generate Salsa20 cipher stream
*/
void salsa20(byte output[64], const u32bit input[16])
   {
   u32bit x00 = input[0];
   u32bit x01 = input[1];
   u32bit x02 = input[2];
   u32bit x03 = input[3];
   u32bit x04 = input[4];
   u32bit x05 = input[5];
   u32bit x06 = input[6];
   u32bit x07 = input[7];
   u32bit x08 = input[8];
   u32bit x09 = input[9];
   u32bit x10 = input[10];
   u32bit x11 = input[11];
   u32bit x12 = input[12];
   u32bit x13 = input[13];
   u32bit x14 = input[14];
   u32bit x15 = input[15];

   for(u32bit i = 0; i != 10; ++i)
      {
      x04 ^= rotate_left(x00 + x12,  7);
      x08 ^= rotate_left(x04 + x00,  9);
      x12 ^= rotate_left(x08 + x04, 13);
      x00 ^= rotate_left(x12 + x08, 18);
      x09 ^= rotate_left(x05 + x01,  7);
      x13 ^= rotate_left(x09 + x05,  9);
      x01 ^= rotate_left(x13 + x09, 13);
      x05 ^= rotate_left(x01 + x13, 18);
      x14 ^= rotate_left(x10 + x06,  7);
      x02 ^= rotate_left(x14 + x10,  9);
      x06 ^= rotate_left(x02 + x14, 13);
      x10 ^= rotate_left(x06 + x02, 18);
      x03 ^= rotate_left(x15 + x11,  7);
      x07 ^= rotate_left(x03 + x15,  9);
      x11 ^= rotate_left(x07 + x03, 13);
      x15 ^= rotate_left(x11 + x07, 18);

      x01 ^= rotate_left(x00 + x03,  7);
      x02 ^= rotate_left(x01 + x00,  9);
      x03 ^= rotate_left(x02 + x01, 13);
      x00 ^= rotate_left(x03 + x02, 18);
      x06 ^= rotate_left(x05 + x04,  7);
      x07 ^= rotate_left(x06 + x05,  9);
      x04 ^= rotate_left(x07 + x06, 13);
      x05 ^= rotate_left(x04 + x07, 18);
      x11 ^= rotate_left(x10 + x09,  7);
      x08 ^= rotate_left(x11 + x10,  9);
      x09 ^= rotate_left(x08 + x11, 13);
      x10 ^= rotate_left(x09 + x08, 18);
      x12 ^= rotate_left(x15 + x14,  7);
      x13 ^= rotate_left(x12 + x15,  9);
      x14 ^= rotate_left(x13 + x12, 13);
      x15 ^= rotate_left(x14 + x13, 18);
      }

   store_le(x00 + input[ 0], output + 4 *  0);
   store_le(x01 + input[ 1], output + 4 *  1);
   store_le(x02 + input[ 2], output + 4 *  2);
   store_le(x03 + input[ 3], output + 4 *  3);
   store_le(x04 + input[ 4], output + 4 *  4);
   store_le(x05 + input[ 5], output + 4 *  5);
   store_le(x06 + input[ 6], output + 4 *  6);
   store_le(x07 + input[ 7], output + 4 *  7);
   store_le(x08 + input[ 8], output + 4 *  8);
   store_le(x09 + input[ 9], output + 4 *  9);
   store_le(x10 + input[10], output + 4 * 10);
   store_le(x11 + input[11], output + 4 * 11);
   store_le(x12 + input[12], output + 4 * 12);
   store_le(x13 + input[13], output + 4 * 13);
   store_le(x14 + input[14], output + 4 * 14);
   store_le(x15 + input[15], output + 4 * 15);
   }

}

/*
* Combine cipher stream with message
*/
void Salsa20::cipher(const byte in[], byte out[], u32bit length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, buffer.begin() + position, buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      salsa20(buffer.begin(), state);

      ++state[8];
      if(!state[8]) // if overflow in state[8]
         ++state[9]; // carry to state[9]

      position = 0;
      }

   xor_buf(out, in, buffer.begin() + position, length);

   position += length;
   }

/*
* Salsa20 Key Schedule
*/
void Salsa20::key_schedule(const byte key[], u32bit length)
   {
   static const u32bit TAU[] =
      { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

   static const u32bit SIGMA[] =
      { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

   clear();

   if(length == 16)
      {
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

/*
* Return the name of this type
*/
void Salsa20::resync(const byte iv[], u32bit length)
   {
   if(length != IV_LENGTH)
      throw Invalid_IV_Length(name(), length);

   state[6] = load_le<u32bit>(iv, 0);
   state[7] = load_le<u32bit>(iv, 1);
   state[8] = 0;
   state[9] = 0;

   salsa20(buffer.begin(), state);
   ++state[8];
   if(!state[8]) // if overflow in state[8]
      ++state[9]; // carry to state[9]

   position = 0;
   }

/*
* Return the name of this type
*/
std::string Salsa20::name() const
   {
   return "Salsa20";
   }

/*
* Clear memory of sensitive data
*/
void Salsa20::clear() throw()
   {
   state.clear();
   buffer.clear();
   position = 0;
   }

/*
* Salsa20 Constructor
*/
Salsa20::Salsa20() : StreamCipher(16, 32, 16, 8)
   {
   clear();
   }

}
