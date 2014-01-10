/*
* Salsa20 / XSalsa20
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/salsa20.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

namespace {

#define SALSA20_QUARTER_ROUND(x1, x2, x3, x4)    \
   do {                                          \
      x2 ^= rotate_left(x1 + x4,  7);            \
      x3 ^= rotate_left(x2 + x1,  9);            \
      x4 ^= rotate_left(x3 + x2, 13);            \
      x1 ^= rotate_left(x4 + x3, 18);            \
   } while(0)

/*
* Generate HSalsa20 cipher stream (for XSalsa20 IV setup)
*/
void hsalsa20(u32bit output[8], const u32bit input[16])
   {
   u32bit x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
          x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
          x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
          x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

   for(size_t i = 0; i != 10; ++i)
      {
      SALSA20_QUARTER_ROUND(x00, x04, x08, x12);
      SALSA20_QUARTER_ROUND(x05, x09, x13, x01);
      SALSA20_QUARTER_ROUND(x10, x14, x02, x06);
      SALSA20_QUARTER_ROUND(x15, x03, x07, x11);

      SALSA20_QUARTER_ROUND(x00, x01, x02, x03);
      SALSA20_QUARTER_ROUND(x05, x06, x07, x04);
      SALSA20_QUARTER_ROUND(x10, x11, x08, x09);
      SALSA20_QUARTER_ROUND(x15, x12, x13, x14);
      }

   output[0] = x00;
   output[1] = x05;
   output[2] = x10;
   output[3] = x15;
   output[4] = x06;
   output[5] = x07;
   output[6] = x08;
   output[7] = x09;
   }

/*
* Generate Salsa20 cipher stream
*/
void salsa20(byte output[64], const u32bit input[16])
   {
   u32bit x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
          x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
          x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
          x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

   for(size_t i = 0; i != 10; ++i)
      {
      SALSA20_QUARTER_ROUND(x00, x04, x08, x12);
      SALSA20_QUARTER_ROUND(x05, x09, x13, x01);
      SALSA20_QUARTER_ROUND(x10, x14, x02, x06);
      SALSA20_QUARTER_ROUND(x15, x03, x07, x11);

      SALSA20_QUARTER_ROUND(x00, x01, x02, x03);
      SALSA20_QUARTER_ROUND(x05, x06, x07, x04);
      SALSA20_QUARTER_ROUND(x10, x11, x08, x09);
      SALSA20_QUARTER_ROUND(x15, x12, x13, x14);
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
void Salsa20::cipher(const byte in[], byte out[], size_t length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, &buffer[position], buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      salsa20(&buffer[0], &state[0]);

      ++state[8];
      if(!state[8]) // if overflow in state[8]
         ++state[9]; // carry to state[9]

      position = 0;
      }

   xor_buf(out, in, &buffer[position], length);

   position += length;
   }

/*
* Salsa20 Key Schedule
*/
void Salsa20::key_schedule(const byte key[], size_t length)
   {
   static const u32bit TAU[] =
      { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

   static const u32bit SIGMA[] =
      { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

   state.resize(16);
   buffer.resize(64);

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

   position = 0;

   const byte ZERO[8] = { 0 };
   set_iv(ZERO, sizeof(ZERO));
   }

/*
* Return the name of this type
*/
void Salsa20::set_iv(const byte iv[], size_t length)
   {
   if(!valid_iv_length(length))
      throw Invalid_IV_Length(name(), length);

   if(length == 8)
      {
      // Salsa20
      state[6] = load_le<u32bit>(iv, 0);
      state[7] = load_le<u32bit>(iv, 1);
      }
   else
      {
      // XSalsa20
      state[6] = load_le<u32bit>(iv, 0);
      state[7] = load_le<u32bit>(iv, 1);
      state[8] = load_le<u32bit>(iv, 2);
      state[9] = load_le<u32bit>(iv, 3);

      secure_vector<u32bit> hsalsa(8);
      hsalsa20(&hsalsa[0], &state[0]);

      state[ 1] = hsalsa[0];
      state[ 2] = hsalsa[1];
      state[ 3] = hsalsa[2];
      state[ 4] = hsalsa[3];
      state[ 6] = load_le<u32bit>(iv, 4);
      state[ 7] = load_le<u32bit>(iv, 5);
      state[11] = hsalsa[4];
      state[12] = hsalsa[5];
      state[13] = hsalsa[6];
      state[14] = hsalsa[7];
      }

   state[8] = 0;
   state[9] = 0;

   salsa20(&buffer[0], &state[0]);
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
void Salsa20::clear()
   {
   zap(state);
   zap(buffer);
   position = 0;
   }

}
