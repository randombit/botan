/*
* ChaCha
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/chacha.h>
#include <botan/loadstor.h>

namespace Botan {

ChaCha::ChaCha(size_t rounds) : m_rounds(rounds)
   {
   if(m_rounds != 8 && m_rounds != 12 && m_rounds != 20)
      throw Invalid_Argument("ChaCha only supports 8, 12 or 20 rounds");
   }

namespace {

void chacha(byte output[64], const u32bit input[16], size_t rounds)
   {
   BOTAN_ASSERT(rounds % 2 == 0, "Valid rounds");

   u32bit x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
          x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
          x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
          x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

#define CHACHA_QUARTER_ROUND(a, b, c, d)   \
   do {                                    \
   a += b; d ^= a; d = rotate_left(d, 16); \
   c += d; b ^= c; b = rotate_left(b, 12); \
   a += b; d ^= a; d = rotate_left(d, 8);  \
   c += d; b ^= c; b = rotate_left(b, 7);  \
   } while(0)

   for(size_t i = 0; i != rounds / 2; ++i)
      {
      CHACHA_QUARTER_ROUND(x00, x04, x08, x12);
      CHACHA_QUARTER_ROUND(x01, x05, x09, x13);
      CHACHA_QUARTER_ROUND(x02, x06, x10, x14);
      CHACHA_QUARTER_ROUND(x03, x07, x11, x15);

      CHACHA_QUARTER_ROUND(x00, x05, x10, x15);
      CHACHA_QUARTER_ROUND(x01, x06, x11, x12);
      CHACHA_QUARTER_ROUND(x02, x07, x08, x13);
      CHACHA_QUARTER_ROUND(x03, x04, x09, x14);
      }

#undef CHACHA_QUARTER_ROUND

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
void ChaCha::cipher(const byte in[], byte out[], size_t length)
   {
   while(length >= m_buffer.size() - m_position)
      {
      xor_buf(out, in, &m_buffer[m_position], m_buffer.size() - m_position);
      length -= (m_buffer.size() - m_position);
      in += (m_buffer.size() - m_position);
      out += (m_buffer.size() - m_position);
      chacha(m_buffer.data(), m_state.data(), m_rounds);

      ++m_state[12];
      m_state[13] += (m_state[12] == 0);

      m_position = 0;
      }

   xor_buf(out, in, &m_buffer[m_position], length);

   m_position += length;
   }

/*
* ChaCha Key Schedule
*/
void ChaCha::key_schedule(const byte key[], size_t length)
   {
   static const u32bit TAU[] =
      { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

   static const u32bit SIGMA[] =
      { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

   const u32bit* CONSTANTS = (length == 16) ? TAU : SIGMA;

   m_state.resize(16);
   m_buffer.resize(64);

   m_state[0] = CONSTANTS[0];
   m_state[1] = CONSTANTS[1];
   m_state[2] = CONSTANTS[2];
   m_state[3] = CONSTANTS[3];

   m_state[4] = load_le<u32bit>(key, 0);
   m_state[5] = load_le<u32bit>(key, 1);
   m_state[6] = load_le<u32bit>(key, 2);
   m_state[7] = load_le<u32bit>(key, 3);

   if(length == 32)
      key += 16;

   m_state[8] = load_le<u32bit>(key, 0);
   m_state[9] = load_le<u32bit>(key, 1);
   m_state[10] = load_le<u32bit>(key, 2);
   m_state[11] = load_le<u32bit>(key, 3);

   m_position = 0;

   const byte ZERO[8] = { 0 };
   set_iv(ZERO, sizeof(ZERO));
   }

void ChaCha::set_iv(const byte iv[], size_t length)
   {
   if(!valid_iv_length(length))
      throw Invalid_IV_Length(name(), length);

   m_state[12] = 0;
   m_state[13] = 0;

   if(length == 8)
      {
      m_state[14] = load_le<u32bit>(iv, 0);
      m_state[15] = load_le<u32bit>(iv, 1);
      }
   else if(length == 12)
      {
      m_state[13] = load_le<u32bit>(iv, 0);
      m_state[14] = load_le<u32bit>(iv, 1);
      m_state[15] = load_le<u32bit>(iv, 2);
      }

   chacha(m_buffer.data(), m_state.data(), m_rounds);
   ++m_state[12];
   m_state[13] += (m_state[12] == 0);

   m_position = 0;
   }

void ChaCha::clear()
   {
   zap(m_state);
   zap(m_buffer);
   m_position = 0;
   }

std::string ChaCha::name() const
   {
   return "ChaCha(" + std::to_string(m_rounds) + ")";
   }

void ChaCha::seek(u64bit offset)
   {
   if (m_state.size() == 0 && m_buffer.size() == 0)
      {
         throw Invalid_State("You have to setup the stream cipher (key and iv)");
      }

   m_position = offset % m_buffer.size();

   u64bit counter = offset / m_buffer.size();

   byte out[8];

   store_le(counter, out);

   m_state[12] = load_le<u32bit>(out, 0);
   m_state[13] += load_le<u32bit>(out, 1);

   chacha(m_buffer.data(), m_state.data(), m_rounds);

   ++m_state[12];
   m_state[13] += (m_state[12] == 0);
   }
}
