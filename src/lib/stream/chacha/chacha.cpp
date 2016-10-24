/*
* ChaCha
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/chacha.h>
#include <botan/loadstor.h>
#include <botan/cpuid.h>

namespace Botan {

ChaCha::ChaCha(size_t rounds) : m_rounds(rounds)
   {
   if(m_rounds != 8 && m_rounds != 12 && m_rounds != 20)
      throw Invalid_Argument("ChaCha only supports 8, 12 or 20 rounds");
   }

std::string ChaCha::provider() const
   {
#if defined(BOTAN_HAS_CHACHA_SSE2)
   if(CPUID::has_sse2())
      {
      return "sse2";
      }
#endif

   return "base";
   }

//static
void ChaCha::chacha_x4(byte output[64*4], u32bit input[16], size_t rounds)
   {
   BOTAN_ASSERT(rounds % 2 == 0, "Valid rounds");

#if defined(BOTAN_HAS_CHACHA_SSE2)
   if(CPUID::has_sse2())
      {
      return ChaCha::chacha_sse2_x4(output, input, rounds);
      }
#endif

   // TODO interleave rounds
   for(size_t i = 0; i != 4; ++i)
      {
      u32bit x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
             x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
             x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
             x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

#define CHACHA_QUARTER_ROUND(a, b, c, d)        \
      do {                                      \
      a += b; d ^= a; d = rotate_left(d, 16);   \
      c += d; b ^= c; b = rotate_left(b, 12);   \
      a += b; d ^= a; d = rotate_left(d, 8);    \
      c += d; b ^= c; b = rotate_left(b, 7);    \
      } while(0)

      for(size_t r = 0; r != rounds / 2; ++r)
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

      x00 += input[0];
      x01 += input[1];
      x02 += input[2];
      x03 += input[3];
      x04 += input[4];
      x05 += input[5];
      x06 += input[6];
      x07 += input[7];
      x08 += input[8];
      x09 += input[9];
      x10 += input[10];
      x11 += input[11];
      x12 += input[12];
      x13 += input[13];
      x14 += input[14];
      x15 += input[15];

      store_le(x00, output + 64 * i + 4 *  0);
      store_le(x01, output + 64 * i + 4 *  1);
      store_le(x02, output + 64 * i + 4 *  2);
      store_le(x03, output + 64 * i + 4 *  3);
      store_le(x04, output + 64 * i + 4 *  4);
      store_le(x05, output + 64 * i + 4 *  5);
      store_le(x06, output + 64 * i + 4 *  6);
      store_le(x07, output + 64 * i + 4 *  7);
      store_le(x08, output + 64 * i + 4 *  8);
      store_le(x09, output + 64 * i + 4 *  9);
      store_le(x10, output + 64 * i + 4 * 10);
      store_le(x11, output + 64 * i + 4 * 11);
      store_le(x12, output + 64 * i + 4 * 12);
      store_le(x13, output + 64 * i + 4 * 13);
      store_le(x14, output + 64 * i + 4 * 14);
      store_le(x15, output + 64 * i + 4 * 15);

      input[12]++;
      input[13] += input[12] < i; // carry?
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
      chacha_x4(m_buffer.data(), m_state.data(), m_rounds);
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

   // Repeat the key if 128 bits
   const byte* key2 = (length == 32) ? key + 16 : key;

   m_position = 0;
   m_state.resize(16);
   m_buffer.resize(4*64);

   m_state[0] = CONSTANTS[0];
   m_state[1] = CONSTANTS[1];
   m_state[2] = CONSTANTS[2];
   m_state[3] = CONSTANTS[3];

   m_state[4] = load_le<u32bit>(key, 0);
   m_state[5] = load_le<u32bit>(key, 1);
   m_state[6] = load_le<u32bit>(key, 2);
   m_state[7] = load_le<u32bit>(key, 3);

   m_state[8] = load_le<u32bit>(key2, 0);
   m_state[9] = load_le<u32bit>(key2, 1);
   m_state[10] = load_le<u32bit>(key2, 2);
   m_state[11] = load_le<u32bit>(key2, 3);

   // Default all-zero IV
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

   chacha_x4(m_buffer.data(), m_state.data(), m_rounds);
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

   // Find the block offset
   u64bit counter = offset / 64;

   byte out[8];

   store_le(counter, out);

   m_state[12] = load_le<u32bit>(out, 0);
   m_state[13] += load_le<u32bit>(out, 1);

   chacha_x4(m_buffer.data(), m_state.data(), m_rounds);
   m_position = offset % 64;
   }
}
