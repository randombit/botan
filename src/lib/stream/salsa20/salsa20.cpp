/*
* Salsa20 / XSalsa20
* (C) 1999-2010,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/salsa20.h>
#include <botan/exceptn.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

#define SALSA20_QUARTER_ROUND(x1, x2, x3, x4)    \
   do {                                          \
      x2 ^= rotl<7>(x1 + x4);                    \
      x3 ^= rotl<9>(x2 + x1);                    \
      x4 ^= rotl<13>(x3 + x2);                   \
      x1 ^= rotl<18>(x4 + x3);                   \
   } while(0)

/*
* Generate HSalsa20 cipher stream (for XSalsa20 IV setup)
*/
//static
void Salsa20::hsalsa20(uint32_t output[8], const uint32_t input[16])
   {
   uint32_t x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
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
//static
void Salsa20::salsa_core(uint8_t output[64], const uint32_t input[16], size_t rounds)
   {
   BOTAN_ASSERT_NOMSG(rounds % 2 == 0);

   uint32_t x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
            x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
            x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
            x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

   for(size_t i = 0; i != rounds / 2; ++i)
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

#undef SALSA20_QUARTER_ROUND

/*
* Combine cipher stream with message
*/
void Salsa20::cipher(const uint8_t in[], uint8_t out[], size_t length)
   {
   verify_key_set(m_state.empty() == false);

   while(length >= m_buffer.size() - m_position)
      {
      const size_t available = m_buffer.size() - m_position;

      xor_buf(out, in, &m_buffer[m_position], available);
      salsa_core(m_buffer.data(), m_state.data(), 20);

      ++m_state[8];
      m_state[9] += (m_state[8] == 0);

      length -= available;
      in += available;
      out += available;

      m_position = 0;
      }

   xor_buf(out, in, &m_buffer[m_position], length);

   m_position += length;
   }

void Salsa20::initialize_state()
   {
   static const uint32_t TAU[] =
      { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

   static const uint32_t SIGMA[] =
      { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

   m_state[1] = m_key[0];
   m_state[2] = m_key[1];
   m_state[3] = m_key[2];
   m_state[4] = m_key[3];

   if(m_key.size() == 4)
      {
      m_state[0] = TAU[0];
      m_state[5] = TAU[1];
      m_state[10] = TAU[2];
      m_state[15] = TAU[3];
      m_state[11] = m_key[0];
      m_state[12] = m_key[1];
      m_state[13] = m_key[2];
      m_state[14] = m_key[3];
      }
   else
      {
      m_state[0] = SIGMA[0];
      m_state[5] = SIGMA[1];
      m_state[10] = SIGMA[2];
      m_state[15] = SIGMA[3];
      m_state[11] = m_key[4];
      m_state[12] = m_key[5];
      m_state[13] = m_key[6];
      m_state[14] = m_key[7];
      }

   m_state[6] = 0;
   m_state[7] = 0;
   m_state[8] = 0;
   m_state[9] = 0;

   m_position = 0;
   }

/*
* Salsa20 Key Schedule
*/
void Salsa20::key_schedule(const uint8_t key[], size_t length)
   {
   m_key.resize(length / 4);
   load_le<uint32_t>(m_key.data(), key, m_key.size());

   m_state.resize(16);
   m_buffer.resize(64);

   set_iv(nullptr, 0);
   }

/*
* Set the Salsa IV
*/
void Salsa20::set_iv(const uint8_t iv[], size_t length)
   {
   verify_key_set(m_state.empty() == false);

   if(!valid_iv_length(length))
      throw Invalid_IV_Length(name(), length);

   initialize_state();

   if(length == 0)
      {
      // Salsa20 null IV
      m_state[6] = 0;
      m_state[7] = 0;
      }
   else if(length == 8)
      {
      // Salsa20
      m_state[6] = load_le<uint32_t>(iv, 0);
      m_state[7] = load_le<uint32_t>(iv, 1);
      }
   else
      {
      // XSalsa20
      m_state[6] = load_le<uint32_t>(iv, 0);
      m_state[7] = load_le<uint32_t>(iv, 1);
      m_state[8] = load_le<uint32_t>(iv, 2);
      m_state[9] = load_le<uint32_t>(iv, 3);

      secure_vector<uint32_t> hsalsa(8);
      hsalsa20(hsalsa.data(), m_state.data());

      m_state[ 1] = hsalsa[0];
      m_state[ 2] = hsalsa[1];
      m_state[ 3] = hsalsa[2];
      m_state[ 4] = hsalsa[3];
      m_state[ 6] = load_le<uint32_t>(iv, 4);
      m_state[ 7] = load_le<uint32_t>(iv, 5);
      m_state[11] = hsalsa[4];
      m_state[12] = hsalsa[5];
      m_state[13] = hsalsa[6];
      m_state[14] = hsalsa[7];
      }

   m_state[8] = 0;
   m_state[9] = 0;

   salsa_core(m_buffer.data(), m_state.data(), 20);
   ++m_state[8];
   m_state[9] += (m_state[8] == 0);

   m_position = 0;
   }

bool Salsa20::valid_iv_length(size_t iv_len) const
   {
   return (iv_len == 0 || iv_len == 8 || iv_len == 24);
   }

size_t Salsa20::default_iv_length() const
   {
   return 24;
   }

Key_Length_Specification Salsa20::key_spec() const
   {
   return Key_Length_Specification(16, 32, 16);
   }

StreamCipher* Salsa20::clone() const
   {
   return new Salsa20;
   }

std::string Salsa20::name() const
   {
   return "Salsa20";
   }

/*
* Clear memory of sensitive data
*/
void Salsa20::clear()
   {
   zap(m_key);
   zap(m_state);
   zap(m_buffer);
   m_position = 0;
   }

void Salsa20::seek(uint64_t offset)
   {
   verify_key_set(m_state.empty() == false);

   // Find the block offset
   const uint64_t counter = offset / 64;
   uint8_t counter8[8];
   store_le(counter, counter8);

   m_state[8]  = load_le<uint32_t>(counter8, 0);
   m_state[9] += load_le<uint32_t>(counter8, 1);

   salsa_core(m_buffer.data(), m_state.data(), 20);

   ++m_state[8];
   m_state[9] += (m_state[8] == 0);

   m_position = offset % 64;
   }
}
