/*
* ChaCha
* (C) 2014,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/chacha.h>
#include <botan/exceptn.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>
#include <botan/cpuid.h>

namespace Botan {

namespace {

#define CHACHA_QUARTER_ROUND(a, b, c, d) \
      do {                               \
      a += b; d ^= a; d = rotl<16>(d);   \
      c += d; b ^= c; b = rotl<12>(b);   \
      a += b; d ^= a; d = rotl<8>(d);    \
      c += d; b ^= c; b = rotl<7>(b);    \
      } while(0)

/*
* Generate HChaCha cipher stream (for XChaCha IV setup)
*/
void hchacha(uint32_t output[8], const uint32_t input[16], size_t rounds)
   {
   BOTAN_ASSERT(rounds % 2 == 0, "Valid rounds");

   uint32_t x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
            x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
            x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
            x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

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

   output[0] = x00;
   output[1] = x01;
   output[2] = x02;
   output[3] = x03;
   output[4] = x12;
   output[5] = x13;
   output[6] = x14;
   output[7] = x15;
   }

}

ChaCha::ChaCha(size_t rounds) : m_rounds(rounds)
   {
   BOTAN_ARG_CHECK(m_rounds == 8 || m_rounds == 12 || m_rounds == 20,
                   "ChaCha only supports 8, 12 or 20 rounds");
   }

std::string ChaCha::provider() const
   {
#if defined(BOTAN_HAS_CHACHA_AVX2)
   if(CPUID::has_avx2())
      {
      return "avx2";
      }
#endif

#if defined(BOTAN_HAS_CHACHA_SIMD32)
   if(CPUID::has_simd_32())
      {
      return "simd32";
      }
#endif

   return "base";
   }

//static
void ChaCha::chacha_x8(uint8_t output[64*8], uint32_t input[16], size_t rounds)
   {
   BOTAN_ASSERT(rounds % 2 == 0, "Valid rounds");

#if defined(BOTAN_HAS_CHACHA_AVX2)
   if(CPUID::has_avx2())
      {
      return ChaCha::chacha_avx2_x8(output, input, rounds);
      }
#endif

#if defined(BOTAN_HAS_CHACHA_SIMD32)
   if(CPUID::has_simd_32())
      {
      ChaCha::chacha_simd32_x4(output, input, rounds);
      ChaCha::chacha_simd32_x4(output + 4*64, input, rounds);
      return;
      }
#endif

   // TODO interleave rounds
   for(size_t i = 0; i != 8; ++i)
      {
      uint32_t x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
               x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
               x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
               x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

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
      input[13] += (input[12] == 0);
      }
   }

#undef CHACHA_QUARTER_ROUND

/*
* Combine cipher stream with message
*/
void ChaCha::cipher(const uint8_t in[], uint8_t out[], size_t length)
   {
   verify_key_set(m_state.empty() == false);

   while(length >= m_buffer.size() - m_position)
      {
      const size_t available = m_buffer.size() - m_position;

      xor_buf(out, in, &m_buffer[m_position], available);
      chacha_x8(m_buffer.data(), m_state.data(), m_rounds);

      length -= available;
      in += available;
      out += available;
      m_position = 0;
      }

   xor_buf(out, in, &m_buffer[m_position], length);

   m_position += length;
   }

void ChaCha::write_keystream(uint8_t out[], size_t length)
   {
   verify_key_set(m_state.empty() == false);

   while(length >= m_buffer.size() - m_position)
      {
      const size_t available = m_buffer.size() - m_position;

      copy_mem(out, &m_buffer[m_position], available);
      chacha_x8(m_buffer.data(), m_state.data(), m_rounds);

      length -= available;
      out += available;
      m_position = 0;
      }

   copy_mem(out, &m_buffer[m_position], length);

   m_position += length;
   }

void ChaCha::initialize_state()
   {
   static const uint32_t TAU[] =
      { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

   static const uint32_t SIGMA[] =
      { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

   m_state[4] = m_key[0];
   m_state[5] = m_key[1];
   m_state[6] = m_key[2];
   m_state[7] = m_key[3];

   if(m_key.size() == 4)
      {
      m_state[0] = TAU[0];
      m_state[1] = TAU[1];
      m_state[2] = TAU[2];
      m_state[3] = TAU[3];

      m_state[8] = m_key[0];
      m_state[9] = m_key[1];
      m_state[10] = m_key[2];
      m_state[11] = m_key[3];
      }
   else
      {
      m_state[0] = SIGMA[0];
      m_state[1] = SIGMA[1];
      m_state[2] = SIGMA[2];
      m_state[3] = SIGMA[3];

      m_state[8] = m_key[4];
      m_state[9] = m_key[5];
      m_state[10] = m_key[6];
      m_state[11] = m_key[7];
      }

   m_state[12] = 0;
   m_state[13] = 0;
   m_state[14] = 0;
   m_state[15] = 0;

   m_position = 0;
   }

/*
* ChaCha Key Schedule
*/
void ChaCha::key_schedule(const uint8_t key[], size_t length)
   {
   m_key.resize(length / 4);
   load_le<uint32_t>(m_key.data(), key, m_key.size());

   m_state.resize(16);

   const size_t chacha_parallelism = 8; // chacha_x8
   const size_t chacha_block = 64;
   m_buffer.resize(chacha_parallelism * chacha_block);

   set_iv(nullptr, 0);
   }

size_t ChaCha::default_iv_length() const
   {
   return 24;
   }

Key_Length_Specification ChaCha::key_spec() const
   {
   return Key_Length_Specification(16, 32, 16);
   }

StreamCipher* ChaCha::clone() const
   {
   return new ChaCha(m_rounds);
   }

bool ChaCha::valid_iv_length(size_t iv_len) const
   {
   return (iv_len == 0 || iv_len == 8 || iv_len == 12 || iv_len == 24);
   }

void ChaCha::set_iv(const uint8_t iv[], size_t length)
   {
   verify_key_set(m_state.empty() == false);

   if(!valid_iv_length(length))
      throw Invalid_IV_Length(name(), length);

   initialize_state();

   if(length == 0)
      {
      // Treat zero length IV same as an all-zero IV
      m_state[14] = 0;
      m_state[15] = 0;
      }
   else if(length == 8)
      {
      m_state[14] = load_le<uint32_t>(iv, 0);
      m_state[15] = load_le<uint32_t>(iv, 1);
      }
   else if(length == 12)
      {
      m_state[13] = load_le<uint32_t>(iv, 0);
      m_state[14] = load_le<uint32_t>(iv, 1);
      m_state[15] = load_le<uint32_t>(iv, 2);
      }
   else if(length == 24)
      {
      m_state[12] = load_le<uint32_t>(iv, 0);
      m_state[13] = load_le<uint32_t>(iv, 1);
      m_state[14] = load_le<uint32_t>(iv, 2);
      m_state[15] = load_le<uint32_t>(iv, 3);

      secure_vector<uint32_t> hc(8);
      hchacha(hc.data(), m_state.data(), m_rounds);

      m_state[ 4] = hc[0];
      m_state[ 5] = hc[1];
      m_state[ 6] = hc[2];
      m_state[ 7] = hc[3];
      m_state[ 8] = hc[4];
      m_state[ 9] = hc[5];
      m_state[10] = hc[6];
      m_state[11] = hc[7];
      m_state[12] = 0;
      m_state[13] = 0;
      m_state[14] = load_le<uint32_t>(iv, 4);
      m_state[15] = load_le<uint32_t>(iv, 5);
      }

   chacha_x8(m_buffer.data(), m_state.data(), m_rounds);
   m_position = 0;
   }

void ChaCha::clear()
   {
   zap(m_key);
   zap(m_state);
   zap(m_buffer);
   m_position = 0;
   }

std::string ChaCha::name() const
   {
   return "ChaCha(" + std::to_string(m_rounds) + ")";
   }

void ChaCha::seek(uint64_t offset)
   {
   verify_key_set(m_state.empty() == false);

   // Find the block offset
   const uint64_t counter = offset / 64;

   uint8_t out[8];

   store_le(counter, out);

   m_state[12] = load_le<uint32_t>(out, 0);
   m_state[13] += load_le<uint32_t>(out, 1);

   chacha_x8(m_buffer.data(), m_state.data(), m_rounds);
   m_position = offset % 64;
   }
}
