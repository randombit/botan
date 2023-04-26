/*
* KMAC
* (C) 2023 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "botan/secmem.h"
#include "botan/exceptn.h"
#include "botan/assert.h"
#include <botan/internal/kmac.h>
#include <botan/internal/keccak_fips.h>
#include <botan/exceptn.h>
#include <botan/secmem.h>
#include <botan/types.h>
#include <limits>
#include <string>
#include <vector>


namespace Botan {

/**
* KMAC
* https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf
*
*
* newX = bytepad(encode_string(K), 136) ‖ input ‖ right_encode(L)
* T = bytebad(encode_string("KMAC" ‖ encode_string(S), 136))  // S = nonce
* return Keccak[512](T ‖ newX ‖ 00, L)
*
*/

// regarding the interface see https://github.com/randombit/botan/issues/3262
//
//

namespace {

template < bool IS_LEFT_ENCODE, typename T>
size_t left_or_right_encode(size_t s, T& output_container)
   {
   int i;
   size_t bytes_appended = 0;
   // determine number of octets needed to encode s
   for(i = sizeof(s); i > 0; i--)
      {
      uint8_t t = (s >> ((i-1)*8) & static_cast<size_t>(0xFF)  );
      if(t != 0)
         {
         break;
         }
      }
   if(i == 0)
   {
       i = 1;
   }
   if(IS_LEFT_ENCODE)
      {
      output_container.push_back(i);
      bytes_appended++;
      }
   // big endian encoding of s
   for(int j = i; j > 0; j--)
      {
      output_container.push_back(s >> (j-1)*8 & (static_cast<size_t>(0xFF)  ));
      bytes_appended++;
      }
   if(!IS_LEFT_ENCODE)
      {
      output_container.push_back(i);
      bytes_appended++;
      }
   return bytes_appended;
   }

template <typename T>
size_t left_encode(size_t s, T& output_container)
   {
   return left_or_right_encode<true>(s, output_container);
   }

template <typename T>
size_t right_encode(size_t s, T& output_container)
   {
   size_t result = left_or_right_encode<false>(s, output_container);
   return result;
   }




size_t byte_len_from_bit_len(size_t bit_length)
   {
   if(bit_length % 8)
      {
      throw Invalid_Argument("cannot convert byte length to bit length that is not a multiple of 8");
      }
   return bit_length / 8;
   }

size_t bit_len_from_byte_len(size_t byte_length)
   {

   size_t bit_length = 8*byte_length;
   if(bit_length < byte_length)
      {
      throw Botan::Invalid_Argument("byte length is too large. Only byte lengths of up to "
                                    + std::to_string(std::numeric_limits<size_t>::max() / 8) + " are supported on this platform in this function.");
      }
   return bit_length;
   }

template <typename T>
void encode_string(const uint8_t* input, size_t input_byte_length, T& output_container)
   {
   // left_encode(*bitlen* of input)
   size_t written = left_encode(bit_len_from_byte_len(input_byte_length), output_container);
   output_container.insert(output_container.end(), input, &input[input_byte_length]);
   written += input_byte_length;
   }

template <typename T>
void byte_pad(uint8_t input[], size_t input_byte_length, size_t w_in_bytes, T& output_container)
   {
   size_t written_bytes = left_encode(w_in_bytes, output_container);
   output_container.insert(output_container.end(), input, &input[input_byte_length]);
   written_bytes += input_byte_length;
   if(w_in_bytes > written_bytes)
      {
      size_t nb_trail_zeroes = w_in_bytes - written_bytes;
      std::vector<uint8_t> trailing_zeroes(nb_trail_zeroes, 0);
      output_container.insert(output_container.end(), &trailing_zeroes[0], &trailing_zeroes[trailing_zeroes.size()]);
      }

   }

}

void KMAC256::clear()
   {
   zap(m_key);
   m_key_set = false;
   m_hash.clear();
   }
std::string KMAC256::name() const
   {
   return std::string("KMAC256(" + std::to_string(m_output_bit_length) + ")");
   }
std::unique_ptr<MessageAuthenticationCode> KMAC256::new_object() const
   {
   return std::make_unique<KMAC256>(m_output_bit_length);
   }

size_t KMAC256::output_length() const
   {
   return m_output_bit_length/8;
   }

Key_Length_Specification KMAC256::key_spec() const
   {
   // KMAC support key lengths from zero up to 2²⁰⁴⁰ (2^(2040)) bits
   // https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf#page=28
   return Key_Length_Specification(0, std::numeric_limits<size_t>::max());
   }

bool KMAC256::has_keying_material() const 
{ 
    return m_key_set; 
}

void KMAC256::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   const uint8_t dom_sep [] = { 'K', 'M', 'A', 'C' };
   assert_key_material_set(m_key_set);
   std::vector<uint8_t> t_input;
   encode_string(dom_sep, sizeof(dom_sep), t_input);
   encode_string(nonce, nonce_len, t_input);
   std::vector<uint8_t> t;
   byte_pad(&t_input[0], t_input.size(), m_pad_byte_length, t);
   m_hash.update(t);
   secure_vector<uint8_t> key_input;
   encode_string(&m_key[0], m_key.size(), key_input);
   secure_vector<uint8_t> newX_head;
   byte_pad(&key_input[0], key_input.size(), m_pad_byte_length, newX_head);
   m_hash.update(newX_head);
   }

/**
* @param hash the hash to use for KMAC256ing
*/
KMAC256::KMAC256(uint32_t output_bit_length)
   :m_output_bit_length(output_bit_length),
    m_hash(Keccak_FIPS_generic("Keccak_FIPS_generic(tailpadding=00)", output_bit_length, 512, 00, 2)),
    m_pad_byte_length(136)
   {
   // ensure valid output length
   byte_len_from_bit_len(m_output_bit_length);
   }

void KMAC256::add_data(unsigned char const* data, unsigned long data_len)
   {
   assert_key_material_set(m_key_set);
   m_hash.update(data, data_len);
   }

void KMAC256::final_result(unsigned char* output)
   {

   assert_key_material_set(m_key_set);
   std::vector<uint8_t> tail;
   right_encode(m_output_bit_length, tail);
   m_hash.update(tail);

   std::vector<uint8_t> result;
   m_hash.final(result);
   BOTAN_ASSERT_EQUAL(result.size(),  m_output_bit_length/8, "consistent output length" );
   memcpy(output, &result[0], result.size());
   }


void KMAC256::key_schedule(const uint8_t key[], size_t key_length)
   {

   m_hash.clear();
   zap(m_key);
   m_key.insert(m_key.end(), &key[0], &key[key_length]);
   m_key_set = true;
   }
}
