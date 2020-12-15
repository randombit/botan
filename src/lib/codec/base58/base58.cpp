/*
* (C) 2018,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/base58.h>
#include <botan/exceptn.h>
#include <botan/bigint.h>
#include <botan/divide.h>
#include <botan/loadstor.h>
#include <botan/internal/ct_utils.h>
#include <botan/hash.h>

namespace Botan {

namespace {

uint32_t sha256_d_checksum(const uint8_t input[], size_t input_length)
   {
   std::unique_ptr<HashFunction> sha256 = HashFunction::create_or_throw("SHA-256");

   std::vector<uint8_t> checksum(32);

   sha256->update(input, input_length);
   sha256->final(checksum);

   sha256->update(checksum);
   sha256->final(checksum);

   return load_be<uint32_t>(checksum.data(), 0);
   }

char lookup_base58_char(uint8_t x)
   {
   // "123456789 ABCDEFGH JKLMN PQRSTUVWXYZ abcdefghijk mnopqrstuvwxyz"
   BOTAN_DEBUG_ASSERT(x < 58);

   const auto is_dec_19      = CT::Mask<uint8_t>::is_lte(x, 8);
   const auto is_alpha_AH    = CT::Mask<uint8_t>::is_within_range(x, 9, 16);
   const auto is_alpha_JN    = CT::Mask<uint8_t>::is_within_range(x, 17, 21);
   const auto is_alpha_PZ    = CT::Mask<uint8_t>::is_within_range(x, 22, 32);
   const auto is_alpha_ak    = CT::Mask<uint8_t>::is_within_range(x, 33, 43);
   // otherwise in 'm'-'z'

   const char c_19 = '1' + x;
   const char c_AH = 'A' + (x - 9);
   const char c_JN = 'J' + (x - 17);
   const char c_PZ = 'P' + (x - 22);
   const char c_ak = 'a' + (x - 33);
   const char c_mz = 'm' + (x - 44);

   char ret = c_mz;
   ret = is_dec_19.select(c_19, ret);
   ret = is_alpha_AH.select(c_AH, ret);
   ret = is_alpha_JN.select(c_JN, ret);
   ret = is_alpha_PZ.select(c_PZ, ret);
   ret = is_alpha_ak.select(c_ak, ret);

   return ret;
   }

std::string base58_encode(BigInt v, size_t leading_zeros)
   {
   const uint8_t radix = 58;

   std::string result;
   BigInt q;

   while(v.is_nonzero())
      {
      uint8_t r;
      ct_divide_u8(v, radix, q, r);
      result.push_back(lookup_base58_char(r));
      v.swap(q);
      }

   for(size_t i = 0; i != leading_zeros; ++i)
      result.push_back('1'); // 'zero' byte

   return std::string(result.rbegin(), result.rend());
   }

template<typename T, typename Z>
size_t count_leading_zeros(const T input[], size_t input_length, Z zero)
   {
   size_t leading_zeros = 0;

   while(leading_zeros < input_length && input[leading_zeros] == zero)
      leading_zeros += 1;

   return leading_zeros;
   }

uint8_t base58_value_of(char input)
   {
   // "123456789 ABCDEFGH JKLMN PQRSTUVWXYZ abcdefghijk mnopqrstuvwxyz"

   const uint8_t c = static_cast<uint8_t>(input);

   const auto is_dec_19      = CT::Mask<uint8_t>::is_within_range(c, uint8_t('1'), uint8_t('9'));
   const auto is_alpha_AH    = CT::Mask<uint8_t>::is_within_range(c, uint8_t('A'), uint8_t('H'));
   const auto is_alpha_JN    = CT::Mask<uint8_t>::is_within_range(c, uint8_t('J'), uint8_t('N'));
   const auto is_alpha_PZ    = CT::Mask<uint8_t>::is_within_range(c, uint8_t('P'), uint8_t('Z'));

   const auto is_alpha_ak    = CT::Mask<uint8_t>::is_within_range(c, uint8_t('a'), uint8_t('k'));
   const auto is_alpha_mz    = CT::Mask<uint8_t>::is_within_range(c, uint8_t('m'), uint8_t('z'));

   const uint8_t c_dec_19 = c - uint8_t('1');
   const uint8_t c_AH     = c - uint8_t('A') + 9;
   const uint8_t c_JN     = c - uint8_t('J') + 17;
   const uint8_t c_PZ     = c - uint8_t('P') + 22;

   const uint8_t c_ak     = c - uint8_t('a') + 33;
   const uint8_t c_mz     = c - uint8_t('m') + 44;

   uint8_t ret = 0xFF; // default value

   ret = is_dec_19.select(c_dec_19, ret);
   ret = is_alpha_AH.select(c_AH, ret);
   ret = is_alpha_JN.select(c_JN, ret);
   ret = is_alpha_PZ.select(c_PZ, ret);
   ret = is_alpha_ak.select(c_ak, ret);
   ret = is_alpha_mz.select(c_mz, ret);
   return ret;
   }

}

std::string base58_encode(const uint8_t input[], size_t input_length)
   {
   BigInt v(input, input_length);
   return base58_encode(v, count_leading_zeros(input, input_length, 0));
   }

std::string base58_check_encode(const uint8_t input[], size_t input_length)
   {
   BigInt v(input, input_length);
   v <<= 32;
   v += sha256_d_checksum(input, input_length);
   return base58_encode(v, count_leading_zeros(input, input_length, 0));
   }

std::vector<uint8_t> base58_decode(const char input[], size_t input_length)
   {
   const size_t leading_zeros = count_leading_zeros(input, input_length, '1');

   BigInt v;

   for(size_t i = leading_zeros; i != input_length; ++i)
      {
      const char c = input[i];

      if(c == ' ' || c == '\n')
         continue;

      const uint8_t idx = base58_value_of(c);

      if(idx == 0xFF)
         throw Decoding_Error("Invalid base58");

      v *= 58;
      v += idx;
      }

   std::vector<uint8_t> output(v.bytes() + leading_zeros);
   v.binary_encode(output.data() + leading_zeros);
   return output;
   }

std::vector<uint8_t> base58_check_decode(const char input[], size_t input_length)
   {
   std::vector<uint8_t> dec = base58_decode(input, input_length);

   if(dec.size() < 4)
      throw Decoding_Error("Invalid base58 too short for checksum");

   const uint32_t computed_checksum = sha256_d_checksum(dec.data(), dec.size() - 4);
   const uint32_t checksum = load_be<uint32_t>(&dec[dec.size()-4], 0);

   if(checksum != computed_checksum)
      throw Decoding_Error("Invalid base58 checksum");

   dec.resize(dec.size() - 4);

   return dec;
   }

}
