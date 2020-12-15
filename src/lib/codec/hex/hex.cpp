/*
* Hex Encoding and Decoding
* (C) 2010,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hex.h>
#include <botan/mem_ops.h>
#include <botan/exceptn.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

namespace {

char hex_encode_nibble(uint8_t n, bool uppercase)
   {
   BOTAN_DEBUG_ASSERT(n <= 15);

   const auto in_09 = CT::Mask<uint8_t>::is_lt(n, 10);

   const char c_09 = n + '0';
   const char c_af = n + (uppercase ? 'A' : 'a') - 10;

   return in_09.select(c_09, c_af);
   }

}

void hex_encode(char output[],
                const uint8_t input[],
                size_t input_length,
                bool uppercase)
   {
   for(size_t i = 0; i != input_length; ++i)
      {
      const uint8_t n0 = (input[i] >> 4) & 0xF;
      const uint8_t n1 = (input[i]     ) & 0xF;

      output[2*i  ] = hex_encode_nibble(n0, uppercase);
      output[2*i+1] = hex_encode_nibble(n1, uppercase);
      }
   }

std::string hex_encode(const uint8_t input[],
                       size_t input_length,
                       bool uppercase)
   {
   std::string output(2 * input_length, 0);

   if(input_length)
      hex_encode(&output.front(), input, input_length, uppercase);

   return output;
   }

namespace {

uint8_t hex_char_to_bin(char input)
   {
   const uint8_t c = static_cast<uint8_t>(input);

   const auto is_alpha_upper = CT::Mask<uint8_t>::is_within_range(c, uint8_t('A'), uint8_t('F'));
   const auto is_alpha_lower = CT::Mask<uint8_t>::is_within_range(c, uint8_t('a'), uint8_t('f'));
   const auto is_decimal     = CT::Mask<uint8_t>::is_within_range(c, uint8_t('0'), uint8_t('9'));

   const auto is_whitespace  = CT::Mask<uint8_t>::is_any_of(c, {
         uint8_t(' '), uint8_t('\t'), uint8_t('\n'), uint8_t('\r')
      });

   const uint8_t c_upper = c - uint8_t('A') + 10;
   const uint8_t c_lower = c - uint8_t('a') + 10;
   const uint8_t c_decim = c - uint8_t('0');

   uint8_t ret = 0xFF; // default value

   ret = is_alpha_upper.select(c_upper, ret);
   ret = is_alpha_lower.select(c_lower, ret);
   ret = is_decimal.select(c_decim, ret);
   ret = is_whitespace.select(0x80, ret);

   return ret;
   }

}


size_t hex_decode(uint8_t output[],
                  const char input[],
                  size_t input_length,
                  size_t& input_consumed,
                  bool ignore_ws)
   {
   uint8_t* out_ptr = output;
   bool top_nibble = true;

   clear_mem(output, input_length / 2);

   for(size_t i = 0; i != input_length; ++i)
      {
      const uint8_t bin = hex_char_to_bin(input[i]);

      if(bin >= 0x10)
         {
         if(bin == 0x80 && ignore_ws)
            continue;

         std::string bad_char(1, input[i]);
         if(bad_char == "\t")
           bad_char = "\\t";
         else if(bad_char == "\n")
           bad_char = "\\n";

         throw Invalid_Argument(
           std::string("hex_decode: invalid hex character '") +
           bad_char + "'");
         }

      if(top_nibble)
         *out_ptr |= bin << 4;
      else
         *out_ptr |= bin;

      top_nibble = !top_nibble;
      if(top_nibble)
         ++out_ptr;
      }

   input_consumed = input_length;
   size_t written = (out_ptr - output);

   /*
   * We only got half of a uint8_t at the end; zap the half-written
   * output and mark it as unread
   */
   if(!top_nibble)
      {
      *out_ptr = 0;
      input_consumed -= 1;
      }

   return written;
   }

size_t hex_decode(uint8_t output[],
                  const char input[],
                  size_t input_length,
                  bool ignore_ws)
   {
   size_t consumed = 0;
   size_t written = hex_decode(output, input, input_length,
                               consumed, ignore_ws);

   if(consumed != input_length)
      throw Invalid_Argument("hex_decode: input did not have full bytes");

   return written;
   }

size_t hex_decode(uint8_t output[],
                  const std::string& input,
                  bool ignore_ws)
   {
   return hex_decode(output, input.data(), input.length(), ignore_ws);
   }

secure_vector<uint8_t> hex_decode_locked(const char input[],
                                      size_t input_length,
                                      bool ignore_ws)
   {
   secure_vector<uint8_t> bin(1 + input_length / 2);

   size_t written = hex_decode(bin.data(),
                               input,
                               input_length,
                               ignore_ws);

   bin.resize(written);
   return bin;
   }

secure_vector<uint8_t> hex_decode_locked(const std::string& input,
                                      bool ignore_ws)
   {
   return hex_decode_locked(input.data(), input.size(), ignore_ws);
   }

std::vector<uint8_t> hex_decode(const char input[],
                             size_t input_length,
                             bool ignore_ws)
   {
   std::vector<uint8_t> bin(1 + input_length / 2);

   size_t written = hex_decode(bin.data(),
                               input,
                               input_length,
                               ignore_ws);

   bin.resize(written);
   return bin;
   }

std::vector<uint8_t> hex_decode(const std::string& input,
                             bool ignore_ws)
   {
   return hex_decode(input.data(), input.size(), ignore_ws);
   }

}
