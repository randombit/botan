/*
* Base64 Encoding and Decoding
* (C) 2010,2015,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/base64.h>
#include <botan/internal/codec_base.h>
#include <botan/exceptn.h>
#include <botan/internal/rounding.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

namespace {

class Base64 final
   {
   public:
      static inline std::string name() noexcept
         {
         return "base64";
         }

      static inline size_t encoding_bytes_in() noexcept
         {
         return m_encoding_bytes_in;
         }
      static inline size_t encoding_bytes_out() noexcept
         {
         return m_encoding_bytes_out;
         }

      static inline size_t decoding_bytes_in() noexcept
         {
         return m_encoding_bytes_out;
         }
      static inline size_t decoding_bytes_out() noexcept
         {
         return m_encoding_bytes_in;
         }

      static inline size_t bits_consumed() noexcept
         {
         return m_encoding_bits;
         }
      static inline size_t remaining_bits_before_padding() noexcept
         {
         return m_remaining_bits_before_padding;
         }

      static inline size_t encode_max_output(size_t input_length)
         {
         return (round_up(input_length, m_encoding_bytes_in) / m_encoding_bytes_in) * m_encoding_bytes_out;
         }
      static inline size_t decode_max_output(size_t input_length)
         {
         return (round_up(input_length, m_encoding_bytes_out) * m_encoding_bytes_in) / m_encoding_bytes_out;
         }

      static void encode(char out[8], const uint8_t in[5]) noexcept;

      static uint8_t lookup_binary_value(char input) noexcept;

      static bool check_bad_char(uint8_t bin, char input, bool ignore_ws);

      static void decode(uint8_t* out_ptr, const uint8_t decode_buf[4])
         {
         out_ptr[0] = (decode_buf[0] << 2) | (decode_buf[1] >> 4);
         out_ptr[1] = (decode_buf[1] << 4) | (decode_buf[2] >> 2);
         out_ptr[2] = (decode_buf[2] << 6) | decode_buf[3];
         }

      static inline size_t bytes_to_remove(size_t final_truncate)
         {
         return final_truncate;
         }

   private:
      static const size_t m_encoding_bits = 6;
      static const size_t m_remaining_bits_before_padding = 8;

      static const size_t m_encoding_bytes_in = 3;
      static const size_t m_encoding_bytes_out = 4;
   };

char lookup_base64_char(uint8_t x)
   {
   BOTAN_DEBUG_ASSERT(x < 64);

   const auto in_az = CT::Mask<uint8_t>::is_within_range(x, 26, 51);
   const auto in_09 = CT::Mask<uint8_t>::is_within_range(x, 52, 61);
   const auto eq_plus = CT::Mask<uint8_t>::is_equal(x, 62);
   const auto eq_slash = CT::Mask<uint8_t>::is_equal(x, 63);

   const char c_AZ = 'A' + x;
   const char c_az = 'a' + (x - 26);
   const char c_09 = '0' + (x - 2*26);
   const char c_plus = '+';
   const char c_slash = '/';

   char ret = c_AZ;
   ret = in_az.select(c_az, ret);
   ret = in_09.select(c_09, ret);
   ret = eq_plus.select(c_plus, ret);
   ret = eq_slash.select(c_slash, ret);

   return ret;
   }

//static
void Base64::encode(char out[8], const uint8_t in[5]) noexcept
   {
   const uint8_t b0 = (in[0] & 0xFC) >> 2;
   const uint8_t b1 = ((in[0] & 0x03) << 4) | (in[1] >> 4);
   const uint8_t b2 = ((in[1] & 0x0F) << 2) | (in[2] >> 6);
   const uint8_t b3 = in[2] & 0x3F;
   out[0] = lookup_base64_char(b0);
   out[1] = lookup_base64_char(b1);
   out[2] = lookup_base64_char(b2);
   out[3] = lookup_base64_char(b3);
   }

//static
uint8_t Base64::lookup_binary_value(char input) noexcept
   {
   const uint8_t c = static_cast<uint8_t>(input);

   const auto is_alpha_upper = CT::Mask<uint8_t>::is_within_range(c, uint8_t('A'), uint8_t('Z'));
   const auto is_alpha_lower = CT::Mask<uint8_t>::is_within_range(c, uint8_t('a'), uint8_t('z'));
   const auto is_decimal     = CT::Mask<uint8_t>::is_within_range(c, uint8_t('0'), uint8_t('9'));

   const auto is_plus        = CT::Mask<uint8_t>::is_equal(c, uint8_t('+'));
   const auto is_slash       = CT::Mask<uint8_t>::is_equal(c, uint8_t('/'));
   const auto is_equal       = CT::Mask<uint8_t>::is_equal(c, uint8_t('='));

   const auto is_whitespace  = CT::Mask<uint8_t>::is_any_of(c, {
         uint8_t(' '), uint8_t('\t'), uint8_t('\n'), uint8_t('\r')
      });

   const uint8_t c_upper = c - uint8_t('A');
   const uint8_t c_lower = c - uint8_t('a') + 26;
   const uint8_t c_decim = c - uint8_t('0') + 2*26;

   uint8_t ret = 0xFF; // default value

   ret = is_alpha_upper.select(c_upper, ret);
   ret = is_alpha_lower.select(c_lower, ret);
   ret = is_decimal.select(c_decim, ret);
   ret = is_plus.select(62, ret);
   ret = is_slash.select(63, ret);
   ret = is_equal.select(0x81, ret);
   ret = is_whitespace.select(0x80, ret);

   return ret;
   }

//static
bool Base64::check_bad_char(uint8_t bin, char input, bool ignore_ws)
   {
   if(bin <= 0x3F)
      {
      return true;
      }
   else if(!(bin == 0x81 || (bin == 0x80 && ignore_ws)))
      {
      std::string bad_char(1, input);
      if(bad_char == "\t")
         { bad_char = "\\t"; }
      else if(bad_char == "\n")
         { bad_char = "\\n"; }
      else if(bad_char == "\r")
         { bad_char = "\\r"; }

      throw Invalid_Argument(
         std::string("base64_decode: invalid base64 character '") +
         bad_char + "'");
      }
   return false;
   }

}

size_t base64_encode(char out[],
                     const uint8_t in[],
                     size_t input_length,
                     size_t& input_consumed,
                     bool final_inputs)
   {
   return base_encode(Base64(), out, in, input_length, input_consumed, final_inputs);
   }

std::string base64_encode(const uint8_t input[],
                          size_t input_length)
   {
   return base_encode_to_string(Base64(), input, input_length);
   }

size_t base64_decode(uint8_t out[],
                     const char in[],
                     size_t input_length,
                     size_t& input_consumed,
                     bool final_inputs,
                     bool ignore_ws)
   {
   return base_decode(Base64(), out, in, input_length, input_consumed, final_inputs, ignore_ws);
   }

size_t base64_decode(uint8_t output[],
                     const char input[],
                     size_t input_length,
                     bool ignore_ws)
   {
   return base_decode_full(Base64(), output, input, input_length, ignore_ws);
   }

size_t base64_decode(uint8_t output[],
                     const std::string& input,
                     bool ignore_ws)
   {
   return base64_decode(output, input.data(), input.length(), ignore_ws);
   }

secure_vector<uint8_t> base64_decode(const char input[],
                                     size_t input_length,
                                     bool ignore_ws)
   {
   return base_decode_to_vec<secure_vector<uint8_t>>(Base64(), input, input_length, ignore_ws);
   }

secure_vector<uint8_t> base64_decode(const std::string& input,
                                     bool ignore_ws)
   {
   return base64_decode(input.data(), input.size(), ignore_ws);
   }

size_t base64_encode_max_output(size_t input_length)
   {
   return Base64::encode_max_output(input_length);
   }

size_t base64_decode_max_output(size_t input_length)
   {
   return Base64::decode_max_output(input_length);
   }

}
