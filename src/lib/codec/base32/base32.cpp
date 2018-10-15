/*
* Base32 Encoding and Decoding
* (C) 2018 Erwan Chaussy
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/base32.h>
#include <botan/internal/codec_base.h>
#include <botan/internal/rounding.h>

namespace Botan {

namespace {

class Base32 final
   {
   public:
      static inline std::string name() noexcept
         {
         return "base32";
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

      static void encode(char out[8], const uint8_t in[5]) noexcept
         {
         out[0] = Base32::m_bin_to_base32[(in[0] & 0xF8) >> 3];
         out[1] = Base32::m_bin_to_base32[((in[0] & 0x07) << 2) | (in[1] >> 6)];
         out[2] = Base32::m_bin_to_base32[((in[1] & 0x3E) >> 1)];
         out[3] = Base32::m_bin_to_base32[((in[1] & 0x01) << 4) | (in[2] >> 4)];
         out[4] = Base32::m_bin_to_base32[((in[2] & 0x0F) << 1) | (in[3] >> 7)];
         out[5] = Base32::m_bin_to_base32[((in[3] & 0x7C) >> 2)];
         out[6] = Base32::m_bin_to_base32[((in[3] & 0x03) << 3) | (in[4] >> 5)];
         out[7] = Base32::m_bin_to_base32[in[4] & 0x1F];
         }

      static inline uint8_t lookup_binary_value(char input) noexcept
         {
         return Base32::m_base32_to_bin[static_cast<uint8_t>(input)];
         }

      static inline bool check_bad_char(uint8_t bin, char input, bool ignore_ws)
         {
         if(bin <= 0x1F)
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
               std::string("base32_decode: invalid base32 character '") +
               bad_char + "'");
            }
         return false;
         }

      static void decode(uint8_t* out_ptr, const uint8_t decode_buf[8])
         {
         out_ptr[0] = (decode_buf[0] << 3) | (decode_buf[1] >> 2);
         out_ptr[1] = (decode_buf[1] << 6) | (decode_buf[2] << 1) | (decode_buf[3] >> 4);
         out_ptr[2] = (decode_buf[3] << 4) | (decode_buf[4] >> 1);
         out_ptr[3] = (decode_buf[4] << 7) | (decode_buf[5] << 2) | (decode_buf[6] >> 3);
         out_ptr[4] = (decode_buf[6] << 5) | decode_buf[7];
         }

      static inline size_t bytes_to_remove(size_t final_truncate)
         {
         return final_truncate ? (final_truncate / 2) + 1 : 0;
         }

   private:
      static const size_t m_encoding_bits = 5;
      static const size_t m_remaining_bits_before_padding = 6;


      static const size_t m_encoding_bytes_in = 5;
      static const size_t m_encoding_bytes_out = 8;


      static const uint8_t m_bin_to_base32[32];
      static const uint8_t m_base32_to_bin[256];
   };

const uint8_t Base32::m_bin_to_base32[32] =
   {
   'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
   'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
   '2', '3', '4', '5', '6', '7'
   };

/*
* base32 Decoder Lookup Table
* Warning: assumes ASCII encodings
*/
const uint8_t Base32::m_base32_to_bin[256] =
   {
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80,
   0x80, 0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0x81, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04,
   0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
   0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
   0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
   };

}

size_t base32_encode(char out[],
                     const uint8_t in[],
                     size_t input_length,
                     size_t& input_consumed,
                     bool final_inputs)
   {
   return base_encode(Base32(), out, in, input_length, input_consumed, final_inputs);
   }

std::string base32_encode(const uint8_t input[],
                          size_t input_length)
   {
   return base_encode_to_string(Base32(), input, input_length);
   }

size_t base32_decode(uint8_t out[],
                     const char in[],
                     size_t input_length,
                     size_t& input_consumed,
                     bool final_inputs,
                     bool ignore_ws)
   {
   return base_decode(Base32(), out, in, input_length, input_consumed, final_inputs, ignore_ws);
   }

size_t base32_decode(uint8_t output[],
                     const char input[],
                     size_t input_length,
                     bool ignore_ws)
   {
   return base_decode_full(Base32(), output, input, input_length, ignore_ws);
   }

size_t base32_decode(uint8_t output[],
                     const std::string& input,
                     bool ignore_ws)
   {
   return base32_decode(output, input.data(), input.length(), ignore_ws);
   }

secure_vector<uint8_t> base32_decode(const char input[],
                                     size_t input_length,
                                     bool ignore_ws)
   {
   return base_decode_to_vec<secure_vector<uint8_t>>(Base32(), input, input_length, ignore_ws);
   }

secure_vector<uint8_t> base32_decode(const std::string& input,
                                     bool ignore_ws)
   {
   return base32_decode(input.data(), input.size(), ignore_ws);
   }

}
