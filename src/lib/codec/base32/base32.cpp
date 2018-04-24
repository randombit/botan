/*
* Base32 Encoding and Decoding
* (C) 2018 Erwan Chaussy
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/base32.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/rounding.h>

namespace Botan {

namespace {

static const uint8_t BIN_TO_BASE32[32] =
   {
   'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
   'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
   '2', '3', '4', '5', '6', '7'
   };

void do_base32_encode(char out[8], const uint8_t in[5])
   {
   out[0] = BIN_TO_BASE32[(in[0] & 0xF8) >> 3];
   out[1] = BIN_TO_BASE32[((in[0] & 0x07) << 2) | (in[1] >> 6)];
   out[2] = BIN_TO_BASE32[((in[1] & 0x3E) >> 1)];
   out[3] = BIN_TO_BASE32[((in[1] & 0x01) << 4) | (in[2] >> 4)];
   out[4] = BIN_TO_BASE32[((in[2] & 0x0F) << 1) | (in[3] >> 7)];
   out[5] = BIN_TO_BASE32[((in[3] & 0x7C) >> 2)];
   out[6] = BIN_TO_BASE32[((in[3] & 0x03) << 3) | (in[4] >> 5)];
   out[7] = BIN_TO_BASE32[in[4] & 0x1F];
   }

}

size_t base32_encode(char out[],
                     const uint8_t in[],
                     size_t input_length,
                     size_t& input_consumed,
                     bool final_inputs)
   {
   input_consumed = 0;

   size_t input_remaining = input_length;
   size_t output_produced = 0;

   while(input_remaining >= 5)
      {
      do_base32_encode(out + output_produced, in + input_consumed);

      input_consumed += 5;
      output_produced += 8;
      input_remaining -= 5;
      }

   if(final_inputs && input_remaining)
      {
      uint8_t remainder[5] = {0};
      for(size_t i = 0; i != input_remaining; ++i)
         { remainder[i] = in[input_consumed + i]; }

      do_base32_encode(out + output_produced, remainder);

      size_t empty_bits = 8 * (5 - input_remaining);
      size_t index      = output_produced + 8 - 1;
      while(empty_bits >= 6)
         {
         out[index--] = '=';
         empty_bits -= 5;
         }

      input_consumed += input_remaining;
      output_produced += 8;
      }

   return output_produced;
   }

std::string base32_encode(const uint8_t input[],
                          size_t input_length)
   {
   const size_t output_length = base32_encode_max_output(input_length);
   std::string output(output_length, 0);

   size_t consumed = 0;
   size_t produced = 0;

   if(output_length > 0)
      {
      produced = base32_encode(&output.front(),
                               input, input_length,
                               consumed, true);
      }

   BOTAN_ASSERT_EQUAL(consumed, input_length, "Consumed the entire input");
   BOTAN_ASSERT_EQUAL(produced, output.size(), "Produced expected size");

   return output;
   }

size_t base32_decode(uint8_t output[],
                     const char input[],
                     size_t input_length,
                     size_t& input_consumed,
                     bool final_inputs,
                     bool ignore_ws)
   {
   /*
   * base32 Decoder Lookup Table
   * Warning: assumes ASCII encodings
   */
   static const uint8_t BASE32_TO_BIN[256] =
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

   uint8_t* out_ptr = output;
   uint8_t decode_buf[8];
   size_t decode_buf_pos = 0;
   size_t final_truncate = 0;

   clear_mem(output, input_length * 5 / 8);

   for(size_t i = 0; i != input_length; ++i)
      {
      const uint8_t bin = BASE32_TO_BIN[static_cast<uint8_t>(input[i])];

      if(bin <= 0x1F)
         {
         decode_buf[decode_buf_pos] = bin;
         decode_buf_pos += 1;
         }
      else if(!(bin == 0x81 || (bin == 0x80 && ignore_ws)))
         {
         std::string bad_char(1, input[i]);
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

      /*
      * If we're at the end of the input, pad with 0s and truncate
      */
      if(final_inputs && (i == input_length - 1))
         {
         if(decode_buf_pos)
            {
            for(size_t j = decode_buf_pos; j != 8; ++j)
               { decode_buf[j] = 0; }
            final_truncate = 8 - decode_buf_pos;
            decode_buf_pos = 8;
            }
         }

      if(decode_buf_pos == 8)
         {
         out_ptr[0] = (decode_buf[0] << 3) | (decode_buf[1] >> 2);
         out_ptr[1] = (decode_buf[1] << 6) | (decode_buf[2] << 1) | (decode_buf[3] >> 4);
         out_ptr[2] = (decode_buf[3] << 4) | (decode_buf[4] >> 1);
         out_ptr[3] = (decode_buf[4] << 7) | (decode_buf[5] << 2) | (decode_buf[6] >> 3);
         out_ptr[4] = (decode_buf[6] << 5) | decode_buf[7];

         out_ptr += 5;
         decode_buf_pos = 0;
         input_consumed = i + 1;
         }
      }

   while(input_consumed < input_length &&
         BASE32_TO_BIN[static_cast<uint8_t>(input[input_consumed])] == 0x80)
      {
      ++input_consumed;
      }

   size_t written = (out_ptr - output);

   if(final_truncate)
      {
      written -= (final_truncate / 2) + 1;
      }

   return written;
   }

size_t base32_decode(uint8_t output[],
                     const char input[],
                     size_t input_length,
                     bool ignore_ws)
   {
   size_t consumed = 0;
   size_t written = base32_decode(output, input, input_length,
                                  consumed, true, ignore_ws);

   if(consumed != input_length)
      { throw Invalid_Argument("base32_decode: input did not have full bytes"); }

   return written;
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
   const size_t output_length = base32_decode_max_output(input_length);
   secure_vector<uint8_t> bin(output_length);

   size_t written = base32_decode(bin.data(),
                                  input,
                                  input_length,
                                  ignore_ws);

   bin.resize(written);
   return bin;
   }

secure_vector<uint8_t> base32_decode(const std::string& input,
                                     bool ignore_ws)
   {
   return base32_decode(input.data(), input.size(), ignore_ws);
   }

size_t base32_encode_max_output(size_t input_length)
   {
   return (round_up(input_length, 5) / 5) * 8;
   }

size_t base32_decode_max_output(size_t input_length)
   {
   return (round_up(input_length, 8) * 5) / 8;
   }

}
