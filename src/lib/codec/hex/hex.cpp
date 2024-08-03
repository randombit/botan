/*
* Hex Encoding and Decoding
* (C) 2010,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hex.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/charset.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

uint16_t hex_encode_2nibble(uint8_t n8, bool uppercase) {
   // Offset for upper or lower case 'a' resp
   const uint16_t a_mask = uppercase ? 0x0707 : 0x2727;

   const uint16_t n = (static_cast<uint16_t>(n8 & 0xF0) << 4) | (n8 & 0x0F);
   // n >= 10? If so add offset
   const uint16_t diff = swar_lt<uint16_t>(0x0909, n) & a_mask;
   // Can't overflow between bytes, so don't need explicit SWAR addition:
   return n + 0x3030 + diff;
}

}  // namespace

void hex_encode(char output[], const uint8_t input[], size_t input_length, bool uppercase) {
   for(size_t i = 0; i != input_length; ++i) {
      const uint16_t h = hex_encode_2nibble(input[i], uppercase);
      output[2 * i] = get_byte<0>(h);
      output[2 * i + 1] = get_byte<1>(h);
   }
}

std::string hex_encode(const uint8_t input[], size_t input_length, bool uppercase) {
   std::string output(2 * input_length, 0);

   if(input_length) {
      hex_encode(&output.front(), input, input_length, uppercase);
   }

   return output;
}

namespace {

uint8_t hex_char_to_bin(char input) {
   // Starts of valid value ranges (v_lo) and their lengths (v_range)
   constexpr uint64_t v_lo = make_uint64(0, '0', 'a', 'A', ' ', '\n', '\t', '\r');
   constexpr uint64_t v_range = make_uint64(0, 10, 6, 6, 1, 1, 1, 1);

   const uint8_t x = static_cast<uint8_t>(input);
   const uint64_t x8 = x * 0x0101010101010101;

   const uint64_t v_mask = swar_in_range<uint64_t>(x8, v_lo, v_range) ^ 0x8000000000000000;

   // This is the offset added to x to get the value we need
   const uint64_t val_v = 0xd0a9c960767773 ^ static_cast<uint64_t>(0xFF - x) << 56;

   return x + static_cast<uint8_t>(val_v >> (8 * index_of_first_set_byte(v_mask)));
}

}  // namespace

size_t hex_decode(uint8_t output[], const char input[], size_t input_length, size_t& input_consumed, bool ignore_ws) {
   uint8_t* out_ptr = output;
   bool top_nibble = true;

   clear_mem(output, input_length / 2);

   for(size_t i = 0; i != input_length; ++i) {
      const uint8_t bin = hex_char_to_bin(input[i]);

      if(bin >= 0x10) {
         if(bin == 0x80 && ignore_ws) {
            continue;
         }

         throw Invalid_Argument(fmt("hex_decode: invalid character '{}'", format_char_for_display(input[i])));
      }

      if(top_nibble) {
         *out_ptr |= bin << 4;
      } else {
         *out_ptr |= bin;
      }

      top_nibble = !top_nibble;
      if(top_nibble) {
         ++out_ptr;
      }
   }

   input_consumed = input_length;
   size_t written = (out_ptr - output);

   /*
   * We only got half of a uint8_t at the end; zap the half-written
   * output and mark it as unread
   */
   if(!top_nibble) {
      *out_ptr = 0;
      input_consumed -= 1;
   }

   return written;
}

size_t hex_decode(uint8_t output[], const char input[], size_t input_length, bool ignore_ws) {
   size_t consumed = 0;
   size_t written = hex_decode(output, input, input_length, consumed, ignore_ws);

   if(consumed != input_length) {
      throw Invalid_Argument("hex_decode: input did not have full bytes");
   }

   return written;
}

size_t hex_decode(uint8_t output[], std::string_view input, bool ignore_ws) {
   return hex_decode(output, input.data(), input.length(), ignore_ws);
}

size_t hex_decode(std::span<uint8_t> output, std::string_view input, bool ignore_ws) {
   return hex_decode(output.data(), input.data(), input.length(), ignore_ws);
}

secure_vector<uint8_t> hex_decode_locked(const char input[], size_t input_length, bool ignore_ws) {
   secure_vector<uint8_t> bin(1 + input_length / 2);

   size_t written = hex_decode(bin.data(), input, input_length, ignore_ws);

   bin.resize(written);
   return bin;
}

secure_vector<uint8_t> hex_decode_locked(std::string_view input, bool ignore_ws) {
   return hex_decode_locked(input.data(), input.size(), ignore_ws);
}

std::vector<uint8_t> hex_decode(const char input[], size_t input_length, bool ignore_ws) {
   std::vector<uint8_t> bin(1 + input_length / 2);

   size_t written = hex_decode(bin.data(), input, input_length, ignore_ws);

   bin.resize(written);
   return bin;
}

std::vector<uint8_t> hex_decode(std::string_view input, bool ignore_ws) {
   return hex_decode(input.data(), input.size(), ignore_ws);
}

}  // namespace Botan
