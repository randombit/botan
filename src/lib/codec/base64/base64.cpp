/*
* Base64 Encoding and Decoding
* (C) 2010,2015,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/base64.h>

#include <botan/exceptn.h>
#include <botan/internal/charset.h>
#include <botan/internal/codec_base.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rounding.h>

namespace Botan {

namespace {

class Base64 final {
   public:
      static std::string name() noexcept { return "base64"; }

      static size_t encoding_bytes_in() noexcept { return m_encoding_bytes_in; }

      static size_t encoding_bytes_out() noexcept { return m_encoding_bytes_out; }

      static size_t decoding_bytes_in() noexcept { return m_encoding_bytes_out; }

      static size_t decoding_bytes_out() noexcept { return m_encoding_bytes_in; }

      static size_t bits_consumed() noexcept { return m_encoding_bits; }

      static size_t remaining_bits_before_padding() noexcept { return m_remaining_bits_before_padding; }

      static size_t encode_max_output(size_t input_length) {
         return (round_up(input_length, m_encoding_bytes_in) / m_encoding_bytes_in) * m_encoding_bytes_out;
      }

      static size_t decode_max_output(size_t input_length) {
         return (round_up(input_length, m_encoding_bytes_out) * m_encoding_bytes_in) / m_encoding_bytes_out;
      }

      static void encode(char out[4], const uint8_t in[3]) noexcept;

      static uint8_t lookup_binary_value(char input) noexcept;

      static bool check_bad_char(uint8_t bin, char input, bool ignore_ws);

      static void decode(uint8_t* out_ptr, const uint8_t decode_buf[4]) {
         out_ptr[0] = (decode_buf[0] << 2) | (decode_buf[1] >> 4);
         out_ptr[1] = (decode_buf[1] << 4) | (decode_buf[2] >> 2);
         out_ptr[2] = (decode_buf[2] << 6) | decode_buf[3];
      }

      static size_t bytes_to_remove(size_t final_truncate) { return final_truncate; }

   private:
      static const size_t m_encoding_bits = 6;
      static const size_t m_remaining_bits_before_padding = 8;

      static const size_t m_encoding_bytes_in = 3;
      static const size_t m_encoding_bytes_out = 4;
};

uint32_t lookup_base64_chars(uint32_t x32) {
   /*
   * The basic insight of this approach is that our goal is computing
   * f(x) = y where x is in [0,63) and y is the correct base64 encoding.
   *
   * Instead of doing this directly, we compute
   * offset(x) such that f(x) = x + offset(x)
   *
   * This is described in
   * http://0x80.pl/notesen/2016-01-12-sse-base64-encoding.html#improved-version
   *
   * Here we do a SWAR (simd within a register) implementation of Wojciech's lookup_version2_swar
   */

   auto swar_lt_32 = [](uint32_t a, uint32_t b) -> uint32_t {
      // This assumes the high bits of both a and b are clear!!
      constexpr uint32_t hi = 0x80808080;
      constexpr uint32_t lo = 0x7F7F7F7F;
      uint32_t r = (lo - a + b) & hi;
      return (r << 1) - (r >> 7);
   };

   uint32_t r = x32 + 0x41414141;

   r += (~swar_lt_32(x32, 0x1A1A1A1A)) & 0x06060606;
   r -= (~swar_lt_32(x32, 0x34343434)) & 0x4B4B4B4B;
   r -= (~swar_lt_32(x32, 0x3E3E3E3E)) & 0x0F0F0F0F;
   r += (~swar_lt_32(x32, 0x3F3F3F3F)) & 0x03030303;

   return r;
}

//static
void Base64::encode(char out[4], const uint8_t in[3]) noexcept {
   const uint32_t b0 = (in[0] & 0xFC) >> 2;
   const uint32_t b1 = ((in[0] & 0x03) << 4) | (in[1] >> 4);
   const uint32_t b2 = ((in[1] & 0x0F) << 2) | (in[2] >> 6);
   const uint32_t b3 = in[2] & 0x3F;

   const uint32_t z = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;

   const uint32_t b64 = lookup_base64_chars(z);

   out[0] = static_cast<char>(get_byte<0>(b64));
   out[1] = static_cast<char>(get_byte<1>(b64));
   out[2] = static_cast<char>(get_byte<2>(b64));
   out[3] = static_cast<char>(get_byte<3>(b64));
}

//static
uint8_t Base64::lookup_binary_value(char input) noexcept {
   auto has_zero_byte = [](uint64_t v) { return ((v - 0x0101010101010101) & ~(v) & 0x8080808080808080); };

   // Assumes each byte is either 0x00 or 0x80
   auto index_of_first_set_byte = [](uint64_t v) {
      return ((((v - 1) & 0x0101010101010101) * 0x0101010101010101) >> 56) - 1;
   };

   auto swar_lt = [](uint64_t a, uint64_t b) -> uint64_t {
      // This assumes that the high bits of each byte of b are unset
      constexpr uint64_t hi = 0x8080808080808080;
      constexpr uint64_t lo7 = 0x7F7F7F7F7F7F7F7F;

      const uint64_t a_lo = a & lo7;
      const uint64_t a_hi = a & hi;
      uint64_t r = (lo7 - a_lo + b) & hi;
      r &= ~a_hi;
      return r;
   };

   auto swar_sub = [](uint64_t x, uint64_t y) {
      constexpr uint64_t hi = 0x8080808080808080;
      constexpr uint64_t lo7 = 0x7F7F7F7F7F7F7F7F;
      return ((x | hi) - (y & lo7)) ^ ((x ^ (~y)) & hi);
   };

   constexpr uint64_t lo = 0x0101010101010101;

   const uint8_t x = static_cast<uint8_t>(input);

   const uint64_t x8 = x * lo;

   // 'A', 'a', '0'
   const uint64_t val_l = 0x416130;
   // 26, 26, 10
   const uint64_t val_u = 0x1A1A0A;

   // If x is in one of the ranges return a mask. Otherwise we xor in at the
   // high word which will be our invalid marker
   auto v_mask = swar_lt(swar_sub(x8, val_l), val_u) ^ 0x80000000;

   // This is the offset added to x to get the value
   const uint64_t val_v = 0xbfb904 ^ (0xFF000000 - (x << 24));

   uint8_t z = x + static_cast<uint8_t>(val_v >> (8 * index_of_first_set_byte(v_mask)));

   // Specials:
   // [<empty>, '+', '/', '=', ' ', '\n', '\t', '\r']
   constexpr uint64_t specials_i = 0x002b2f3d200a090d;

   const uint64_t specials_v = 0x3e3f8180808080 ^ (static_cast<uint64_t>(z) << 56);

   const uint64_t smask = has_zero_byte(x8 ^ specials_i) ^ 0x8000000000000000;

   return static_cast<uint8_t>(specials_v >> (8 * index_of_first_set_byte(smask)));
}

//static
bool Base64::check_bad_char(uint8_t bin, char input, bool ignore_ws) {
   if(bin <= 0x3F) {
      return true;
   } else if(!(bin == 0x81 || (bin == 0x80 && ignore_ws))) {
      throw Invalid_Argument(fmt("base64_decode: invalid character '{}'", format_char_for_display(input)));
   }
   return false;
}

}  // namespace

size_t base64_encode(char out[], const uint8_t in[], size_t input_length, size_t& input_consumed, bool final_inputs) {
   return base_encode(Base64(), out, in, input_length, input_consumed, final_inputs);
}

std::string base64_encode(const uint8_t input[], size_t input_length) {
   return base_encode_to_string(Base64(), input, input_length);
}

size_t base64_decode(
   uint8_t out[], const char in[], size_t input_length, size_t& input_consumed, bool final_inputs, bool ignore_ws) {
   return base_decode(Base64(), out, in, input_length, input_consumed, final_inputs, ignore_ws);
}

size_t base64_decode(uint8_t output[], const char input[], size_t input_length, bool ignore_ws) {
   return base_decode_full(Base64(), output, input, input_length, ignore_ws);
}

size_t base64_decode(uint8_t output[], std::string_view input, bool ignore_ws) {
   return base64_decode(output, input.data(), input.length(), ignore_ws);
}

size_t base64_decode(std::span<uint8_t> output, std::string_view input, bool ignore_ws) {
   if(output.size() < base64_decode_max_output(input.size())) {
      throw Invalid_Argument("base64_decode: output buffer is too short");
   }
   return base64_decode(output.data(), input.data(), input.length(), ignore_ws);
}

secure_vector<uint8_t> base64_decode(const char input[], size_t input_length, bool ignore_ws) {
   return base_decode_to_vec<secure_vector<uint8_t>>(Base64(), input, input_length, ignore_ws);
}

secure_vector<uint8_t> base64_decode(std::string_view input, bool ignore_ws) {
   return base64_decode(input.data(), input.size(), ignore_ws);
}

size_t base64_encode_max_output(size_t input_length) {
   return Base64::encode_max_output(input_length);
}

size_t base64_decode_max_output(size_t input_length) {
   return Base64::decode_max_output(input_length);
}

}  // namespace Botan
