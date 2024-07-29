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
   const uint8_t c = static_cast<uint8_t>(input);

   const auto is_alpha_upper = CT::Mask<uint8_t>::is_lt(c - uint8_t('A'), 26);
   const auto is_alpha_lower = CT::Mask<uint8_t>::is_lt(c - uint8_t('a'), 26);
   const auto is_decimal = CT::Mask<uint8_t>::is_lt(c - uint8_t('0'), 10);

   const auto is_plus = CT::Mask<uint8_t>::is_equal(c, uint8_t('+'));
   const auto is_slash = CT::Mask<uint8_t>::is_equal(c, uint8_t('/'));
   const auto is_equal = CT::Mask<uint8_t>::is_equal(c, uint8_t('='));

   const auto is_whitespace =
      CT::Mask<uint8_t>::is_any_of(c, {uint8_t(' '), uint8_t('\t'), uint8_t('\n'), uint8_t('\r')});

   const uint8_t c_upper = c - uint8_t('A');
   const uint8_t c_lower = c - uint8_t('a') + 26;
   const uint8_t c_decim = c - uint8_t('0') + 2 * 26;

   uint8_t ret = 0xFF;  // default value

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
