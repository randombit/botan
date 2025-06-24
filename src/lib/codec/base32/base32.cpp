/*
* Base32 Encoding and Decoding
* (C) 2018 Erwan Chaussy
* (C) 2018,2020,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/base32.h>

#include <botan/internal/charset.h>
#include <botan/internal/codec_base.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rounding.h>

namespace Botan {

namespace {

class Base32 final {
   public:
      static std::string name() noexcept { return "base32"; }

      static constexpr size_t encoding_bytes_in() noexcept { return m_encoding_bytes_in; }

      static constexpr size_t encoding_bytes_out() noexcept { return m_encoding_bytes_out; }

      static constexpr size_t decoding_bytes_in() noexcept { return m_encoding_bytes_out; }

      static constexpr size_t decoding_bytes_out() noexcept { return m_encoding_bytes_in; }

      static constexpr size_t bits_consumed() noexcept { return m_encoding_bits; }

      static constexpr size_t remaining_bits_before_padding() noexcept { return m_remaining_bits_before_padding; }

      static constexpr size_t encode_max_output(size_t input_length) {
         return (round_up(input_length, m_encoding_bytes_in) / m_encoding_bytes_in) * m_encoding_bytes_out;
      }

      static constexpr size_t decode_max_output(size_t input_length) {
         return (round_up(input_length, m_encoding_bytes_out) * m_encoding_bytes_in) / m_encoding_bytes_out;
      }

      static void encode(char out[8], const uint8_t in[5]) noexcept;

      static uint8_t lookup_binary_value(char input) noexcept;

      static bool check_bad_char(uint8_t bin, char input, bool ignore_ws);

      static void decode(uint8_t* out_ptr, const uint8_t decode_buf[8]) {
         out_ptr[0] = (decode_buf[0] << 3) | (decode_buf[1] >> 2);
         out_ptr[1] = (decode_buf[1] << 6) | (decode_buf[2] << 1) | (decode_buf[3] >> 4);
         out_ptr[2] = (decode_buf[3] << 4) | (decode_buf[4] >> 1);
         out_ptr[3] = (decode_buf[4] << 7) | (decode_buf[5] << 2) | (decode_buf[6] >> 3);
         out_ptr[4] = (decode_buf[6] << 5) | decode_buf[7];
      }

      static size_t bytes_to_remove(size_t final_truncate) {
         return (final_truncate > 0) ? (final_truncate / 2) + 1 : 0;
      }

   private:
      static constexpr size_t m_encoding_bits = 5;
      static constexpr size_t m_remaining_bits_before_padding = 6;

      static constexpr size_t m_encoding_bytes_in = 5;
      static constexpr size_t m_encoding_bytes_out = 8;
};

namespace {

uint64_t lookup_base32_char(uint64_t x) {
   uint64_t r = x;
   r += swar_lt<uint64_t>(x, 0x1a1a1a1a1a1a1a1a) & 0x2929292929292929;
   r += 0x1818181818181818;

   return r;
}

}  // namespace

//static
void Base32::encode(char out[8], const uint8_t in[5]) noexcept {
   const uint8_t b0 = (in[0] & 0xF8) >> 3;
   const uint8_t b1 = ((in[0] & 0x07) << 2) | (in[1] >> 6);
   const uint8_t b2 = ((in[1] & 0x3E) >> 1);
   const uint8_t b3 = ((in[1] & 0x01) << 4) | (in[2] >> 4);
   const uint8_t b4 = ((in[2] & 0x0F) << 1) | (in[3] >> 7);
   const uint8_t b5 = ((in[3] & 0x7C) >> 2);
   const uint8_t b6 = ((in[3] & 0x03) << 3) | (in[4] >> 5);
   const uint8_t b7 = in[4] & 0x1F;

   auto b = lookup_base32_char(make_uint64(b0, b1, b2, b3, b4, b5, b6, b7));

   out[0] = static_cast<char>(get_byte<0>(b));
   out[1] = static_cast<char>(get_byte<1>(b));
   out[2] = static_cast<char>(get_byte<2>(b));
   out[3] = static_cast<char>(get_byte<3>(b));
   out[4] = static_cast<char>(get_byte<4>(b));
   out[5] = static_cast<char>(get_byte<5>(b));
   out[6] = static_cast<char>(get_byte<6>(b));
   out[7] = static_cast<char>(get_byte<7>(b));
}

//static
uint8_t Base32::lookup_binary_value(char input) noexcept {
   const uint8_t c = static_cast<uint8_t>(input);

   const auto is_alpha_upper = CT::Mask<uint8_t>::is_within_range(c, uint8_t('A'), uint8_t('Z'));
   const auto is_decimal = CT::Mask<uint8_t>::is_within_range(c, uint8_t('2'), uint8_t('7'));

   const auto is_equal = CT::Mask<uint8_t>::is_equal(c, uint8_t('='));
   const auto is_whitespace =
      CT::Mask<uint8_t>::is_any_of(c, {uint8_t(' '), uint8_t('\t'), uint8_t('\n'), uint8_t('\r')});

   const uint8_t c_upper = c - uint8_t('A');
   const uint8_t c_decim = c - uint8_t('2') + 26;

   uint8_t ret = 0xFF;  // default value

   ret = is_alpha_upper.select(c_upper, ret);
   ret = is_decimal.select(c_decim, ret);
   ret = is_equal.select(0x81, ret);
   ret = is_whitespace.select(0x80, ret);

   return ret;
}

//static
bool Base32::check_bad_char(uint8_t bin, char input, bool ignore_ws) {
   if(bin <= 0x1F) {
      return true;
   } else if(!(bin == 0x81 || (bin == 0x80 && ignore_ws))) {
      throw Invalid_Argument(fmt("base32_decode: invalid character '{}'", format_char_for_display(input)));
   }
   return false;
}

}  // namespace

size_t base32_encode(char out[], const uint8_t in[], size_t input_length, size_t& input_consumed, bool final_inputs) {
   return base_encode(Base32(), out, in, input_length, input_consumed, final_inputs);
}

std::string base32_encode(const uint8_t input[], size_t input_length) {
   return base_encode_to_string(Base32(), input, input_length);
}

size_t base32_decode(
   uint8_t out[], const char in[], size_t input_length, size_t& input_consumed, bool final_inputs, bool ignore_ws) {
   return base_decode(Base32(), out, in, input_length, input_consumed, final_inputs, ignore_ws);
}

size_t base32_decode(uint8_t output[], const char input[], size_t input_length, bool ignore_ws) {
   return base_decode_full(Base32(), output, input, input_length, ignore_ws);
}

size_t base32_decode(uint8_t output[], std::string_view input, bool ignore_ws) {
   return base32_decode(output, input.data(), input.length(), ignore_ws);
}

secure_vector<uint8_t> base32_decode(const char input[], size_t input_length, bool ignore_ws) {
   return base_decode_to_vec<secure_vector<uint8_t>>(Base32(), input, input_length, ignore_ws);
}

secure_vector<uint8_t> base32_decode(std::string_view input, bool ignore_ws) {
   return base32_decode(input.data(), input.size(), ignore_ws);
}

size_t base32_encode_max_output(size_t input_length) {
   return Base32::encode_max_output(input_length);
}

size_t base32_decode_max_output(size_t input_length) {
   return Base32::decode_max_output(input_length);
}

}  // namespace Botan
