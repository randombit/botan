/*
* BigInt Encoding/Decoding
* (C) 1999-2010,2012,2019,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/mem_ops.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>
#include <algorithm>
#include <array>
#include <bit>

namespace Botan {

namespace {

consteval word decimal_conversion_radix() {
   if constexpr(sizeof(word) == 8) {
      return 10000000000000000000U;
   } else {
      return 1000000000U;
   }
}

consteval size_t decimal_conversion_radix_digits() {
   if constexpr(sizeof(word) == 8) {
      return 19;
   } else {
      return 9;
   }
}

/*
* Return floor(x / 10) using a multiplication by ceil(2^(W+3) / 10)
*/
constexpr word divide_by_10(word x) {
   constexpr word reciprocal = (WordInfo<word>::max / 5) * 4 + 1;
   word hi = 0;
   word_madd2(x, reciprocal, &hi);
   return hi >> 3;
}

}  // namespace

std::string BigInt::to_dec_string() const {
   // Note that this is quadratic in the length of the input, applications should
   // check sizes are acceptable before printing

   // Use the largest power of 10 that fits in a word
   constexpr word conversion_radix = decimal_conversion_radix();
   constexpr size_t radix_digits = decimal_conversion_radix_digits();

   // Each division by the radix removes at least this many bits from the value
   constexpr size_t radix_bits = std::bit_width(conversion_radix) - 1;

   constexpr auto div_radix = divide_precomp<word>::setup(conversion_radix);

   /*
   * A division produces its quotient words most significant first, which is
   * the order the following division consumes them in. So several successive
   * divisions can be done in a single pass over the value. The remainders are
   * independent dependency chains which the CPU can execute in parallel.
   */
   constexpr size_t divisions_per_pass = 3;

   // (over-)estimate of the number of digits needed; log2(10) ~ 3.3219
   const size_t digit_estimate = static_cast<size_t>(1 + (static_cast<double>(this->bits()) / 3.32));

   // (over-)estimate of db such that conversion_radix^db > *this
   const size_t digit_blocks = (digit_estimate + radix_digits - 1) / radix_digits;

   secure_vector<word> value(_data(), _data() + sig_words());
   size_t value_bits = this->bits();

   // The digits are written starting from the least significant, at the
   // end of the string. The extra leading character leaves room for a sign.
   std::string s(1 + digit_blocks * radix_digits, '0');
   size_t s_pos = s.size();

   for(size_t i = 0; i < digit_blocks; i += divisions_per_pass) {
      const size_t value_words = (value_bits + WordInfo<word>::bits - 1) / WordInfo<word>::bits;

      // Extract groups of digits into words
      std::array<word, divisions_per_pass> digit_groups = {};

      for(size_t j = value_words; j > 0; --j) {
         word w = value[j - 1];
         for(size_t k = 0; k != divisions_per_pass; ++k) {
            const auto [q, r] = div_radix.divmod_2to1_ct(digit_groups[k], w);
            digit_groups[k] = r;
            w = q;
         }
         value[j - 1] = w;
      }

      for(size_t k = 0; k != divisions_per_pass; ++k) {
         if(i + k < digit_blocks) {
            // Extract digits from the group
            word remainder = digit_groups[k];
            for(size_t j = 0; j != radix_digits; ++j) {
               const word q = divide_by_10(remainder);
               s_pos -= 1;
               s[s_pos] = static_cast<char>('0' + (remainder - q * 10));  // assumes ASCII
               remainder = q;
            }
         } else {
            BOTAN_ASSERT_NOMSG(digit_groups[k] == 0);
         }
      }

      value_bits -= std::min(value_bits, divisions_per_pass * radix_bits);
   }

   BOTAN_ASSERT_NOMSG(CT::all_zeros(value.data(), value.size()).as_bool());

   // remove leading zeros, but always keeping at least one digit
   size_t first_digit = std::min(s.find_first_not_of('0'), s.size() - 1);

   BOTAN_ASSERT_NOMSG(digit_estimate >= s.size() - first_digit);

   if(signum() < 0) {
      first_digit -= 1;
      s[first_digit] = '-';
   }

   s.erase(0, first_digit);

   return s;
}

std::string BigInt::to_hex_string() const {
   const size_t this_bytes = this->bytes();
   std::vector<uint8_t> bits(std::max<size_t>(1, this_bytes));

   if(this_bytes > 0) {
      this->serialize_to(bits);
   }

   std::string hrep;
   if(signum() < 0) {
      hrep += '-';
   }
   hrep += "0x";
   hrep += hex_encode(bits);
   return hrep;
}

//static
BigInt BigInt::from_radix_digits(std::string_view digits, size_t radix) {
   if(radix == 16) {
      secure_vector<uint8_t> binary;

      if(digits.size() % 2 == 1) {
         // Handle lack of leading 0
         const char buf0_with_leading_0[2] = {'0', digits[0]};

         binary = hex_decode_locked(buf0_with_leading_0, 2);

         if(digits.size() > 1) {
            binary += hex_decode_locked(&digits[1], digits.size() - 1, false);
         }
      } else {
         binary = hex_decode_locked(digits, false);
      }

      return BigInt::from_bytes(binary);
   } else if(radix == 10) {
      // Note that this is quadratic in the length of the input, applications should
      // check sizes are acceptable before parsing

      // Use the largest power of 10 that fits in a word, accumulating
      // groups of digits into word-sized chunks to minimize the number
      // of multiprecision multiplications.
      constexpr word conversion_radix = decimal_conversion_radix();
      constexpr size_t radix_digits = decimal_conversion_radix_digits();

      const size_t blocks = (digits.size() + radix_digits - 1) / radix_digits;

      // After b blocks the value is less than conversion_radix^b so fits in b words
      secure_vector<word> r(blocks);

      // The initial block is short if the digit count is not a multiple of radix_digits
      const size_t partial_block = digits.size() % radix_digits;
      size_t block_digits = (partial_block > 0) ? partial_block : radix_digits;
      size_t offset = 0;

      for(size_t b = 0; b != blocks; ++b) {
         word acc = 0;
         for(size_t j = 0; j != block_digits; ++j) {
            const char c = digits[offset + j];
            BOTAN_ARG_CHECK(c >= '0' && c <= '9', "Invalid decimal character");
            acc = acc * 10 + static_cast<word>(c - '0');
         }
         offset += block_digits;
         block_digits = radix_digits;

         // r = r * conversion_radix + acc
         word carry = acc;
         for(size_t i = 0; i != b; ++i) {
            r[i] = word_madd2(r[i], conversion_radix, &carry);
         }
         r[b] = carry;
      }

      return BigInt::_from_words(r);
   } else {
      throw Invalid_Argument("BigInt::from_radix_digits unknown radix");
   }
}

/*
* Encode two BigInt, with leading 0s if needed, and concatenate
*/
secure_vector<uint8_t> BigInt::encode_fixed_length_int_pair(const BigInt& n1, const BigInt& n2, size_t bytes) {
   if(n1.signum() < 0 || n2.signum() < 0) {
      throw Encoding_Error("encode_fixed_length_int_pair: values must be positive");
   }
   if(n1.bytes() > bytes || n2.bytes() > bytes) {
      throw Encoding_Error("encode_fixed_length_int_pair: values too large to encode properly");
   }
   secure_vector<uint8_t> output(2 * bytes);
   BufferStuffer stuffer(output);
   n1.serialize_to(stuffer.next(bytes));
   n2.serialize_to(stuffer.next(bytes));
   return output;
}

BigInt BigInt::decode(std::span<const uint8_t> buf, Base base) {
   if(base == Binary) {
      return BigInt::from_bytes(buf);
   }
   return BigInt::decode(buf.data(), buf.size(), base);
}

/*
* Decode a BigInt
*/
BigInt BigInt::decode(const uint8_t buf[], size_t length, Base base) {
   if(base == Binary) {
      return BigInt::from_bytes(std::span{buf, length});
   } else if(base == Hexadecimal) {
      const std::string_view sv{cast_uint8_ptr_to_char(buf), length};
      return BigInt::from_radix_digits(sv, 16);
   } else if(base == Decimal) {
      const std::string_view sv{cast_uint8_ptr_to_char(buf), length};
      return BigInt::from_radix_digits(sv, 10);
   } else {
      throw Invalid_Argument("Unknown BigInt decoding method");
   }
}

}  // namespace Botan
