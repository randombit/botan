/*
* BigInt Encoding/Decoding
* (C) 1999-2010,2012,2019,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>

#include <botan/hex.h>
#include <botan/internal/divide.h>
#include <botan/internal/stl_util.h>

namespace Botan {

std::string BigInt::to_dec_string() const {
   // Use the largest power of 10 that fits in a word
#if(BOTAN_MP_WORD_BITS == 64)
   const word conversion_radix = 10000000000000000000U;
   const word radix_digits = 19;
#else
   const word conversion_radix = 1000000000U;
   const word radix_digits = 9;
#endif

   // (over-)estimate of the number of digits needed; log2(10) ~ 3.3219
   const size_t digit_estimate = static_cast<size_t>(1 + (this->bits() / 3.32));

   // (over-)estimate of db such that conversion_radix^db > *this
   const size_t digit_blocks = (digit_estimate + radix_digits - 1) / radix_digits;

   BigInt value = *this;
   value.set_sign(Positive);

   // Extract groups of digits into words
   std::vector<word> digit_groups(digit_blocks);

   for(size_t i = 0; i != digit_blocks; ++i) {
      word remainder = 0;
      ct_divide_word(value, conversion_radix, value, remainder);
      digit_groups[i] = remainder;
   }

   BOTAN_ASSERT_NOMSG(value.is_zero());

   // Extract digits from the groups
   std::vector<uint8_t> digits(digit_blocks * radix_digits);

   for(size_t i = 0; i != digit_blocks; ++i) {
      word remainder = digit_groups[i];
      for(size_t j = 0; j != radix_digits; ++j) {
         // Compiler should convert div/mod by 10 into mul by magic constant
         const word digit = remainder % 10;
         remainder /= 10;
         digits[radix_digits * i + j] = static_cast<uint8_t>(digit);
      }
   }

   // remove leading zeros
   while(!digits.empty() && digits.back() == 0) {
      digits.pop_back();
   }

   BOTAN_ASSERT_NOMSG(digit_estimate >= digits.size());

   // Reverse the digits to big-endian and format to text
   std::string s;
   s.reserve(1 + digits.size());

   if(is_negative()) {
      s += "-";
   }

   // Reverse and convert to textual digits
   for(auto i = digits.rbegin(); i != digits.rend(); ++i) {
      s.push_back(*i + '0');  // assumes ASCII
   }

   if(s.empty()) {
      s += "0";
   }

   return s;
}

std::string BigInt::to_hex_string() const {
   const size_t this_bytes = this->bytes();
   std::vector<uint8_t> bits(std::max<size_t>(1, this_bytes));

   if(this_bytes > 0) {
      this->serialize_to(bits);
   }

   std::string hrep;
   if(is_negative()) {
      hrep += "-";
   }
   hrep += "0x";
   hrep += hex_encode(bits);
   return hrep;
}

/*
* Encode two BigInt, with leading 0s if needed, and concatenate
*/
secure_vector<uint8_t> BigInt::encode_fixed_length_int_pair(const BigInt& n1, const BigInt& n2, size_t bytes) {
   if(n1.is_negative() || n2.is_negative()) {
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
      BigInt r;
      secure_vector<uint8_t> binary;

      if(length % 2) {
         // Handle lack of leading 0
         const char buf0_with_leading_0[2] = {'0', static_cast<char>(buf[0])};

         binary = hex_decode_locked(buf0_with_leading_0, 2);

         if(length > 1) {
            binary += hex_decode_locked(cast_uint8_ptr_to_char(&buf[1]), length - 1, false);
         }
      } else {
         binary = hex_decode_locked(cast_uint8_ptr_to_char(buf), length, false);
      }

      r.assign_from_bytes(binary);
      return r;
   } else if(base == Decimal) {
      BigInt r;
      // This could be made faster using the same trick as to_dec_string
      for(size_t i = 0; i != length; ++i) {
         const char c = buf[i];

         if(c < '0' || c > '9') {
            throw Invalid_Argument("BigInt::decode: invalid decimal char");
         }

         const uint8_t x = c - '0';
         BOTAN_ASSERT_NOMSG(x < 10);

         r *= 10;
         r += x;
      }
      return r;
   } else {
      throw Invalid_Argument("Unknown BigInt decoding method");
   }
}

}  // namespace Botan
