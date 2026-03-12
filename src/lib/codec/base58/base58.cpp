/*
* (C) 2018,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/base58.h>

#include <botan/bigint.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/divide.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mul128.h>

namespace Botan {

namespace {

uint32_t sha256_d_checksum(const uint8_t input[], size_t input_length) {
   auto sha256 = HashFunction::create_or_throw("SHA-256");

   std::vector<uint8_t> checksum(32);

   sha256->update(input, input_length);
   sha256->final(checksum);

   sha256->update(checksum);
   sha256->final(checksum);

   return load_be<uint32_t>(checksum.data(), 0);
}

char lookup_base58_char(uint8_t x) {
   // "123456789 ABCDEFGH JKLMN PQRSTUVWXYZ abcdefghijk mnopqrstuvwxyz"
   BOTAN_DEBUG_ASSERT(x < 58);

   // This works by computing offset(x) such that x + offset(x) is equal to the
   // desired character

   size_t offset = 49;

   offset += CT::Mask<uint8_t>::is_gt(x, 8).if_set_return(7);
   offset += CT::Mask<uint8_t>::is_gt(x, 16).if_set_return(1);
   offset += CT::Mask<uint8_t>::is_gt(x, 21).if_set_return(1);
   offset += CT::Mask<uint8_t>::is_gt(x, 32).if_set_return(6);
   offset += CT::Mask<uint8_t>::is_gt(x, 43).if_set_return(1);
   return static_cast<char>(x + offset);
}

consteval word base58_conversion_radix() {
   if constexpr(sizeof(word) == 8) {
      // 58^10 largest that fits into a 64 bit word
      return 430804206899405824U;
   } else {
      // 58^5 largest that fits into a 32 bit word
      return 656356768U;
   }
}

consteval size_t base58_conversion_radix_digits() {
   if constexpr(sizeof(word) == 8) {
      return 10;
   } else {
      return 5;
   }
}

constexpr std::pair<uint8_t, word> divmod_58(word x) {
   BOTAN_DEBUG_ASSERT(x < base58_conversion_radix());

   word q = 0;

   // Division by constant 58
   //
   // Compilers will *usually* convert an expression like `x / 58` into
   // exactly this kind of operation, but not necessarily always...
   if constexpr(sizeof(word) == 4) {
      const uint64_t magic = 2369637129;  // ceil(2**36 / 29)
      const uint64_t z = magic * x;
      q = z >> 37;
   } else {
      const uint64_t magic = 5088756985850910791;  // ceil(2**67 / 29)
      uint64_t lo = 0;                             // unused
      uint64_t hi = 0;
      mul64x64_128(magic, x >> 1, &lo, &hi);
      q = static_cast<word>(hi >> 3);
   }

   const uint8_t r = static_cast<uint8_t>(x - q * 58);
   return std::make_pair(r, q);
}

std::string base58_encode(BigInt v, size_t leading_zeros) {
   constexpr word radix = base58_conversion_radix();
   constexpr size_t radix_digits = base58_conversion_radix_digits();

   BigInt q;
   std::vector<uint8_t> digits;

   while(v.is_nonzero()) {
      word r = 0;
      ct_divide_word(v, radix, q, r);

      for(size_t i = 0; i != radix_digits; ++i) {
         const auto [r58, q58] = divmod_58(r);
         digits.push_back(r58);
         r = q58;
      }
      v.swap(q);
   }

   // remove leading zeros
   while(!digits.empty() && digits.back() == 0) {
      digits.pop_back();
   }

   std::string result;

   for(const uint8_t d : digits) {
      result.push_back(lookup_base58_char(d));
   }

   for(size_t i = 0; i != leading_zeros; ++i) {
      result.push_back('1');  // 'zero' byte
   }

   return std::string(result.rbegin(), result.rend());
}

template <typename T, typename Z>
size_t count_leading_zeros(const T input[], size_t input_length, Z zero) {
   size_t leading_zeros = 0;

   while(leading_zeros < input_length && input[leading_zeros] == zero) {
      leading_zeros += 1;
   }

   return leading_zeros;
}

uint8_t base58_value_of(char input) {
   /*
   * Alphabet: "123456789 ABCDEFGH JKLMN PQRSTUVWXYZ abcdefghijk mnopqrstuvwxyz"
   *
   * Valid input ranges are:
   *
   * '1'-'9' (length 9)
   * 'A'-'H' (length 8)
   * 'J'-'N' (length 5)
   * 'P'-'Z' (length 11)
   * 'a'-'k' (length 11)
   * 'm'-'z' (length 14)
   */
   constexpr uint64_t v_lo = make_uint64(0, '1', 'A', 'J', 'P', 'a', 'm', 0);
   constexpr uint64_t v_range = make_uint64(0, 9, 8, 5, 11, 11, 14, 0);

   const uint8_t x = static_cast<uint8_t>(input);
   const uint64_t x8 = x * 0x0101010101010101;  // replicate x to each byte

   // is x8 in any of the ranges?
   const uint64_t v_mask = swar_in_range<uint64_t>(x8, v_lo, v_range) ^ 0x8000000000000000;

   /*
   * Offsets mapping from the character code x to the base58 value of x in each range
   *
   * For example '2' (50) + 0xCF == 1
   *
   * Fallback byte 7 is set to 0xFF - x so that if used it results in 0xFF to indicate invalid.
   */
   constexpr uint64_t val_v_const = make_uint64(0, 0xCF, 0xC8, 0xC7, 0xC6, 0xC0, 0xBF, 0);
   const uint64_t val_v = val_v_const ^ (static_cast<uint64_t>(0xFF - x) << 56);

   return x + static_cast<uint8_t>(val_v >> (8 * index_of_first_set_byte(v_mask)));
}

}  // namespace

std::string base58_encode(const uint8_t input[], size_t input_length) {
   const BigInt v(input, input_length);
   return base58_encode(v, count_leading_zeros(input, input_length, 0));
}

std::string base58_check_encode(const uint8_t input[], size_t input_length) {
   BigInt v(input, input_length);
   v <<= 32;
   v += sha256_d_checksum(input, input_length);
   return base58_encode(v, count_leading_zeros(input, input_length, 0));
}

std::vector<uint8_t> base58_decode(const char input[], size_t input_length) {
   const size_t leading_zeros = count_leading_zeros(input, input_length, '1');

   std::vector<uint8_t> digits;

   for(size_t i = leading_zeros; i != input_length; ++i) {
      const char c = input[i];

      if(c == ' ' || c == '\n') {
         continue;
      }

      const uint8_t idx = base58_value_of(c);

      if(idx == 0xFF) {
         throw Decoding_Error("Invalid base58");
      }

      digits.push_back(idx);
   }

   BigInt v;

   constexpr word radix1 = 58;
   constexpr word radix2 = 58 * 58;
   constexpr word radix3 = 58 * 58 * 58;
   constexpr word radix4 = 58 * 58 * 58 * 58;

   std::span<uint8_t> remaining{digits};

   while(remaining.size() >= 4) {
      const word accum = radix3 * remaining[0] + radix2 * remaining[1] + radix1 * remaining[2] + remaining[3];
      v *= radix4;
      v += accum;
      remaining = remaining.subspan(4);
   }

   while(!remaining.empty()) {
      v *= 58;
      v += remaining[0];
      remaining = remaining.subspan(1);
   }

   return v.serialize(v.bytes() + leading_zeros);
}

std::vector<uint8_t> base58_check_decode(const char input[], size_t input_length) {
   std::vector<uint8_t> dec = base58_decode(input, input_length);

   if(dec.size() < 4) {
      throw Decoding_Error("Invalid base58 too short for checksum");
   }

   const uint32_t computed_checksum = sha256_d_checksum(dec.data(), dec.size() - 4);
   const uint32_t checksum = load_be<uint32_t>(&dec[dec.size() - 4], 0);

   if(checksum != computed_checksum) {
      throw Decoding_Error("Invalid base58 checksum");
   }

   dec.resize(dec.size() - 4);

   return dec;
}

}  // namespace Botan
