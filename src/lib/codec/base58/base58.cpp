/*
* (C) 2018,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/base58.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/mem_ops.h>
#include <botan/secmem.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/mul128.h>
#include <algorithm>
#include <bit>
#include <optional>

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

/*
* In-place constant time division of a little-endian word vector by the
* base58 conversion radix, returning the remainder
*/
word ct_divmod_base58radix(std::span<word> x) {
   constexpr divide_precomp<word> radix_div(base58_conversion_radix());

   word rem = 0;

   for(size_t i = x.size(); i > 0; --i) {
      const auto [q, r] = radix_div.divmod_2to1(rem, x[i - 1]);
      x[i - 1] = q;
      rem = r;
   }

   return rem;
}

// v = v * mul + add; requires that the result fits in v
void ct_mul_add_word(std::span<word> v, word mul, word add) {
   word carry = add;

   for(word& w : v) {
      w = word_madd2(w, mul, &carry);
   }

   // The final carry is provably zero for in-range inputs
   CT::unpoison(carry);
   BOTAN_DEBUG_ASSERT(carry == 0);
}

// Count of leading bytes equal to c, without leaking which bytes matched
size_t ct_count_leading_eq(std::span<const uint8_t> input, uint8_t c) {
   constexpr uint64_t lo1 = 0x0101010101010101;
   constexpr uint64_t hi1 = lo1 << 7;
   constexpr uint64_t lo7 = ~hi1;

   size_t count = 0;
   auto all_eq = CT::Mask<uint64_t>::set();

   while(input.size() >= 8) {
      const uint64_t x = load_le<uint64_t>(input.first<8>()) ^ (lo1 * c);
      // 0x80 in each byte of x which is zero
      const uint64_t z = ~(((x & lo7) + lo7) | x) & hi1;
      // 0x80 in each byte where it and all preceding bytes are zero
      uint64_t p = z & ((z << 8) | 0x80);
      p &= (p << 16) | 0x8080;
      p &= (p << 32) | 0x80808080;
      // Number of set bytes in p
      const uint64_t n = ((p >> 7) * lo1) >> 56;
      count += static_cast<size_t>(all_eq.if_set_return(n));
      all_eq &= CT::Mask<uint64_t>::is_equal(p, hi1);
      input = input.subspan(8);
   }

   for(const uint8_t b : input) {
      all_eq &= CT::Mask<uint64_t>::is_equal(b, c);
      count += static_cast<size_t>(all_eq.if_set_return(1));
   }

   return count;
}

size_t ct_count_trailing_zeros(std::span<const uint8_t> input) {
   size_t count = 0;
   auto all_zero = CT::Mask<uint8_t>::set();

   for(size_t i = input.size(); i > 0; --i) {
      all_zero &= CT::Mask<uint8_t>::is_zero(input[i - 1]);
      count += all_zero.if_set_return(1);
   }

   return count;
}

// Load a big-endian byte string into a little-endian word vector
secure_vector<word> to_le_words(std::span<const uint8_t> input) {
   secure_vector<word> v((input.size() + sizeof(word) - 1) / sizeof(word));

   for(size_t i = 0; i != input.size(); ++i) {
      const uint8_t b = input[input.size() - 1 - i];
      v[i / sizeof(word)] |= static_cast<word>(b) << (8 * (i % sizeof(word)));
   }

   return v;
}

std::string base58_encode(std::span<word> v, size_t leading_zeros) {
   constexpr size_t radix_digits = base58_conversion_radix_digits();

   // Each division removes at least radix_bits bits, so after chunks
   // divisions v is zero regardless of its value
   constexpr size_t radix_bits = std::bit_width(base58_conversion_radix()) - 1;
   const size_t chunks = (v.size() * WordInfo<word>::bits + radix_bits - 1) / radix_bits;

   secure_vector<uint8_t> digits;
   digits.reserve(chunks * radix_digits);

   for(size_t c = 0; c != chunks; ++c) {
      word r = ct_divmod_base58radix(v);

      for(size_t i = 0; i != radix_digits; ++i) {
         const auto [r58, q58] = divmod_58(r);
         digits.push_back(r58);
         r = q58;
      }
   }

   // Render all digits; leading zero digits become '1', same as leading zero bytes
   std::string result(leading_zeros + digits.size(), '1');

   for(size_t i = 0; i != digits.size(); ++i) {
      result[result.size() - 1 - i] = lookup_base58_char(digits[i]);
   }

   // Remove leading zero digits; this reveals only the output length
   const size_t zero_digits = ct_count_trailing_zeros(digits);
   CT::unpoison(zero_digits);
   CT::unpoison(result);
   result.erase(0, zero_digits);
   return result;
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

   constexpr uint64_t expand8 = 0x0101010101010101;

   const uint8_t x = static_cast<uint8_t>(input);
   const uint64_t x8 = x * expand8;  // replicate x to each byte

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

/*
* Decode 8 base58 characters at once
*
* Returns the digit value of each byte of @p w, in the same byte position, or
* nullopt if any byte is not a valid base58 character.
*/
std::optional<uint64_t> base58_values_of_8(uint64_t w) {
   constexpr uint64_t lo1 = 0x0101010101010101;
   constexpr uint64_t hi1 = 0x8080808080808080;

   // For each byte v (assumed < 0x80), 0x80 if v > c else 0x00
   const uint64_t w80 = w | hi1;
   auto gt = [w80](char c) { return (w80 - lo1 * static_cast<uint8_t>(c + 1)) & hi1; };

   /*
    * Alphabet: "123456789 ABCDEFGH JKLMN PQRSTUVWXYZ abcdefghijk mnopqrstuvwxyz"
    *
    * This is ASCII '1' through 'z' with gaps ':'-'@', 'I', 'O', '['-'`' and
    * 'l'. The value of a character is its ASCII code minus '1' minus the total
    * size of the gaps below it.
    */
   // NOLINTBEGIN(*-confusable-identifiers)
   const uint64_t gt_0 = gt('0');
   const uint64_t gt_9 = gt('9');
   const uint64_t gt_at = gt('@');
   const uint64_t gt_H = gt('H');
   const uint64_t gt_I = gt('I');
   const uint64_t gt_N = gt('N');
   const uint64_t gt_O = gt('O');
   const uint64_t gt_Z = gt('Z');
   const uint64_t gt_bt = gt('`');
   const uint64_t gt_k = gt('k');
   const uint64_t gt_l = gt('l');
   const uint64_t gt_z = gt('z');
   // NOLINTEND(*-confusable-identifiers)

   const uint64_t in_gap = (gt_9 & ~gt_at) | (gt_H & ~gt_I) | (gt_N & ~gt_O) | (gt_Z & ~gt_bt) | (gt_k & ~gt_l);
   const uint64_t invalid = (w & hi1) | (~gt_0 & hi1) | gt_z | in_gap;

   if(invalid != 0) {
      return std::nullopt;
   }

   // Each byte is at most 65 and for valid input no byte of w is less than its
   // offset, so neither the sum nor the subtraction carries between bytes
   const uint64_t offsets = lo1 * 49 + 7 * (gt_at >> 7) + (gt_I >> 7) + (gt_O >> 7) + 6 * (gt_Z >> 7) + (gt_l >> 7);
   return w - offsets;
}

}  // namespace

std::string base58_encode(const uint8_t input[], size_t input_length) {
   const auto in = std::span{input, input_length};
   const auto poison_guard = CT::scoped_poison(in);

   const size_t leading_zeros = ct_count_leading_eq(in, 0);
   CT::unpoison(leading_zeros);

   auto v = to_le_words(in);
   return base58_encode(v, leading_zeros);
}

std::string base58_check_encode(const uint8_t input[], size_t input_length) {
   const auto in = std::span{input, input_length};
   const auto poison_guard = CT::scoped_poison(in);

   const size_t leading_zeros = ct_count_leading_eq(in, 0);
   CT::unpoison(leading_zeros);

   secure_vector<uint8_t> buf(input_length + 4);
   copy_mem(buf.data(), input, input_length);
   store_be(sha256_d_checksum(input, input_length), buf.data() + input_length);

   auto v = to_le_words(buf);
   return base58_encode(v, leading_zeros);
}

std::vector<uint8_t> base58_decode(const char input[], size_t input_length) {
   const auto in = as_span_of_bytes(input, input_length);

   const size_t leading_zeros = ct_count_leading_eq(in, static_cast<uint8_t>('1'));

   secure_vector<uint8_t> digits(input_length - leading_zeros);
   size_t digit_count = 0;

   auto chars = in.subspan(leading_zeros);

   while(!chars.empty()) {
      if(chars.size() >= 8) {
         if(auto values = base58_values_of_8(load_le<uint64_t>(chars.first<8>()))) {
            store_le(std::span{digits}.subspan(digit_count).first<8>(), *values);
            digit_count += 8;
            chars = chars.subspan(8);
            continue;
         }
      }

      // Fewer than 8 characters remain, or the block contains whitespace or an invalid character
      const size_t n = std::min<size_t>(chars.size(), 8);
      for(size_t i = 0; i != n; ++i) {
         const char c = static_cast<char>(chars[i]);

         if(c == ' ' || c == '\n') {
            continue;
         }

         const uint8_t idx = base58_value_of(c);

         if(idx == 0xFF) {
            throw Decoding_Error("Invalid base58");
         }

         digits[digit_count++] = idx;
      }
      chars = chars.subspan(n);
   }

   digits.resize(digit_count);

   // From here on the digit values are secret; only lengths are revealed
   const auto poison_guard = CT::scoped_poison(digits);

   constexpr size_t radix_digits = base58_conversion_radix_digits();

   // Since 58 < 2^6, any value of digits.size() base58 digits fits in
   // 6 bits per digit
   secure_vector<word> v((6 * digits.size() + WordInfo<word>::bits - 1) / WordInfo<word>::bits);

   // Combine up to radix_digits digits into a single word
   auto accum_digits = [](std::span<const uint8_t> chunk) {
      BOTAN_DEBUG_ASSERT(chunk.size() <= radix_digits);
      word accum = 0;
      for(const uint8_t d : chunk) {
         accum = accum * 58 + d;
      }
      return accum;
   };

   std::span<const uint8_t> remaining{digits};

   // Consume a leading partial chunk so that all remaining chunks are full;
   // since v is zero at this point no multiplication is needed
   if(const size_t partial = remaining.size() % radix_digits; partial > 0) {
      v[0] = accum_digits(remaining.first(partial));
      remaining = remaining.subspan(partial);
   }

   while(!remaining.empty()) {
      ct_mul_add_word(v, base58_conversion_radix(), accum_digits(remaining.first(radix_digits)));
      remaining = remaining.subspan(radix_digits);
   }

   secure_vector<uint8_t> vbytes(v.size() * sizeof(word));
   for(size_t i = 0; i != v.size(); ++i) {
      store_be(v[v.size() - 1 - i], vbytes.data() + i * sizeof(word));
   }

   const size_t sig_bytes = vbytes.size() - ct_count_leading_eq(vbytes, 0);
   CT::unpoison(sig_bytes);

   std::vector<uint8_t> output(leading_zeros + sig_bytes);
   copy_mem(output.data() + leading_zeros, vbytes.data() + vbytes.size() - sig_bytes, sig_bytes);
   CT::unpoison(output);
   return output;
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
