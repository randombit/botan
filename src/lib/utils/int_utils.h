/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_INT_UTILS_H_
#define BOTAN_INT_UTILS_H_

#include <botan/concepts.h>
#include <botan/exceptn.h>
#include <botan/strong_type.h>
#include <botan/types.h>
#include <optional>

namespace Botan {

template <std::unsigned_integral T>
constexpr inline std::optional<T> checked_add(T a, T b) {
   const T r = a + b;
   if(r < a || r < b) {
      return {};
   }
   return r;
}

template <std::unsigned_integral T>
constexpr std::optional<T> checked_sub(T a, T b) {
   if(b > a) {
      return {};
   }
   return a - b;
}

template <std::unsigned_integral T, std::unsigned_integral... Ts>
   requires all_same_v<T, Ts...>
constexpr inline std::optional<T> checked_add(T a, T b, Ts... rest) {
   if(auto r = checked_add(a, b)) {
      return checked_add(r.value(), rest...);
   } else {
      return {};
   }
}

template <std::unsigned_integral T>
constexpr inline std::optional<T> checked_mul(T a, T b) {
   // Multiplication by 1U is a hack to work around C's insane
   // integer promotion rules.
   // https://stackoverflow.com/questions/24795651
   const T r = (1U * a) * b;
   // If a == 0 then the multiply certainly did not overflow
   // Otherwise r / a == b unless overflow occured
   if(a != 0 && r / a != b) {
      return {};
   }
   return r;
}

template <typename RT, typename ExceptionType, typename AT>
   requires std::integral<strong_type_wrapped_type<RT>> && std::integral<strong_type_wrapped_type<AT>>
constexpr RT checked_cast_to_or_throw(AT i, std::string_view error_msg_on_fail) {
   const auto unwrapped_input = unwrap_strong_type(i);

   const auto unwrapped_result = static_cast<strong_type_wrapped_type<RT>>(unwrapped_input);
   if(unwrapped_input != static_cast<strong_type_wrapped_type<AT>>(unwrapped_result)) [[unlikely]] {
      throw ExceptionType(error_msg_on_fail);
   }

   return wrap_strong_type<RT>(unwrapped_result);
}

template <typename RT, typename AT>
   requires std::integral<strong_type_wrapped_type<RT>> && std::integral<strong_type_wrapped_type<AT>>
constexpr RT checked_cast_to(AT i) {
   return checked_cast_to_or_throw<RT, Internal_Error>(i, "Error during integer conversion");
}

/**
* SWAR (SIMD within a word) byte-by-byte comparison
*
* This individually compares each byte of the provided words.
* It returns a mask which contains, for each byte, 0xFF if
* the byte in @p a was less than the byte in @p b. Otherwise the
* mask is 00.
*
* This implementation assumes that the high bits of each byte
* in both @p a and @p b are clear! It is possible to support the
* full range of bytes, but this requires additional comparisons.
*/
template <std::unsigned_integral T>
constexpr T swar_lt(T a, T b) {
   // The constant 0x808080... as a T
   constexpr T hi1 = (static_cast<T>(-1) / 255) << 7;
   // The constant 0x7F7F7F... as a T
   constexpr T lo7 = static_cast<T>(~hi1);
   T r = (lo7 - a + b) & hi1;
   // Currently the mask is 80 if lt, otherwise 00. Convert to FF/00
   return (r << 1) - (r >> 7);
}

/**
* SWAR (SIMD within a word) byte-by-byte comparison
*
* This individually compares each byte of the provided words.
* It returns a mask which contains, for each byte, 0x80 if
* the byte in @p a was less than the byte in @p b. Otherwise the
* mask is 00.
*
* This implementation assumes that the high bits of each byte
* in both @p lower and @p upper are clear! It is possible to support the
* full range of bytes, but this requires additional comparisons.
*/
template <std::unsigned_integral T>
constexpr T swar_in_range(T v, T lower, T upper) {
   // The constant 0x808080... as a T
   constexpr T hi1 = (static_cast<T>(-1) / 255) << 7;
   // The constant 0x7F7F7F... as a T
   constexpr T lo7 = ~hi1;

   const T sub = ((v | hi1) - (lower & lo7)) ^ ((v ^ (~lower)) & hi1);
   const T a_lo = sub & lo7;
   const T a_hi = sub & hi1;
   return (lo7 - a_lo + upper) & hi1 & ~a_hi;
}

/**
* Return the index of the first byte with the high bit set
*/
template <std::unsigned_integral T>
constexpr size_t index_of_first_set_byte(T v) {
   // The constant 0x010101... as a T
   constexpr T lo1 = (static_cast<T>(-1) / 255);
   // The constant 0x808080... as a T
   constexpr T hi1 = lo1 << 7;
   // How many bits to shift in order to get the top byte
   constexpr size_t bits = (sizeof(T) * 8) - 8;

   return static_cast<size_t>((((((v & hi1) - 1) & lo1) * lo1) >> bits) - 1);
}

}  // namespace Botan

#endif
