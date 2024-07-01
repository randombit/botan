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

#define BOTAN_CHECKED_ADD(x, y) checked_add(x, y, __FILE__, __LINE__)
#define BOTAN_CHECKED_MUL(x, y) checked_mul(x, y)

}  // namespace Botan

#endif
