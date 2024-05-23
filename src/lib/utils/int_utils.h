/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_INT_UTILS_H_
#define BOTAN_INT_UTILS_H_

#include <botan/concepts.h>
#include <botan/exceptn.h>
#include <botan/types.h>
#include <limits>
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

namespace detail {

template <typename T>
concept int_or_strong_type = std::integral<T> || concepts::integral_strong_type<T>;

template <int_or_strong_type T>
struct unwrap_type {};

template <int_or_strong_type T>
   requires std::integral<T>
struct unwrap_type<T> {
      using type = T;
};

template <int_or_strong_type T>
   requires concepts::integral_strong_type<T>
struct unwrap_type<T> {
      using type = typename T::wrapped_type;
};

template <int_or_strong_type T>
using unwrap_type_t = typename unwrap_type<T>::type;

template <int_or_strong_type T>
constexpr auto unwrap(T t) -> unwrap_type_t<T> {
   if constexpr(std::integral<T>) {
      return t;
   } else {
      return t.get();
   }
}

template <int_or_strong_type T>
constexpr auto wrap(unwrap_type_t<T> t) -> T {
   if constexpr(std::integral<T>) {
      return t;
   } else {
      return T(t);
   }
}

}  // namespace detail

template <detail::int_or_strong_type RT, typename ExceptionType, detail::int_or_strong_type AT>
constexpr RT checked_cast_to_or_throw(AT i, std::string_view error_msg_on_fail) {
   const auto unwrapped_input = detail::unwrap(i);
   using unwrapped_input_type = detail::unwrap_type_t<AT>;
   using unwrapped_result_type = detail::unwrap_type_t<RT>;

   const auto unwrapped_result = static_cast<unwrapped_result_type>(unwrapped_input);
   if(unwrapped_input != static_cast<unwrapped_input_type>(unwrapped_result)) [[unlikely]] {
      throw ExceptionType(error_msg_on_fail);
   }

   return detail::wrap<RT>(unwrapped_result);
}

template <detail::int_or_strong_type RT, detail::int_or_strong_type AT>
constexpr RT checked_cast_to(AT i) {
   return checked_cast_to_or_throw<RT, Internal_Error>(i, "Error during integer conversion");
}

#define BOTAN_CHECKED_ADD(x, y) checked_add(x, y, __FILE__, __LINE__)
#define BOTAN_CHECKED_MUL(x, y) checked_mul(x, y)

}  // namespace Botan

#endif
