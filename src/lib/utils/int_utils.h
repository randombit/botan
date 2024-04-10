/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_INT_UTILS_H_
#define BOTAN_INT_UTILS_H_

#include <botan/concepts.h>
#include <botan/types.h>
#include <limits>
#include <optional>

namespace Botan {

template <std::unsigned_integral T>
constexpr inline std::optional<T> checked_add(T a, T b) {
   const T r = a + b;
   if(r - a != b) {
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

template <std::unsigned_integral ReturnT>
constexpr inline std::optional<ReturnT> checked_cast(std::unsigned_integral auto input) {
   if(std::numeric_limits<ReturnT>::max() < input) {
      return {};
   }
   return static_cast<ReturnT>(input);
}

}  // namespace Botan

#endif
