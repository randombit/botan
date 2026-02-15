/*
* (C) 2022 René Meusel
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_ARB_EQ_H_
#define BOTAN_TEST_ARB_EQ_H_

#include "tests.h"

#include <sstream>

namespace Botan_Tests {

namespace detail {

template <typename, typename = void>
constexpr bool has_std_to_string = false;
template <typename T>
constexpr bool has_std_to_string<T, std::void_t<decltype(std::to_string(std::declval<T>()))>> = true;

template <typename, typename = void>
constexpr bool has_ostream_operator = false;
template <typename T>
constexpr bool
   has_ostream_operator<T, std::void_t<decltype(operator<<(std::declval<std::ostringstream&>(), std::declval<T>()))>> =
      true;

template <typename T>
struct is_optional : std::false_type {};

template <typename T>
struct is_optional<std::optional<T>> : std::true_type {};

template <typename T>
constexpr bool is_optional_v = is_optional<T>::value;

template <typename T>
std::string to_string(const T& v) {
   if constexpr(detail::is_optional_v<T>) {
      return (v.has_value()) ? to_string(v.value()) : std::string("std::nullopt");
   } else if constexpr(detail::has_ostream_operator<T>) {
      std::ostringstream oss;
      oss << v;
      return oss.str();
   } else if constexpr(detail::has_std_to_string<T>) {
      //static_assert(false, "no std::to_string for you");
      return std::to_string(v);
   } else {
      //static_assert(false, "unknown type");
      return "<?>";
   }
}

}  // namespace detail

template <typename T>
bool test_arb_eq(Test::Result& result, std::string_view what, const T& produced, const T& expected) {
   static_assert(!std::convertible_to<T, std::span<const uint8_t>>, "Use test_bin_eq");
   static_assert(!std::convertible_to<T, std::string_view>, "Use test_str_eq");
   static_assert(!std::is_integral_v<T>, "Use test_{sz,u8,u16,u32,u64}_eq");
   static_assert(!std::is_enum_v<T>, "Use test_enum_eq");

   if(produced == expected) {
      return result.test_success(what);
   } else {
      std::ostringstream out;

      out << result.who() << " " << what << " produced unexpected result '" << detail::to_string(produced)
          << "' expected '" << detail::to_string(expected) << "'";

      return result.test_failure(out.str());
   }
}

}  // namespace Botan_Tests

#endif
