/*
* (C) 2022 René Meusel
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_ARB_EQ_H_
#define BOTAN_TEST_ARB_EQ_H_

#include "tests.h"

#include <array>
#include <span>
#include <sstream>
#include <vector>

namespace Botan_Tests {

namespace detail {

/* Does T have a member to_string() returning std::string? */
template <typename, typename = void>
constexpr bool has_member_to_string = false;

template <typename T>
constexpr bool has_member_to_string<T, std::void_t<decltype(std::declval<const T&>().to_string())>> =
   std::is_convertible_v<decltype(std::declval<const T&>().to_string()), std::string>;

/* Is std::to_string(T) defined? */
template <typename, typename = void>
constexpr bool has_std_to_string = false;

template <typename T>
constexpr bool has_std_to_string<T, std::void_t<decltype(std::to_string(std::declval<T>()))>> = true;

/* Is ostream<<(T) defined? */
template <typename, typename = void>
constexpr bool has_ostream_operator = false;

template <typename T>
constexpr bool
   has_ostream_operator<T, std::void_t<decltype(operator<<(std::declval<std::ostringstream&>(), std::declval<T>()))>> =
      true;

/* Is T a std::optional? */
template <typename T>
struct is_optional : std::false_type {};

template <typename T>
struct is_optional<std::optional<T>> : std::true_type {};

template <typename T>
constexpr bool is_optional_v = is_optional<T>::value;

/* Is T a std::vector? */
template <typename T>
struct is_vector : std::false_type {};

template <typename T>
struct is_vector<std::vector<T>> : std::true_type {};

template <typename T>
constexpr bool is_vector_v = is_vector<T>::value;

/* Is T a std::array? */
template <typename T>
struct is_std_array : std::false_type {};

template <typename T, std::size_t N>
struct is_std_array<std::array<T, N>> : std::true_type {};

template <typename T>
constexpr bool is_std_array_v = is_std_array<T>::value;

template <typename T>
std::string to_string(const T& v) {
   if constexpr(detail::is_optional_v<T>) {
      return (v.has_value()) ? to_string(v.value()) : std::string("std::nullopt");
   } else if constexpr(detail::is_vector_v<T> || detail::is_std_array_v<T>) {
      std::ostringstream oss;
      oss << "{";
      for(size_t i = 0; i != v.size(); ++i) {
         if(i > 0) {
            oss << ", ";
         }
         oss << to_string(v[i]);
      }
      oss << "}";
      return oss.str();
   } else if constexpr(detail::has_member_to_string<T>) {
      return v.to_string();
   } else if constexpr(detail::has_ostream_operator<T>) {
      std::ostringstream oss;
      oss << v;
      return oss.str();
   } else if constexpr(detail::has_std_to_string<T>) {
      return std::to_string(v);
   } else {
      static_assert(!sizeof(T), "This type is not printable");
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
