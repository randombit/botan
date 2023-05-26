/**
 * Useful concepts that are available throughout the library
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_CONCEPTS_H_
#define BOTAN_CONCEPTS_H_

#include <compare>
#include <concepts>
#include <cstdint>
#include <ostream>
#include <type_traits>

namespace Botan {

template <typename T, typename Tag, typename... Capabilities>
class Strong;

template <typename... Ts>
struct is_strong_type : std::false_type {};

template <typename... Ts>
struct is_strong_type<Strong<Ts...>> : std::true_type {};

template <typename... Ts>
constexpr bool is_strong_type_v = is_strong_type<std::remove_const_t<Ts>...>::value;

namespace concepts {

// TODO: C++20 use std::convertible_to<> that was not available in Android NDK
//       as of this writing. Tested with API Level up to 33.
template <class FromT, class ToT>
concept convertible_to = std::is_convertible_v<FromT, ToT> && requires { static_cast<ToT>(std::declval<FromT>()); };

// TODO: C++20 provides concepts like std::equality_comparable or
//       std::three_way_comparable, but at the time of this writing, some
//       target platforms did not ship with those (Xcode 14, Android NDK r25,
//       emscripten)

template <typename T>
concept equality_comparable = requires(const std::remove_reference_t<T>& a, const std::remove_reference_t<T> b) {
                                 { a == b } -> convertible_to<bool>;
                              };

template <typename T>
concept three_way_comparison_result =
   convertible_to<T, std::weak_ordering> || convertible_to<T, std::partial_ordering> ||
   convertible_to<T, std::strong_ordering>;

template <typename T>
concept three_way_comparable = requires(const std::remove_reference_t<T>& a, const std::remove_reference_t<T> b) {
                                  { a <=> b } -> three_way_comparison_result;
                               };

template <class T>
concept destructible = std::is_nothrow_destructible_v<T>;

template <class T, class... Args>
concept constructible_from = destructible<T> && std::is_constructible_v<T, Args...>;

template <class T>
concept default_initializable =
   constructible_from<T> && requires { T{}; } && requires { ::new(static_cast<void*>(nullptr)) T; };

// TODO: C++20 provides concepts like std::ranges::range or ::sized_range
//       but at the time of this writing clang had not caught up on all
//       platforms. E.g. clang 14 on Xcode does not support ranges properly.

template <typename IterT, typename ContainerT>
concept container_iterator =
   std::same_as<IterT, typename ContainerT::iterator> || std::same_as<IterT, typename ContainerT::const_iterator>;

template <typename PtrT, typename ContainerT>
concept container_pointer =
   std::same_as<PtrT, typename ContainerT::pointer> || std::same_as<PtrT, typename ContainerT::const_pointer>;

template <typename T>
concept container = requires(T a) {
                       { a.begin() } -> container_iterator<T>;
                       { a.end() } -> container_iterator<T>;
                       { a.cbegin() } -> container_iterator<T>;
                       { a.cend() } -> container_iterator<T>;
                       { a.size() } -> std::same_as<typename T::size_type>;
                       typename T::value_type;
                    };

template <typename T>
concept contiguous_container = container<T> && requires(T a) {
                                                  { a.data() } -> container_pointer<T>;
                                               };

template <typename T>
concept has_empty = requires(T a) {
                       { a.empty() } -> std::same_as<bool>;
                    };

template <typename T>
concept resizable_container = container<T> && requires(T& c, typename T::size_type s) {
                                                 T(s);
                                                 c.resize(s);
                                              };

template <typename T>
concept resizable_byte_buffer =
   contiguous_container<T> && resizable_container<T> && std::same_as<typename T::value_type, uint8_t>;

template <typename T>
concept streamable = requires(std::ostream& os, T a) { os << a; };

template <class T>
concept strong_type = is_strong_type_v<T>;

template <class T>
concept contiguous_strong_type = strong_type<T> && contiguous_container<T>;

// std::integral is a concept that is shipped with C++20 but Android NDK is not
// yet there.
// TODO: C++20 - replace with std::integral
template <typename T>
concept integral = std::is_integral_v<T>;

}  // namespace concepts

}  // namespace Botan

#endif
