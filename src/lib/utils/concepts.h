/**
 * Useful concepts that are available throughout the library
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_CONCEPTS_H_
#define BOTAN_CONCEPTS_H_

#include <botan/types.h>
#include <concepts>

namespace Botan {

template <typename T0 = void, typename... Ts>
struct all_same {
      static constexpr bool value = (std::is_same_v<T0, Ts> && ... && true);
};

template <typename... Ts>
static constexpr bool all_same_v = all_same<Ts...>::value;

namespace detail {

/**
 * Helper type to indicate that a certain type should be automatically
 * detected based on the context.
 */
struct AutoDetect {
      constexpr AutoDetect() = delete;
};

}  // namespace detail

namespace concepts {

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
concept reservable_container = container<T> && requires(T& c, typename T::size_type s) { c.reserve(s); };

template <typename T>
concept resizable_byte_buffer =
   contiguous_container<T> && resizable_container<T> && std::same_as<typename T::value_type, uint8_t>;

}  // namespace concepts

}  // namespace Botan

#endif
