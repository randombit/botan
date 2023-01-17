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
#include <type_traits>

namespace Botan::concepts {

// TODO: C++20 provides concepts like std::equality_comparable or
//       std::three_way_comparable, but at the time of this writing, some
//       target platforms did not ship with those (Xcode 14, Android NDK r25,
//       emscripten)

template<typename T>
concept equality_comparable = requires(const std::remove_reference_t<T>& a, const std::remove_reference_t<T> b)
   {
   { a == b } -> std::convertible_to<bool>;
   };

template<typename T>
concept three_way_comparison_result =
   std::convertible_to<T, std::weak_ordering> ||
   std::convertible_to<T, std::partial_ordering> ||
   std::convertible_to<T, std::strong_ordering>;

template<typename T>
concept three_way_comparable = requires(const std::remove_reference_t<T>& a, const std::remove_reference_t<T> b)
   {
   { a <=> b } -> three_way_comparison_result;
   };

// TODO: C++20 provides concepts like std::ranges::range or ::sized_range
//       but at the time of this writing clang had not caught up on all
//       platforms. E.g. clang 14 on Xcode does not support ranges properly.

template<typename IterT, typename ContainerT>
concept container_iterator =
   std::same_as<IterT, typename ContainerT::iterator> ||
   std::same_as<IterT, typename ContainerT::const_iterator>;

template<typename PtrT, typename ContainerT>
concept container_pointer =
   std::same_as<PtrT, typename ContainerT::pointer> ||
   std::same_as<PtrT, typename ContainerT::const_pointer>;


template<typename T>
concept container = requires(T a)
   {
   { a.begin() } -> container_iterator<T>;
   { a.end() } -> container_iterator<T>;
   { a.cbegin() } -> container_iterator<T>;
   { a.cend() } -> container_iterator<T>;
   { a.size() } -> std::same_as<typename T::size_type>;
   };

template<typename T>
concept contiguous_container =
   container<T> &&
   requires(T a)
   {
   { a.data() } -> container_pointer<T>;
   };

template<typename T>
concept has_empty = requires(T a)
   {
   { a.empty() } -> std::same_as<bool>;
   };

template <typename T>
concept resizable_container =
    container<T> &&
    requires(T& c, typename T::size_type s) { c.resize(s); };

template<typename T>
concept streamable = requires(std::ostream& os, T a)
   { os << a; };

}

#endif
