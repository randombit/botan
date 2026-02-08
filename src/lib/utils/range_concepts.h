/**
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_RANGE_CONCEPTS_H_
#define BOTAN_RANGE_CONCEPTS_H_

#include <botan/types.h>
#include <concepts>
#include <ranges>
#include <span>
#include <utility>

namespace Botan::ranges {

/**
 * Models a std::ranges::contiguous_range that (optionally) restricts its
 * value_type to ValueT. In other words: a stretch of contiguous memory of
 * a certain type (optional ValueT).
 */
template <typename T, typename ValueT = std::ranges::range_value_t<T>>
concept contiguous_range = std::ranges::contiguous_range<T> && std::same_as<ValueT, std::ranges::range_value_t<T>>;

/**
 * Models a std::ranges::contiguous_range that satisfies
 * std::ranges::output_range with an arbitrary value_type. In other words: a
 * stretch of contiguous memory of a certain type (optional ValueT) that can be
 * written to.
 */
template <typename T, typename ValueT = std::ranges::range_value_t<T>>
concept contiguous_output_range = contiguous_range<T, ValueT> && std::ranges::output_range<T, ValueT>;

/**
 * Models a range that can be turned into a std::span<>. Typically, this is some
 * form of ranges::contiguous_range.
 */
template <typename T>
concept spanable_range = std::constructible_from<std::span<const std::ranges::range_value_t<T>>, T>;

/**
 * Models a range that can be turned into a std::span<> with a static extent.
 * Typically, this is a std::array or a std::span derived from an array.
 */
// clang-format off
template <typename T>
concept statically_spanable_range = spanable_range<T> &&
                                    decltype(std::span{std::declval<T&>()})::extent != std::dynamic_extent;

// clang-format on

/**
 * Find the length in bytes of a given contiguous range @p r.
 */
inline constexpr size_t size_bytes(const spanable_range auto& r) {
   return std::span{r}.size_bytes();
}

/**
* Throws an exception indicating that the attempted read or write was invalid
*/
[[noreturn]] void BOTAN_UNSTABLE_API memory_region_size_violation();

/**
 * Check that a given range @p r has a certain statically-known byte length. If
 * the range's extent is known at compile time, this is a static check,
 * otherwise a runtime argument check will be added.
 *
 * @throws Invalid_Argument  if range @p r has a dynamic extent and does not
 *                           feature the expected byte length.
 */
template <size_t expected, spanable_range R>
inline constexpr void assert_exact_byte_length(const R& r) {
   const std::span s{r};
   if constexpr(statically_spanable_range<R>) {
      static_assert(s.size_bytes() == expected, "memory region does not have expected byte lengths");
   } else {
      if(s.size_bytes() != expected) {
         memory_region_size_violation();
      }
   }
}

/**
 * Check that a list of ranges (in @p r0 and @p rs) all have the same byte
 * lengths. If the first range's extent is known at compile time, this will be a
 * static check for all other ranges whose extents are known at compile time,
 * otherwise a runtime argument check will be added.
 *
 * @throws Invalid_Argument  if any range has a dynamic extent and not all
 *                           ranges feature the same byte length.
 */
template <spanable_range R0, spanable_range... Rs>
inline constexpr void assert_equal_byte_lengths(const R0& r0, const Rs&... rs)
   requires(sizeof...(Rs) > 0)
{
   const std::span s0{r0};

   if constexpr(statically_spanable_range<R0>) {
      constexpr size_t expected_size = s0.size_bytes();
      (assert_exact_byte_length<expected_size>(rs), ...);
   } else {
      const size_t expected_size = s0.size_bytes();
      const bool correct_size =
         ((std::span<const std::ranges::range_value_t<Rs>>{rs}.size_bytes() == expected_size) && ...);

      if(!correct_size) {
         memory_region_size_violation();
      }
   }
}

}  // namespace Botan::ranges

#endif
