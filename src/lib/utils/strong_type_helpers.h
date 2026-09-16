/**
 * A bunch of helpers to allow considering the Botan-internal strong types in
 * public APIs without depending on the de-facto internal strong_type.h header.
 *
 * Users of the library should not depend on any of the facilities provided in
 * this header. This is meant to be a bridge to the internal Strong<> template.
 *
 * (C) 2022,2026 Jack Lloyd
 *     2022 René Meusel - Rohde & Schwarz Cybersecurity
 *     2026 René Meusel - Rohde & Schwarz Networks & Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_STRONG_TYPE_HELPERS_H_
#define BOTAN_STRONG_TYPE_HELPERS_H_

#include <botan/concepts.h>
#include <concepts>
#include <type_traits>
#include <utility>

namespace Botan {

template <typename T, typename Tag, typename... Capabilities>
class Strong;

/**
 * Trait that detects whether the given types are a Strong<> instantiation
 */
template <typename... Ts>
struct is_strong_type : std::false_type {};

/// @copydoc is_strong_type
template <typename... Ts>
struct is_strong_type<Strong<Ts...>> : std::true_type {};

template <typename... Ts>
constexpr bool is_strong_type_v = is_strong_type<std::remove_const_t<Ts>...>::value;

namespace concepts {

template <class T>
concept strong_type = is_strong_type_v<T>;

template <class T>
concept contiguous_strong_type = strong_type<T> && contiguous_container<T>;

template <class T>
concept integral_strong_type = strong_type<T> && std::integral<typename T::wrapped_type>;

template <class T>
concept unsigned_integral_strong_type = strong_type<T> && std::unsigned_integral<typename T::wrapped_type>;

}  // namespace concepts

template <concepts::contiguous_strong_type T>
class StrongSpan;

/**
 * Trait that detects whether the given type is a StrongSpan<> instantiation
 */
template <typename>
struct is_strong_span : std::false_type {};

/// @copydoc is_strong_span
template <typename T>
struct is_strong_span<StrongSpan<T>> : std::true_type {};

template <typename T>
constexpr bool is_strong_span_v = is_strong_span<T>::value;

namespace detail {

/**
 * Resolves to the type wrapped by a strong type, or to T itself if T is
 * not a strong type
 */
template <typename T>
struct wrapped_type_helper {
      /// The resolved type
      using type = T;
};

/// @copydoc wrapped_type_helper
template <concepts::strong_type T>
struct wrapped_type_helper<T> {
      /// The resolved type
      using type = typename T::wrapped_type;
};

}  // namespace detail

/**
 * @brief Extracts the wrapped type from a strong type.
 *
 * If the provided type is not a strong type, it is returned as is.
 *
 * @note This is meant as a helper for generic code that needs to deal with both
 *       wrapped strong types and bare objects. Use the ordinary `::wrapped_type`
 *       declaration if you know that you are dealing with a strong type.
 */
template <typename T>
using strong_type_wrapped_type = typename detail::wrapped_type_helper<std::remove_cvref_t<T>>::type;

/**
 * @brief Generically unwraps a strong type to its underlying type.
 *
 * If the provided type is not a strong type, it is returned as is.
 *
 * @note This is meant as a helper for generic code that needs to deal with both
 *       wrapped strong types and bare objects. Use the ordinary `get()` method
 *       if you know that you are dealing with a strong type.
 *
 * @param t  value to be unwrapped
 * @return   the unwrapped value
 */
template <typename T>
[[nodiscard]] constexpr decltype(auto) unwrap_strong_type(T&& t) {
   if constexpr(!concepts::strong_type<std::remove_cvref_t<T>>) {
      // If the parameter type isn't a strong type, return it as is.
      return std::forward<T>(t);
   } else {
      // Unwrap the strong type and return the underlying value.
      return std::forward<T>(t).get();
   }
}

/**
 * @brief Wraps a value into a caller-defined (strong) type.
 *
 * If the provided object @p t is already of type @p T, it is returned as is.
 *
 * @note This is meant as a helper for generic code that needs to deal with both
 *       wrapped strong types and bare objects. Use the ordinary constructor if
 *       you know that you are dealing with a bare value type.
 *
 * @param t  value to be wrapped
 * @return   the wrapped value
 */
template <typename T, typename ParamT>
   requires std::constructible_from<T, ParamT> ||
            (concepts::strong_type<T> && std::constructible_from<typename T::wrapped_type, ParamT>)
[[nodiscard]] constexpr decltype(auto) wrap_strong_type(ParamT&& t) {
   if constexpr(std::same_as<std::remove_cvref_t<ParamT>, T>) {
      // Noop, if the parameter type already is the desired return type.
      return std::forward<ParamT>(t);
   } else if constexpr(std::constructible_from<T, ParamT>) {
      // Implicit conversion from the parameter type to the return type.
      return T{std::forward<ParamT>(t)};
   } else {
      // Explicitly calling the wrapped type's constructor to support
      // implicit conversions on types that mark their constructors as explicit.
      static_assert(concepts::strong_type<T> && std::constructible_from<typename T::wrapped_type, ParamT>);
      return T{typename T::wrapped_type{std::forward<ParamT>(t)}};
   }
}

}  // namespace Botan

#endif
