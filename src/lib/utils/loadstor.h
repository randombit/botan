/*
* Load/Store Operators
* (C) 1999-2007,2015,2017 Jack Lloyd
*     2007 Yves Jerschow
*     2023-2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_LOAD_STORE_H_
#define BOTAN_LOAD_STORE_H_

#include <botan/concepts.h>
#include <botan/mem_ops.h>
#include <botan/strong_type.h>
#include <botan/types.h>
#include <botan/internal/bswap.h>

/**
 * @file loadstor.h
 *
 * @brief This header contains various helper functions to load and store
 *        unsigned integers in big- or little-endian byte order.
 *
 * Storing integer values in various ways (same for BE and LE):
 * @code {.cpp}
 *
 *   std::array<uint8_t, 8> bytes = store_le(some_uint64);
 *   std::array<uint8_t, 12> bytes = store_le(some_uint32_1, some_uint32_2, some_uint32_3, ...);
 *   auto bytes = store_le<std::vector<uint8_t>>(some_uint64);
 *   auto bytes = store_le<MyContainerStrongType>(some_uint64);
 *   auto bytes = store_le<std::vector<uint8_t>>(vector_of_ints);
 *   auto bytes = store_le<secure_vector<uint8_t>>(some_uint32_1, some_uint32_2, some_uint32_3, ...);
 *   store_le(bytes, some_uint64);
 *   store_le(concatenated_bytes, some_uint64_1, some_uint64_2, some_uint64_3, ...);
 *   store_le(concatenated_bytes, vector_of_ints);
 *   copy_out_le(short_concated_bytes, vector_of_ints); // stores as many bytes as required in the output buffer
 *
 * @endcode
 *
 * Loading integer values in various ways (same for BE and LE):
 * @code {.cpp}
 *
 *   uint64_t some_uint64 = load_le(bytes_8);
 *   auto some_int32s = load_le<std::vector<uint32_t>>(concatenated_bytes);
 *   auto some_int32s = load_le<std::vector<MyIntStrongType>>(concatenated_bytes);
 *   auto some_int32s = load_le(some_strong_typed_bytes);
 *   auto strong_int  = load_le<MyStrongTypedInteger>(concatenated_bytes);
 *   load_le(concatenated_bytes, out_some_uint64);
 *   load_le(concatenated_bytes, out_some_uint64_1, out_some_uint64_2, out_some_uint64_3, ...);
 *   load_le(out_vector_of_ints, concatenated_bytes);
 *
 * @endcode
 */

namespace Botan {

/**
* Byte extraction
* @param byte_num which byte to extract, 0 == highest byte
* @param input the value to extract from
* @return byte byte_num of input
*/
template <typename T>
inline constexpr uint8_t get_byte_var(size_t byte_num, T input) {
   return static_cast<uint8_t>(input >> (((~byte_num) & (sizeof(T) - 1)) << 3));
}

/**
* Byte extraction
* @param input the value to extract from
* @return byte byte number B of input
*/
template <size_t B, typename T>
inline constexpr uint8_t get_byte(T input)
   requires(B < sizeof(T))
{
   const size_t shift = ((~B) & (sizeof(T) - 1)) << 3;
   return static_cast<uint8_t>((input >> shift) & 0xFF);
}

/**
* Make a uint16_t from two bytes
* @param i0 the first byte
* @param i1 the second byte
* @return i0 || i1
*/
inline constexpr uint16_t make_uint16(uint8_t i0, uint8_t i1) {
   return static_cast<uint16_t>((static_cast<uint16_t>(i0) << 8) | i1);
}

/**
* Make a uint32_t from four bytes
* @param i0 the first byte
* @param i1 the second byte
* @param i2 the third byte
* @param i3 the fourth byte
* @return i0 || i1 || i2 || i3
*/
inline constexpr uint32_t make_uint32(uint8_t i0, uint8_t i1, uint8_t i2, uint8_t i3) {
   return ((static_cast<uint32_t>(i0) << 24) | (static_cast<uint32_t>(i1) << 16) | (static_cast<uint32_t>(i2) << 8) |
           (static_cast<uint32_t>(i3)));
}

/**
* Make a uint64_t from eight bytes
* @param i0 the first byte
* @param i1 the second byte
* @param i2 the third byte
* @param i3 the fourth byte
* @param i4 the fifth byte
* @param i5 the sixth byte
* @param i6 the seventh byte
* @param i7 the eighth byte
* @return i0 || i1 || i2 || i3 || i4 || i5 || i6 || i7
*/
inline constexpr uint64_t make_uint64(
   uint8_t i0, uint8_t i1, uint8_t i2, uint8_t i3, uint8_t i4, uint8_t i5, uint8_t i6, uint8_t i7) {
   return ((static_cast<uint64_t>(i0) << 56) | (static_cast<uint64_t>(i1) << 48) | (static_cast<uint64_t>(i2) << 40) |
           (static_cast<uint64_t>(i3) << 32) | (static_cast<uint64_t>(i4) << 24) | (static_cast<uint64_t>(i5) << 16) |
           (static_cast<uint64_t>(i6) << 8) | (static_cast<uint64_t>(i7)));
}

namespace detail {

enum class Endianness : bool {
   Big,
   Little,
};

/**
 * @warning This function may return false if the native endianness is unknown
 * @returns true iff the native endianness matches the given endianness
 */
constexpr bool is_native(Endianness endianness) {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
   return endianness == Endianness::Big;
#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   return endianness == Endianness::Little;
#else
   BOTAN_UNUSED(endianness);
   return false;
#endif
}

/**
 * @warning This function may return false if the native endianness is unknown
 * @returns true iff the native endianness does not match the given endianness
 */
constexpr bool is_opposite(Endianness endianness) {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
   return endianness == Endianness::Little;
#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   return endianness == Endianness::Big;
#else
   BOTAN_UNUSED(endianness);
   return false;
#endif
}

template <Endianness endianness>
constexpr bool native_endianness_is_unknown() {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN) || defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   return false;
#else
   return true;
#endif
}

/**
 * Models a custom type that provides factory methods to be loaded in big- or
 * little-endian byte order.
 */
template <typename T>
concept custom_loadable = requires(std::span<const uint8_t, sizeof(T)> data) {
   { T::load_be(data) } -> std::same_as<T>;
   { T::load_le(data) } -> std::same_as<T>;
};

/**
 * Models a custom type that provides store methods to be stored in big- or
 * little-endian byte order.
 */
template <typename T>
concept custom_storable = requires(std::span<uint8_t, sizeof(T)> data, const T value) {
   { value.store_be(data) };
   { value.store_le(data) };
};

/**
 * Models a type that can be loaded/stored from/to a byte range.
 */
template <typename T>
concept unsigned_integralish =
   std::unsigned_integral<strong_type_wrapped_type<T>> ||
   (std::is_enum_v<T> && std::unsigned_integral<std::underlying_type_t<T>>) ||
   (custom_loadable<strong_type_wrapped_type<T>> || custom_storable<strong_type_wrapped_type<T>>);

template <typename T>
struct wrapped_type_helper_with_enum {
      using type = strong_type_wrapped_type<T>;
};

template <typename T>
   requires std::is_enum_v<T>
struct wrapped_type_helper_with_enum<T> {
      using type = std::underlying_type_t<T>;
};

template <unsigned_integralish T>
using wrapped_type = typename wrapped_type_helper_with_enum<T>::type;

template <unsigned_integralish InT>
constexpr auto unwrap_strong_type_or_enum(InT t) {
   if constexpr(std::is_enum_v<InT>) {
      // TODO: C++23: use std::to_underlying(in) instead
      return static_cast<std::underlying_type_t<InT>>(t);
   } else {
      return Botan::unwrap_strong_type(t);
   }
}

template <unsigned_integralish OutT, std::unsigned_integral T>
constexpr auto wrap_strong_type_or_enum(T t) {
   if constexpr(std::is_enum_v<OutT>) {
      return static_cast<OutT>(t);
   } else {
      return Botan::wrap_strong_type<OutT>(t);
   }
}

/**
 * Manually load a word from a range in either big or little endian byte order.
 * This will be used only if the endianness of the target platform is unknown at
 * compile time.
 */
template <Endianness endianness, std::unsigned_integral OutT, ranges::contiguous_range<uint8_t> InR>
inline constexpr OutT fallback_load_any(InR&& in_range) {
   std::span in{in_range};
   // clang-format off
   if constexpr(endianness == Endianness::Big) {
      return [&]<size_t... i>(std::index_sequence<i...>) {
         return static_cast<OutT>(((static_cast<OutT>(in[i]) << ((sizeof(OutT) - i - 1) * 8)) | ...));
      } (std::make_index_sequence<sizeof(OutT)>());
   } else {
      static_assert(endianness == Endianness::Little);
      return [&]<size_t... i>(std::index_sequence<i...>) {
         return static_cast<OutT>(((static_cast<OutT>(in[i]) << (i * 8)) | ...));
      } (std::make_index_sequence<sizeof(OutT)>());
   }
   // clang-format on
}

/**
 * Manually store a word into a range in either big or little endian byte order.
 * This will be used only if the endianness of the target platform is unknown at
 * compile time.
 */
template <Endianness endianness, std::unsigned_integral InT, ranges::contiguous_output_range<uint8_t> OutR>
inline constexpr void fallback_store_any(InT in, OutR&& out_range) {
   std::span out{out_range};
   // clang-format off
   if constexpr(endianness == Endianness::Big) {
      [&]<size_t... i>(std::index_sequence<i...>) {
         ((out[i] = get_byte<i>(in)), ...);
      } (std::make_index_sequence<sizeof(InT)>());
   } else {
      static_assert(endianness == Endianness::Little);
      [&]<size_t... i>(std::index_sequence<i...>) {
         ((out[i] = get_byte<sizeof(InT) - i - 1>(in)), ...);
      } (std::make_index_sequence<sizeof(InT)>());
   }
   // clang-format on
}

/**
 * Load a word from a range in either big or little endian byte order
 *
 * This is the base implementation, all other overloads are just convenience
 * wrappers. It is assumed that the range has the correct size for the word.
 *
 * Template arguments of all overloads of load_any() share the same semantics:
 *
 *   1.  Endianness      Either `Endianness::Big` or `Endianness::Little`, that
 *                       will eventually select the byte order translation mode
 *                       implemented in this base function.
 *
 *   2.  Output type     Either `AutoDetect`, an unsigned integer or a container
 *                       holding an unsigned integer type. `AutoDetect` means
 *                       that the caller did not explicitly specify the type and
 *                       expects the type to be inferred from the input.
 *
 *   3+. Argument types  Typically, those are input and output ranges of bytes
 *                       or unsigned integers. Or one or more unsigned integers
 *                       acting as output parameters.
 *
 * @param in_range a fixed-length byte range
 * @return T loaded from @p in_range, as a big-endian value
 */
template <Endianness endianness, unsigned_integralish WrappedOutT, ranges::contiguous_range<uint8_t> InR>
   requires(!custom_loadable<strong_type_wrapped_type<WrappedOutT>>)
inline constexpr WrappedOutT load_any(InR&& in_range) {
   using OutT = detail::wrapped_type<WrappedOutT>;
   ranges::assert_exact_byte_length<sizeof(OutT)>(in_range);

   return detail::wrap_strong_type_or_enum<WrappedOutT>([&]() -> OutT {
      // At compile time we cannot use `typecast_copy` as it uses `std::memcpy`
      // internally to copy ranges on a byte-by-byte basis, which is not allowed
      // in a `constexpr` context.
      if(std::is_constant_evaluated()) /* TODO: C++23: if consteval {} */ {
         return fallback_load_any<endianness, OutT>(std::forward<InR>(in_range));
      } else {
         std::span in{in_range};
         if constexpr(sizeof(OutT) == 1) {
            return static_cast<OutT>(in[0]);
         } else if constexpr(is_native(endianness)) {
            return typecast_copy<OutT>(in);
         } else if constexpr(is_opposite(endianness)) {
            return reverse_bytes(typecast_copy<OutT>(in));
         } else {
            static_assert(native_endianness_is_unknown<endianness>());
            return fallback_load_any<endianness, OutT>(std::forward<InR>(in_range));
         }
      }
   }());
}

/**
 * Load a custom object from a range in either big or little endian byte order
 *
 * This is the base implementation for custom objects (e.g. SIMD type wrappres),
 * all other overloads are just convenience overloads.
 *
 * @param in_range a fixed-length byte range
 * @return T loaded from @p in_range, as a big-endian value
 */
template <Endianness endianness, unsigned_integralish WrappedOutT, ranges::contiguous_range<uint8_t> InR>
   requires(custom_loadable<strong_type_wrapped_type<WrappedOutT>>)
inline constexpr WrappedOutT load_any(InR&& in_range) {
   using OutT = detail::wrapped_type<WrappedOutT>;
   ranges::assert_exact_byte_length<sizeof(OutT)>(in_range);
   std::span<const uint8_t, sizeof(OutT)> ins{in_range};
   if constexpr(endianness == Endianness::Big) {
      return wrap_strong_type<WrappedOutT>(OutT::load_be(ins));
   } else {
      return wrap_strong_type<WrappedOutT>(OutT::load_le(ins));
   }
}

/**
 * Load many unsigned integers
 * @param in   a fixed-length span to some bytes
 * @param outs a arbitrary-length parameter list of unsigned integers to be loaded
 */
template <Endianness endianness, typename OutT, ranges::contiguous_range<uint8_t> InR, unsigned_integralish... Ts>
   requires(sizeof...(Ts) > 0) && ((std::same_as<AutoDetect, OutT> && all_same_v<Ts...>) ||
                                   (unsigned_integralish<OutT> && all_same_v<OutT, Ts...>))
inline constexpr void load_any(InR&& in, Ts&... outs) {
   ranges::assert_exact_byte_length<(sizeof(Ts) + ...)>(in);
   auto load_one = [off = 0]<typename T>(auto i, T& o) mutable {
      o = load_any<endianness, T>(i.subspan(off).template first<sizeof(T)>());
      off += sizeof(T);
   };

   (load_one(std::span{in}, outs), ...);
}

/**
 * Load a variable number of words from @p in into @p out.
 * The byte length of the @p out and @p in ranges must match.
 *
 * @param out the output range of words
 * @param in the input range of bytes
 */
template <Endianness endianness,
          typename OutT,
          ranges::contiguous_output_range OutR,
          ranges::contiguous_range<uint8_t> InR>
   requires(unsigned_integralish<std::ranges::range_value_t<OutR>> &&
            (std::same_as<AutoDetect, OutT> || std::same_as<OutT, std::ranges::range_value_t<OutR>>))
inline constexpr void load_any(OutR&& out, InR&& in) {
   ranges::assert_equal_byte_lengths(out, in);
   using element_type = std::ranges::range_value_t<OutR>;

   auto load_elementwise = [&] {
      constexpr size_t bytes_per_element = sizeof(element_type);
      std::span<const uint8_t> in_s(in);
      for(auto& out_elem : out) {
         out_elem = load_any<endianness, element_type>(in_s.template first<bytes_per_element>());
         in_s = in_s.subspan(bytes_per_element);
      }
   };

   // At compile time we cannot use `typecast_copy` as it uses `std::memcpy`
   // internally to copy ranges on a byte-by-byte basis, which is not allowed
   // in a `constexpr` context.
   if(std::is_constant_evaluated()) /* TODO: C++23: if consteval {} */ {
      load_elementwise();
   } else {
      if constexpr(is_native(endianness) && !custom_loadable<element_type>) {
         typecast_copy(out, in);
      } else {
         load_elementwise();
      }
   }
}

//
// Type inference overloads
//

/**
 * Load one or more unsigned integers, auto-detect the output type if
 * possible. Otherwise, use the specified integer or integer container type.
 *
 * @param in_range a statically-sized range with some bytes
 * @return T loaded from in
 */
template <Endianness endianness, typename OutT, ranges::contiguous_range<uint8_t> InR>
   requires(std::same_as<AutoDetect, OutT> ||
            ((ranges::statically_spanable_range<OutT> || concepts::resizable_container<OutT>) &&
             unsigned_integralish<typename OutT::value_type>))
inline constexpr auto load_any(InR&& in_range) {
   auto out = []([[maybe_unused]] const auto& in) {
      if constexpr(std::same_as<AutoDetect, OutT>) {
         if constexpr(ranges::statically_spanable_range<InR>) {
            constexpr size_t extent = decltype(std::span{in})::extent;

            // clang-format off
            using type =
               std::conditional_t<extent == 1, uint8_t,
               std::conditional_t<extent == 2, uint16_t,
               std::conditional_t<extent == 4, uint32_t,
               std::conditional_t<extent == 8, uint64_t, void>>>>;
            // clang-format on

            static_assert(
               !std::is_void_v<type>,
               "Cannot determine the output type based on a statically sized bytearray with length other than those: 1, 2, 4, 8");

            return type{};
         } else {
            static_assert(
               !std::same_as<AutoDetect, OutT>,
               "cannot infer return type from a dynamic range at compile time, please specify it explicitly");
         }
      } else if constexpr(concepts::resizable_container<OutT>) {
         const size_t in_bytes = std::span{in}.size_bytes();
         constexpr size_t out_elem_bytes = sizeof(typename OutT::value_type);
         BOTAN_ARG_CHECK(in_bytes % out_elem_bytes == 0,
                         "Input range is not word-aligned with the requested output range");
         return OutT(in_bytes / out_elem_bytes);
      } else {
         return OutT{};
      }
   }(in_range);

   using out_type = decltype(out);
   if constexpr(unsigned_integralish<out_type>) {
      out = load_any<endianness, out_type>(std::forward<InR>(in_range));
   } else {
      static_assert(ranges::contiguous_range<out_type>);
      using out_range_type = std::ranges::range_value_t<out_type>;
      load_any<endianness, out_range_type>(out, std::forward<InR>(in_range));
   }
   return out;
}

//
// Legacy load functions that work on raw pointers and arrays
//

/**
 * Load a word from @p in at some offset @p off
 * @param in a pointer to some bytes
 * @param off an offset into the array
 * @return off'th T of in, as a big-endian value
 */
template <Endianness endianness, unsigned_integralish OutT>
inline constexpr OutT load_any(const uint8_t in[], size_t off) {
   // asserts that *in points to enough bytes to read at offset off
   constexpr size_t out_size = sizeof(OutT);
   return load_any<endianness, OutT>(std::span<const uint8_t, out_size>(in + off * out_size, out_size));
}

/**
 * Load many words from @p in
 * @param in   a pointer to some bytes
 * @param outs a arbitrary-length parameter list of unsigned integers to be loaded
 */
template <Endianness endianness, typename OutT, unsigned_integralish... Ts>
   requires(sizeof...(Ts) > 0 && all_same_v<Ts...> &&
            ((std::same_as<AutoDetect, OutT> && all_same_v<Ts...>) ||
             (unsigned_integralish<OutT> && all_same_v<OutT, Ts...>)))
inline constexpr void load_any(const uint8_t in[], Ts&... outs) {
   constexpr auto bytes = (sizeof(outs) + ...);
   // asserts that *in points to the correct amount of memory
   load_any<endianness, OutT>(std::span<const uint8_t, bytes>(in, bytes), outs...);
}

/**
 * Load a variable number of words from @p in into @p out.
 * @param out the output array of words
 * @param in the input array of bytes
 * @param count how many words are in in
 */
template <Endianness endianness, typename OutT, unsigned_integralish T>
   requires(std::same_as<AutoDetect, OutT> || std::same_as<T, OutT>)
inline constexpr void load_any(T out[], const uint8_t in[], size_t count) {
   // asserts that *in and *out point to the correct amount of memory
   load_any<endianness, OutT>(std::span<T>(out, count), std::span<const uint8_t>(in, count * sizeof(T)));
}

}  // namespace detail

/**
 * Load "something" in little endian byte order
 * See the documentation of this file for more details.
 */
template <typename OutT = detail::AutoDetect, typename... ParamTs>
inline constexpr auto load_le(ParamTs&&... params) {
   return detail::load_any<detail::Endianness::Little, OutT>(std::forward<ParamTs>(params)...);
}

/**
 * Load "something" in big endian byte order
 * See the documentation of this file for more details.
 */
template <typename OutT = detail::AutoDetect, typename... ParamTs>
inline constexpr auto load_be(ParamTs&&... params) {
   return detail::load_any<detail::Endianness::Big, OutT>(std::forward<ParamTs>(params)...);
}

namespace detail {

/**
 * Store a word in either big or little endian byte order into a range
 *
 * This is the base implementation, all other overloads are just convenience
 * wrappers. It is assumed that the range has the correct size for the word.
 *
 * Template arguments of all overloads of store_any() share the same semantics
 * as those of load_any(). See the documentation of this function for more
 * details.
 *
 * @param wrapped_in an unsigned integral to be stored
 * @param out_range  a byte range to store the word into
 */
template <Endianness endianness, unsigned_integralish WrappedInT, ranges::contiguous_output_range<uint8_t> OutR>
   requires(!custom_storable<strong_type_wrapped_type<WrappedInT>>)
inline constexpr void store_any(WrappedInT wrapped_in, OutR&& out_range) {
   const auto in = detail::unwrap_strong_type_or_enum(wrapped_in);
   using InT = decltype(in);
   ranges::assert_exact_byte_length<sizeof(in)>(out_range);
   std::span out{out_range};

   // At compile time we cannot use `typecast_copy` as it uses `std::memcpy`
   // internally to copy ranges on a byte-by-byte basis, which is not allowed
   // in a `constexpr` context.
   if(std::is_constant_evaluated()) /* TODO: C++23: if consteval {} */ {
      return fallback_store_any<endianness, InT>(in, std::forward<OutR>(out_range));
   } else {
      if constexpr(sizeof(InT) == 1) {
         out[0] = static_cast<uint8_t>(in);
      } else if constexpr(is_native(endianness)) {
         typecast_copy(out, in);
      } else if constexpr(is_opposite(endianness)) {
         typecast_copy(out, reverse_bytes(in));
      } else {
         static_assert(native_endianness_is_unknown<endianness>());
         return fallback_store_any<endianness, InT>(in, std::forward<OutR>(out_range));
      }
   }
}

/**
 * Store a custom word in either big or little endian byte order into a range
 *
 * This is the base implementation for storing custom objects, all other
 * overloads are just convenience overloads.
 *
 * @param wrapped_in a custom object to be stored
 * @param out_range  a byte range to store the word into
 */
template <Endianness endianness, unsigned_integralish WrappedInT, ranges::contiguous_output_range<uint8_t> OutR>
   requires(custom_storable<strong_type_wrapped_type<WrappedInT>>)
inline constexpr void store_any(WrappedInT wrapped_in, OutR&& out_range) {
   const auto in = detail::unwrap_strong_type_or_enum(wrapped_in);
   using InT = decltype(in);
   ranges::assert_exact_byte_length<sizeof(in)>(out_range);
   std::span<uint8_t, sizeof(InT)> outs{out_range};
   if constexpr(endianness == Endianness::Big) {
      in.store_be(outs);
   } else {
      in.store_le(outs);
   }
}

/**
 * Store many unsigned integers words into a byte range
 * @param out a sized range of some bytes
 * @param ins a arbitrary-length parameter list of unsigned integers to be stored
 */
template <Endianness endianness,
          typename InT,
          ranges::contiguous_output_range<uint8_t> OutR,
          unsigned_integralish... Ts>
   requires(sizeof...(Ts) > 0) && ((std::same_as<AutoDetect, InT> && all_same_v<Ts...>) ||
                                   (unsigned_integralish<InT> && all_same_v<InT, Ts...>))
inline constexpr void store_any(OutR&& out, Ts... ins) {
   ranges::assert_exact_byte_length<(sizeof(Ts) + ...)>(out);
   auto store_one = [off = 0]<typename T>(auto o, T i) mutable {
      store_any<endianness, T>(i, o.subspan(off).template first<sizeof(T)>());
      off += sizeof(T);
   };

   (store_one(std::span{out}, ins), ...);
}

/**
 * Store a variable number of words given in @p in into @p out.
 * The byte lengths of @p in and @p out must be consistent.
 * @param out the output range of bytes
 * @param in the input range of words
 */
template <Endianness endianness,
          typename InT,
          ranges::contiguous_output_range<uint8_t> OutR,
          ranges::spanable_range InR>
   requires(std::same_as<AutoDetect, InT> || std::same_as<InT, std::ranges::range_value_t<InR>>)
inline constexpr void store_any(OutR&& out, InR&& in) {
   ranges::assert_equal_byte_lengths(out, in);
   using element_type = std::ranges::range_value_t<InR>;

   auto store_elementwise = [&] {
      constexpr size_t bytes_per_element = sizeof(element_type);
      std::span<uint8_t> out_s(out);
      for(auto in_elem : in) {
         store_any<endianness, element_type>(out_s.template first<bytes_per_element>(), in_elem);
         out_s = out_s.subspan(bytes_per_element);
      }
   };

   // At compile time we cannot use `typecast_copy` as it uses `std::memcpy`
   // internally to copy ranges on a byte-by-byte basis, which is not allowed
   // in a `constexpr` context.
   if(std::is_constant_evaluated()) /* TODO: C++23: if consteval {} */ {
      store_elementwise();
   } else {
      if constexpr(is_native(endianness) && !custom_storable<element_type>) {
         typecast_copy(out, in);
      } else {
         store_elementwise();
      }
   }
}

//
// Type inference overloads
//

/**
 * Infer InT from a single unsigned integer input parameter.
 *
 * TODO: we might consider dropping this overload (i.e. out-range as second
 *       parameter) and make this a "special case" of the overload below, that
 *       takes a variadic number of input parameters.
 *
 * @param in an unsigned integer to be stored
 * @param out_range a range of bytes to store the word into
 */
template <Endianness endianness, typename InT, unsigned_integralish T, ranges::contiguous_output_range<uint8_t> OutR>
   requires std::same_as<AutoDetect, InT>
inline constexpr void store_any(T in, OutR&& out_range) {
   store_any<endianness, T>(in, std::forward<OutR>(out_range));
}

/**
 * The caller provided some integer values in a collection but did not provide
 * the output container. Let's create one for them, fill it with one of the
 * overloads above and return it. This will default to a std::array if the
 * caller did not specify the desired output container type.
 *
 * @param in_range a range of words that should be stored
 * @return a container of bytes that contains the stored words
 */
template <Endianness endianness, typename OutR, ranges::spanable_range InR>
   requires(std::same_as<AutoDetect, OutR> ||
            (ranges::statically_spanable_range<OutR> && std::default_initializable<OutR>) ||
            concepts::resizable_byte_buffer<OutR>)
inline constexpr auto store_any(InR&& in_range) {
   auto out = []([[maybe_unused]] const auto& in) {
      if constexpr(std::same_as<AutoDetect, OutR>) {
         if constexpr(ranges::statically_spanable_range<InR>) {
            constexpr size_t bytes = decltype(std::span{in})::extent * sizeof(std::ranges::range_value_t<InR>);
            return std::array<uint8_t, bytes>();
         } else {
            static_assert(
               !std::same_as<AutoDetect, OutR>,
               "cannot infer a suitable result container type from the given parameters at compile time, please specify it explicitly");
         }
      } else if constexpr(concepts::resizable_byte_buffer<OutR>) {
         return OutR(std::span{in}.size_bytes());
      } else {
         return OutR{};
      }
   }(in_range);

   store_any<endianness, std::ranges::range_value_t<InR>>(out, std::forward<InR>(in_range));
   return out;
}

/**
 * The caller provided some integer values but did not provide the output
 * container. Let's create one for them, fill it with one of the overloads above
 * and return it. This will default to a std::array if the caller did not
 * specify the desired output container type.
 *
 * @param ins some words that should be stored
 * @return a container of bytes that contains the stored words
 */
template <Endianness endianness, typename OutR, unsigned_integralish... Ts>
   requires all_same_v<Ts...>
inline constexpr auto store_any(Ts... ins) {
   return store_any<endianness, OutR>(std::array{ins...});
}

//
// Legacy store functions that work on raw pointers and arrays
//

/**
 * Store a single unsigned integer into a raw pointer
 * @param in the input unsigned integer
 * @param out the byte array to write to
 */
template <Endianness endianness, typename InT, unsigned_integralish T>
   requires(std::same_as<AutoDetect, InT> || std::same_as<T, InT>)
inline constexpr void store_any(T in, uint8_t out[]) {
   // asserts that *out points to enough bytes to write into
   store_any<endianness, InT>(in, std::span<uint8_t, sizeof(T)>(out, sizeof(T)));
}

/**
 * Store many unsigned integers words into a raw pointer
 * @param ins a arbitrary-length parameter list of unsigned integers to be stored
 * @param out the byte array to write to
 */
template <Endianness endianness, typename InT, unsigned_integralish T0, unsigned_integralish... Ts>
   requires(std::same_as<AutoDetect, InT> || std::same_as<T0, InT>) && all_same_v<T0, Ts...>
inline constexpr void store_any(uint8_t out[], T0 in0, Ts... ins) {
   constexpr auto bytes = sizeof(in0) + (sizeof(ins) + ... + 0);
   // asserts that *out points to the correct amount of memory
   store_any<endianness, T0>(std::span<uint8_t, bytes>(out, bytes), in0, ins...);
}

}  // namespace detail

/**
 * Store "something" in little endian byte order
 * See the documentation of this file for more details.
 */
template <typename ModifierT = detail::AutoDetect, typename... ParamTs>
inline constexpr auto store_le(ParamTs&&... params) {
   return detail::store_any<detail::Endianness::Little, ModifierT>(std::forward<ParamTs>(params)...);
}

/**
 * Store "something" in big endian byte order
 * See the documentation of this file for more details.
 */
template <typename ModifierT = detail::AutoDetect, typename... ParamTs>
inline constexpr auto store_be(ParamTs&&... params) {
   return detail::store_any<detail::Endianness::Big, ModifierT>(std::forward<ParamTs>(params)...);
}

namespace detail {

template <Endianness endianness, unsigned_integralish T>
inline size_t copy_out_any_word_aligned_portion(std::span<uint8_t>& out, std::span<const T>& in) {
   const size_t full_words = out.size() / sizeof(T);
   const size_t full_word_bytes = full_words * sizeof(T);
   const size_t remaining_bytes = out.size() - full_word_bytes;
   BOTAN_ASSERT_NOMSG(in.size_bytes() >= full_word_bytes + remaining_bytes);

   // copy full words
   store_any<endianness, T>(out.first(full_word_bytes), in.first(full_words));
   out = out.subspan(full_word_bytes);
   in = in.subspan(full_words);

   return remaining_bytes;
}

}  // namespace detail

/**
 * Partially copy a subset of @p in into @p out using big-endian
 * byte order.
 */
template <ranges::spanable_range InR>
inline void copy_out_be(std::span<uint8_t> out, InR&& in) {
   using T = std::ranges::range_value_t<InR>;
   std::span<const T> in_s{in};
   const auto remaining_bytes = detail::copy_out_any_word_aligned_portion<detail::Endianness::Big>(out, in_s);

   // copy remaining bytes as a partial word
   for(size_t i = 0; i < remaining_bytes; ++i) {
      out[i] = get_byte_var(i, in_s.front());
   }
}

/**
 * Partially copy a subset of @p in into @p out using little-endian
 * byte order.
 */
template <ranges::spanable_range InR>
inline void copy_out_le(std::span<uint8_t> out, InR&& in) {
   using T = std::ranges::range_value_t<InR>;
   std::span<const T> in_s{in};
   const auto remaining_bytes = detail::copy_out_any_word_aligned_portion<detail::Endianness::Little>(out, in_s);

   // copy remaining bytes as a partial word
   for(size_t i = 0; i < remaining_bytes; ++i) {
      out[i] = get_byte_var(sizeof(T) - 1 - i, in_s.front());
   }
}

}  // namespace Botan

#endif
