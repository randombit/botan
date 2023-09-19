/*
* Load/Store Operators
* (C) 1999-2007,2015,2017 Jack Lloyd
*     2007 Yves Jerschow
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_LOAD_STORE_H_
#define BOTAN_LOAD_STORE_H_

#include <botan/concepts.h>
#include <botan/mem_ops.h>
#include <botan/types.h>
#include <botan/internal/bswap.h>
#include <vector>

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

/**
* Load a big-endian unsigned integer
* @param in_range a fixed-length span with some bytes
* @return T loaded from in, as a big-endian value
*/
template <concepts::unsigned_integral T, ranges::contiguous_range<uint8_t> InR>
inline constexpr T load_be(InR&& in_range) {
   ranges::assert_exact_byte_length<sizeof(T)>(in_range);
   std::span in{in_range};
   if constexpr(sizeof(T) == 1) {
      return static_cast<T>(in[0]);
   } else {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
      return typecast_copy<T>(in);
#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
      return reverse_bytes(typecast_copy<T>(in));
#else
      return [&]<size_t... i>(std::index_sequence<i...>) {
         return ((static_cast<T>(in[i]) << ((sizeof(T) - i - 1) * 8)) | ...);
      }
      (std::make_index_sequence<sizeof(T)>());
#endif
   }
}

/**
* Load a little-endian unsigned integer
* @param in_range a fixed-length span with some bytes
* @return T loaded from in, as a little-endian value
*/
template <concepts::unsigned_integral T, ranges::contiguous_range<uint8_t> InR>
inline constexpr T load_le(InR&& in_range) {
   ranges::assert_exact_byte_length<sizeof(T)>(in_range);
   std::span in{in_range};
   if constexpr(sizeof(T) == 1) {
      return static_cast<T>(in[0]);
   } else {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
      return reverse_bytes(typecast_copy<T>(in));
#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
      return typecast_copy<T>(in);
#else
      return [&]<size_t... i>(std::index_sequence<i...>) {
         return ((static_cast<T>(in[i]) << (i * 8)) | ...);
      }
      (std::make_index_sequence<sizeof(T)>());
#endif
   }
}

/**
* Load a big-endian word
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th T of in, as a big-endian value
*/
template <typename T>
inline constexpr T load_be(const uint8_t in[], size_t off) {
   in += off * sizeof(T);
   T out = 0;
   for(size_t i = 0; i != sizeof(T); ++i) {
      out = static_cast<T>((out << 8) | in[i]);
   }
   return out;
}

/**
* Load a little-endian word
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th T of in, as a litte-endian value
*/
template <typename T>
inline constexpr T load_le(const uint8_t in[], size_t off) {
   in += off * sizeof(T);
   T out = 0;
   for(size_t i = 0; i != sizeof(T); ++i) {
      out = (out << 8) | in[sizeof(T) - 1 - i];
   }
   return out;
}

/**
* Load a big-endian unsigned integer
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th unsigned integer of in, as a big-endian value
*/
template <concepts::unsigned_integral T>
inline constexpr T load_be(const uint8_t in[], size_t off) {
   // asserts that *in points to the correct amount of memory
   return load_be<T>(std::span<const uint8_t, sizeof(T)>(in + off * sizeof(T), sizeof(T)));
}

/**
* Load a little-endian unsigned integer
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th unsigned integer of in, as a little-endian value
*/
template <concepts::unsigned_integral T>
inline constexpr T load_le(const uint8_t in[], size_t off) {
   // asserts that *in points to the correct amount of memory
   return load_le<T>(std::span<const uint8_t, sizeof(T)>(in + off * sizeof(T), sizeof(T)));
}

/**
* Load many big-endian unsigned integers
* @param in   a fixed-length span to some bytes
* @param outs a arbitrary-length parameter list of unsigned integers to be loaded
*/
template <ranges::contiguous_range<uint8_t> InR, concepts::unsigned_integral... Ts>
   requires all_same_v<Ts...>
inline constexpr void load_be(InR&& in, Ts&... outs) {
   ranges::assert_exact_byte_length<(sizeof(Ts) + ...)>(in);
   auto load_one = [off = 0]<typename T>(auto i, T& o) mutable {
      o = load_be<T>(i.subspan(off).template first<sizeof(T)>());
      off += sizeof(T);
   };

   (load_one(std::span{in}, outs), ...);
}

/**
* Load many little-endian unsigned integers
* @param in   a fixed-length span to some bytes
* @param outs a arbitrary-length parameter list of unsigned integers to be loaded
*/
template <ranges::contiguous_range<uint8_t> InR, concepts::unsigned_integral... Ts>
   requires all_same_v<Ts...>
inline constexpr void load_le(InR&& in, Ts&... outs) {
   ranges::assert_exact_byte_length<(sizeof(Ts) + ...)>(in);
   auto load_one = [off = 0]<typename T>(auto i, T& o) mutable {
      o = load_le<T>(i.subspan(off).template first<sizeof(T)>());
      off += sizeof(T);
   };

   (load_one(std::span{in}, outs), ...);
}

/**
* Load two little-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
*/
template <typename T>
inline constexpr void load_le(const uint8_t in[], T& x0, T& x1) {
   x0 = load_le<T>(in, 0);
   x1 = load_le<T>(in, 1);
}

/**
* Load four little-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
*/
template <typename T>
inline constexpr void load_le(const uint8_t in[], T& x0, T& x1, T& x2, T& x3) {
   x0 = load_le<T>(in, 0);
   x1 = load_le<T>(in, 1);
   x2 = load_le<T>(in, 2);
   x3 = load_le<T>(in, 3);
}

/**
* Load eight little-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
* @param x4 where the fifth word will be written
* @param x5 where the sixth word will be written
* @param x6 where the seventh word will be written
* @param x7 where the eighth word will be written
*/
template <typename T>
inline constexpr void load_le(const uint8_t in[], T& x0, T& x1, T& x2, T& x3, T& x4, T& x5, T& x6, T& x7) {
   x0 = load_le<T>(in, 0);
   x1 = load_le<T>(in, 1);
   x2 = load_le<T>(in, 2);
   x3 = load_le<T>(in, 3);
   x4 = load_le<T>(in, 4);
   x5 = load_le<T>(in, 5);
   x6 = load_le<T>(in, 6);
   x7 = load_le<T>(in, 7);
}

/**
* Load a variable number of little-endian words
* @param out the output array of words
* @param in the input array of bytes
* @param count how many words are in in
*/
template <typename T>
inline constexpr void load_le(T out[], const uint8_t in[], size_t count) {
   if(count > 0) {
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
      typecast_copy(out, in, count);

#elif defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
      typecast_copy(out, in, count);

      for(size_t i = 0; i != count; ++i)
         out[i] = reverse_bytes(out[i]);
#else
      for(size_t i = 0; i != count; ++i)
         out[i] = load_le<T>(in, i);
#endif
   }
}

/**
* Load two big-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
*/
template <typename T>
inline constexpr void load_be(const uint8_t in[], T& x0, T& x1) {
   x0 = load_be<T>(in, 0);
   x1 = load_be<T>(in, 1);
}

/**
* Load four big-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
*/
template <typename T>
inline constexpr void load_be(const uint8_t in[], T& x0, T& x1, T& x2, T& x3) {
   x0 = load_be<T>(in, 0);
   x1 = load_be<T>(in, 1);
   x2 = load_be<T>(in, 2);
   x3 = load_be<T>(in, 3);
}

/**
* Load eight big-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
* @param x4 where the fifth word will be written
* @param x5 where the sixth word will be written
* @param x6 where the seventh word will be written
* @param x7 where the eighth word will be written
*/
template <typename T>
inline constexpr void load_be(const uint8_t in[], T& x0, T& x1, T& x2, T& x3, T& x4, T& x5, T& x6, T& x7) {
   x0 = load_be<T>(in, 0);
   x1 = load_be<T>(in, 1);
   x2 = load_be<T>(in, 2);
   x3 = load_be<T>(in, 3);
   x4 = load_be<T>(in, 4);
   x5 = load_be<T>(in, 5);
   x6 = load_be<T>(in, 6);
   x7 = load_be<T>(in, 7);
}

/**
* Load a variable number of big-endian words
* @param out the output array of words
* @param in the input array of bytes
* @param count how many words are in in
*/
template <typename T>
inline constexpr void load_be(T out[], const uint8_t in[], size_t count) {
   if(count > 0) {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
      typecast_copy(out, in, count);

#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
      typecast_copy(out, in, count);

      for(size_t i = 0; i != count; ++i) {
         out[i] = reverse_bytes(out[i]);
      }
#else
      for(size_t i = 0; i != count; ++i)
         out[i] = load_be<T>(in, i);
#endif
   }
}

/**
* Store a big-endian unsigned integer
* @param in the input unsigned integer
* @param out_range the fixed-length span to write to
*/
template <concepts::unsigned_integral T, ranges::contiguous_output_range<uint8_t> OutR>
inline constexpr void store_be(T in, OutR&& out_range) {
   ranges::assert_exact_byte_length<sizeof(T)>(out_range);
   std::span out{out_range};
   if constexpr(sizeof(T) == 1) {
      out[0] = static_cast<uint8_t>(in);
   } else {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
      typecast_copy(out, in);
#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
      typecast_copy(out, reverse_bytes(in));
#else
      [&]<size_t... i>(std::index_sequence<i...>) {
         ((out[i] = get_byte<i>(in)), ...);
      }
      (std::make_index_sequence<sizeof(T)>());
#endif
   }
}

/**
* Store a little-endian unsigned integer
* @param in the input unsigned integer
* @param out_range the fixed-length span to write to
*/
template <concepts::unsigned_integral T, ranges::contiguous_output_range<uint8_t> OutR>
inline constexpr void store_le(T in, OutR&& out_range) {
   ranges::assert_exact_byte_length<sizeof(T)>(out_range);
   std::span out{out_range};
   if constexpr(sizeof(T) == 1) {
      out[0] = static_cast<uint8_t>(in);
   } else {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
      typecast_copy(out, reverse_bytes(in));
#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
      typecast_copy(out, in);
#else
      [&]<size_t... i>(std::index_sequence<i...>) {
         ((out[i] = get_byte<sizeof(T) - i - 1>(in)), ...);
      }
      (std::make_index_sequence<sizeof(T)>());
#endif
   }
}

/**
* Store a big-endian unsigned integer
* @param in the input unsigned integer
* @param out the byte array to write to
*/
template <concepts::unsigned_integral T>
inline constexpr void store_be(T in, uint8_t out[sizeof(T)]) {
   store_be(in, std::span<uint8_t, sizeof(T)>(out, sizeof(T)));
}

/**
* Store a little-endian unsigned integer
* @param in the input unsigned integer
* @param out the byte array to write to
*/
template <concepts::unsigned_integral T>
inline constexpr void store_le(T in, uint8_t out[sizeof(T)]) {
   store_le(in, std::span<uint8_t, sizeof(T)>(out, sizeof(T)));
}

/**
* Store many big-endian unsigned integers
* @param out a fixed-length span to some bytes
* @param ins a arbitrary-length parameter list of unsigned integers to be stored
*/
template <ranges::contiguous_output_range<uint8_t> OutR, concepts::unsigned_integral... Ts>
   requires all_same_v<Ts...>
inline constexpr void store_be(OutR&& out, Ts... ins) {
   ranges::assert_exact_byte_length<(sizeof(Ts) + ...)>(out);
   auto store_one = [off = 0]<typename T>(auto o, T i) mutable {
      store_be<T>(i, o.subspan(off).template first<sizeof(T)>());
      off += sizeof(T);
   };

   (store_one(std::span{out}, ins), ...);
}

/**
* Store many little-endian unsigned integers
* @param out a fixed-length span to some bytes
* @param ins a arbitrary-length parameter list of unsigned integers to be stored
*/
template <ranges::contiguous_output_range<uint8_t> OutR, concepts::unsigned_integral... Ts>
   requires all_same_v<Ts...>
inline constexpr void store_le(OutR&& out, Ts... ins) {
   ranges::assert_exact_byte_length<(sizeof(Ts) + ...)>(out);
   auto store_one = [off = 0]<typename T>(auto o, T i) mutable {
      store_le<T>(i, o.subspan(off).template first<sizeof(T)>());
      off += sizeof(T);
   };

   (store_one(std::span{out}, ins), ...);
}

/**
* Store two little-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
*/
template <typename T>
inline constexpr void store_le(uint8_t out[], T x0, T x1) {
   store_le(x0, out + (0 * sizeof(T)));
   store_le(x1, out + (1 * sizeof(T)));
}

/**
* Store two big-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
*/
template <typename T>
inline constexpr void store_be(uint8_t out[], T x0, T x1) {
   store_be(x0, out + (0 * sizeof(T)));
   store_be(x1, out + (1 * sizeof(T)));
}

/**
* Store four little-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
*/
template <typename T>
inline constexpr void store_le(uint8_t out[], T x0, T x1, T x2, T x3) {
   store_le(x0, out + (0 * sizeof(T)));
   store_le(x1, out + (1 * sizeof(T)));
   store_le(x2, out + (2 * sizeof(T)));
   store_le(x3, out + (3 * sizeof(T)));
}

/**
* Store four big-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
*/
template <typename T>
inline constexpr void store_be(uint8_t out[], T x0, T x1, T x2, T x3) {
   store_be(x0, out + (0 * sizeof(T)));
   store_be(x1, out + (1 * sizeof(T)));
   store_be(x2, out + (2 * sizeof(T)));
   store_be(x3, out + (3 * sizeof(T)));
}

/**
* Store eight little-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
* @param x4 the fifth word
* @param x5 the sixth word
* @param x6 the seventh word
* @param x7 the eighth word
*/
template <typename T>
inline constexpr void store_le(uint8_t out[], T x0, T x1, T x2, T x3, T x4, T x5, T x6, T x7) {
   store_le(x0, out + (0 * sizeof(T)));
   store_le(x1, out + (1 * sizeof(T)));
   store_le(x2, out + (2 * sizeof(T)));
   store_le(x3, out + (3 * sizeof(T)));
   store_le(x4, out + (4 * sizeof(T)));
   store_le(x5, out + (5 * sizeof(T)));
   store_le(x6, out + (6 * sizeof(T)));
   store_le(x7, out + (7 * sizeof(T)));
}

/**
* Store eight big-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
* @param x4 the fifth word
* @param x5 the sixth word
* @param x6 the seventh word
* @param x7 the eighth word
*/
template <typename T>
inline constexpr void store_be(uint8_t out[], T x0, T x1, T x2, T x3, T x4, T x5, T x6, T x7) {
   store_be(x0, out + (0 * sizeof(T)));
   store_be(x1, out + (1 * sizeof(T)));
   store_be(x2, out + (2 * sizeof(T)));
   store_be(x3, out + (3 * sizeof(T)));
   store_be(x4, out + (4 * sizeof(T)));
   store_be(x5, out + (5 * sizeof(T)));
   store_be(x6, out + (6 * sizeof(T)));
   store_be(x7, out + (7 * sizeof(T)));
}

template <typename T>
void copy_out_be(uint8_t out[], size_t out_bytes, const T in[]) {
   while(out_bytes >= sizeof(T)) {
      store_be(in[0], out);
      out += sizeof(T);
      out_bytes -= sizeof(T);
      in += 1;
   }

   for(size_t i = 0; i != out_bytes; ++i) {
      out[i] = get_byte_var(i % 8, in[0]);
   }
}

template <typename T, typename Alloc>
void copy_out_vec_be(uint8_t out[], size_t out_bytes, const std::vector<T, Alloc>& in) {
   copy_out_be(out, out_bytes, in.data());
}

template <typename T>
void copy_out_le(uint8_t out[], size_t out_bytes, const T in[]) {
   while(out_bytes >= sizeof(T)) {
      store_le(in[0], out);
      out += sizeof(T);
      out_bytes -= sizeof(T);
      in += 1;
   }

   for(size_t i = 0; i != out_bytes; ++i) {
      out[i] = get_byte_var(sizeof(T) - 1 - (i % 8), in[0]);
   }
}

template <typename T, typename Alloc>
void copy_out_vec_le(uint8_t out[], size_t out_bytes, const std::vector<T, Alloc>& in) {
   copy_out_le(out, out_bytes, in.data());
}

}  // namespace Botan

#endif
