/*
 * Helper functions to implement Keccak-derived functions from NIST SP.800-185
 * (C) 2023 Jack Lloyd
 * (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KECCAK_HELPERS_H_
#define BOTAN_KECCAK_HELPERS_H_

#include <botan/assert.h>

#include <array>
#include <concepts>
#include <cstdint>
#include <span>

namespace Botan {

/**
 * Integer encoding defined in NIST SP.800-185 that can be unambiguously
 * parsed from the beginning of the string.
 *
 * This function does not allocate any memory and requires the caller to
 * provide a sufficiently large @p buffer. For a given @p x, this will
 * need exactly keccak_int_encoding_size() bytes. For an arbitrary @p x
 * it will generate keccak_max_int_encoding_size() bytes at most.
 *
 * @param buffer  buffer to write the left-encoding of @p x to.
 *                It is assumed that the buffer will hold at least
 *                keccak_int_encoding_size() bytes.
 * @param x       the integer to be left-encoded
 * @return        the byte span that represents the bytes written to @p buffer.
 */
BOTAN_TEST_API std::span<const uint8_t> keccak_int_left_encode(std::span<uint8_t> buffer, size_t x);

/**
 * Integer encoding defined in NIST SP.800-185 that can be unambiguously
 * parsed from the end of the string.
 *
 * This function does not allocate any memory and requires the caller to
 * provide a sufficiently large @p buffer. For a given @p x, this will
 * need exactly keccak_int_encoding_size() bytes. For an arbitrary @p x
 * it will generate keccak_max_int_encoding_size() bytes at most.
 *
 * @param out  buffer to write the right-encoding of @p x to.
 *             It is assumed that the buffer will hold at least
 *             keccak_int_encoding_size() bytes.
 * @param x    the integer to be right-encoded
 * @return     the byte span that represents the bytes written to @p buffer.
 */
BOTAN_TEST_API std::span<const uint8_t> keccak_int_right_encode(std::span<uint8_t> out, size_t x);

/**
 * @returns the required bytes for encodings of keccak_int_left_encode() or
 *          keccak_int_right_encode() given an integer @p x
 */
BOTAN_TEST_API size_t keccak_int_encoding_size(size_t x);

/**
 * @returns the maximum required bytes for encodings of keccak_int_left_encode() or
 *          keccak_int_right_encode()
 */
constexpr size_t keccak_max_int_encoding_size() {
   return sizeof(size_t) + 1 /* the length tag */;
}

template <typename T>
concept updatable_object = requires(T& a, std::span<const uint8_t> span) { a.update(span); };

template <typename T>
concept appendable_object = requires(T& a, std::span<const uint8_t> s) { a.insert(a.end(), s.begin(), s.end()); };

template <typename T>
concept absorbing_object = updatable_object<T> || appendable_object<T>;

/**
 * This is a combination of the functions encode_string() and bytepad() defined
 * in NIST SP.800-185 Section 2.3. Additionally, the result is directly streamed
 * into the provided XOF to avoid unneccessary memory allocation or a byte vector.
 *
 * @param sink         the XOF or byte vector to absorb the @p byte_strings into
 * @param padding_mod  the modulus value to create a padding for (NIST calls this 'w')
 * @param byte_strings a variable-length list of byte strings to be encoded and
 *                     absorbed into the given @p xof
 * @returns the number of bytes absorbed into the @p xof
 */
template <absorbing_object T, typename... Ts>
   requires(std::constructible_from<std::span<const uint8_t>, Ts> && ...)
size_t keccak_absorb_padded_strings_encoding(T& sink, size_t padding_mod, Ts... byte_strings) {
   BOTAN_ASSERT_NOMSG(padding_mod > 0);

   // used as temporary storage for all integer encodings in this function
   std::array<uint8_t, keccak_max_int_encoding_size()> int_encoding_buffer;

   // absorbs byte strings and counts the number of absorbed bytes
   size_t bytes_absorbed = 0;
   auto absorb = [&](std::span<const uint8_t> bytes) {
      if constexpr(updatable_object<T>) {
         sink.update(bytes);
      } else if constexpr(appendable_object<T>) {
         sink.insert(sink.end(), bytes.begin(), bytes.end());
      }
      bytes_absorbed += bytes.size();
   };

   // encodes a given string and absorbs it into the XOF straight away
   auto encode_string_and_absorb = [&](std::span<const uint8_t> bytes) {
      absorb(keccak_int_left_encode(int_encoding_buffer, bytes.size() * 8));
      absorb(bytes);
   };

   // absorbs as many zero-bytes as requested into the XOF
   auto absorb_padding = [&](size_t padding_bytes) {
      for(size_t i = 0; i < padding_bytes; ++i) {
         const uint8_t zero_byte = 0;
         absorb({&zero_byte, 1});
      }
   };

   // implementation of bytepad(encode_string(Ts) || ...) that absorbs the result
   // staight into the given xof
   absorb(keccak_int_left_encode(int_encoding_buffer, padding_mod));
   (encode_string_and_absorb(byte_strings), ...);
   absorb_padding(padding_mod - (bytes_absorbed % padding_mod));

   return bytes_absorbed;
}

}  // namespace Botan

#endif
