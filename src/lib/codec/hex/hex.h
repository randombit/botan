/*
* Hex Encoding and Decoding
* (C) 2010 Jack Lloyd
*     2024 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HEX_CODEC_H_
#define BOTAN_HEX_CODEC_H_

#include <botan/concepts.h>
#include <botan/secmem.h>

#include <array>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

namespace Botan {

/**
* Perform hex encoding
* @param output an array of at least input_length*2 bytes
* @param input is some binary data
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
*/
void BOTAN_PUBLIC_API(2, 0)
   hex_encode(char output[], const uint8_t input[], size_t input_length, bool uppercase = true);

/**
* Perform hex encoding
* @param input some input
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
std::string BOTAN_PUBLIC_API(2, 0) hex_encode(const uint8_t input[], size_t input_length, bool uppercase = true);

/**
* Perform hex encoding
* @param input some input
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
inline std::string hex_encode(std::span<const uint8_t> input, bool uppercase = true) {
   return hex_encode(input.data(), input.size(), uppercase);
}

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*        bytes of input were actually consumed. If less than
*        input_length, then the range input[consumed:length]
*        should be passed in later along with more input.
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2, 0)
   hex_decode(uint8_t output[], const char input[], size_t input_length, size_t& input_consumed, bool ignore_ws = true);

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2, 0)
   hex_decode(uint8_t output[], const char input[], size_t input_length, bool ignore_ws = true);

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(3, 0) hex_decode(uint8_t output[], std::string_view input, bool ignore_ws = true);

/**
* Perform hex decoding
* @param output a contiguous byte buffer of at least input_length/2 bytes
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
*                  exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(3, 0) hex_decode(std::span<uint8_t> output, std::string_view input, bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
std::vector<uint8_t> BOTAN_PUBLIC_API(2, 0) hex_decode(const char input[], size_t input_length, bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
std::vector<uint8_t> BOTAN_PUBLIC_API(3, 0) hex_decode(std::string_view input, bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(2, 0)
   hex_decode_locked(const char input[], size_t input_length, bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(3, 0) hex_decode_locked(std::string_view input, bool ignore_ws = true);

namespace detail {

constexpr bool is_hex_whitespace(char c) {
   constexpr std::array<char, 6> wschars = {' ', '\t', '\n', '\r', '\0', ':'};
   return std::find(wschars.begin(), wschars.end(), c) != wschars.end();
}

constexpr size_t hex_outchars(size_t chars, size_t hexchars) {
   return (hexchars == std::dynamic_extent) ? chars / 2 : hexchars / 2;
};

/**
* TODO: this could also take a std::span, but GCC's iterator-debugging tools
*       confused the constexpr-ness. Last tried with GCC 13.3.
*
* @tparam chars     The number of characters in @p input
* @tparam hexchars  The number of non-whitespace characters within @p input
*
* Note: The second template parameter is optional and is typically explicitly
*       determined by filtering through a string literal in some wrapper API at
*       compile time.
*
* @returns the hex-decoded @p input (if .second is false, the decoding failed)
*/
template <size_t chars, size_t hexchars = std::dynamic_extent>
   requires(hexchars == std::dynamic_extent || (chars >= hexchars && hexchars % 2 == 0))
constexpr auto hex_decode_array(const char (&input)[chars])
   -> std::optional<std::array<uint8_t, hex_outchars(chars, hexchars)>> {
   // If the caller didn't explicitly specify the amount of expected hex chars,
   // e.g. to allow ignoring white-space, we have to ensure that the passed-in
   // character count is divisible by 2. This has to take an optional null
   // termination character into account.
   if constexpr(hexchars == std::dynamic_extent) {
      const bool is_null_terminated = input[chars - 1] == '\0';
      const size_t actual_chars = (!is_null_terminated) ? chars : chars - 1;
      if(actual_chars % 2 != 0) {
         return std::nullopt;
      }
   }

   // Generator that returns decoded hex-characters one-by-one from the input
   // buffer. Essentially, this returns nibbles (of value 0-15), or std::nullopt
   // if the next character was not interpretable as a hex character or no more
   // data is available in the input buffer.
   //
   // Once, std::nullopt was returned, the state of the generator is undefined
   // and its output should not be trusted any longer.
   auto next = [&, in = size_t(0)]() mutable -> std::optional<uint8_t> {
      constexpr bool ignore_ws = hexchars != std::dynamic_extent;
      while(in < chars) {
         const auto c = input[in++];
         if(ignore_ws && is_hex_whitespace(c)) {
            continue;
         } else if(c >= '0' && c <= '9') {
            return static_cast<uint8_t>(c - '0');
         } else if(c >= 'a' && c <= 'f') {
            return static_cast<uint8_t>(c - 'a' + 10);
         } else if(c >= 'A' && c <= 'F') {
            return static_cast<uint8_t>(c - 'A' + 10);
         } else {
            break;
         }
      }
      return std::nullopt;
   };

   std::array<uint8_t, hex_outchars(chars, hexchars)> result;
   for(auto& byte : result) {
      const auto hi = next();
      const auto lo = next();
      if(!hi || !lo) {
         return std::nullopt;
      }

      byte = *hi << 4 | *lo;
   }

   return result;
}

}  // namespace detail

/**
* Perform hex decoding into a std::array
* @tparam bytes the number of bytes expected for the output (must match exactly)
* @param input some hex input
* @return decoded hex output as a std::array sized as @p bytes
*/
template <size_t bytes>
auto hex_decode_array(std::string_view input) -> std::array<uint8_t, bytes> {
   BOTAN_ARG_CHECK(input.size() % 2 == 0, "Parameter contains odd number of hex characters");
   BOTAN_ARG_CHECK(input.size() / 2 == bytes, "Parameter size does not match expected output size");
   std::array<uint8_t, bytes> result;
   hex_decode(result, input, false /* don't allow whitespace */);
   return result;
}

/**
* Perform hex decoding (possibly at compile time)
*
* Currently this cannot handle whitespace, because determining the number of
* elements in the output array from the number of hex characters in the @p input
* string isn't possible at compile time, to the best of our knowledge.
* I.e. this wouldn't compile in C++20, because @p input isn't constexpr::
*
*   constexpr auto hexchars = std::count_if([...], detail::is_hex_whitespace);
*
* TODO: Re-evaluate this for future revisions of C++
*
* @param input some hex input as a string-literal
* @return decoded hex output as an appropriately sized std::array
*/
template <size_t hexchars>
constexpr auto hex_decode_array(const char (&input)[hexchars]) -> std::array<uint8_t, hexchars / 2> {
   if(std::is_constant_evaluated()) {
      BOTAN_DIAGNOSTIC_PUSH

      // MSVC claimed that the expression in the condition below is const and
      // could therefore use `if constexpr`. That would be great, but the
      // invocation to `detail::hex_decode_array()` is not considered a constant
      // expression in all contexts, unfortunately. Otherwise it would make
      // sense to use a `static_assert` instead of the std::invalid_argument.
      BOTAN_DIAGNOSTIC_IGNORE_EXPRESSION_IS_CONST

      auto result = detail::hex_decode_array(input);
      if(!result.has_value()) {
         throw std::invalid_argument("Failed to hex decode input literal");
      }
      return result.value();

      BOTAN_DIAGNOSTIC_POP
   } else {
      return hex_decode_array<hexchars / 2>(std::string_view(input));
   }
}

}  // namespace Botan

#endif
