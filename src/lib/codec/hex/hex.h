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

/**
* TODO: this could also take a std::span, but GCC's iterator-debugging tools
*       confused the constexpr-ness. Last tried with GCC 13.3.
*
* @returns the hex-decoded @p input (if .second is false, the decoding failed)
*/
template <size_t hexchars>
constexpr auto hex_decode_array(const char (&input)[hexchars]) {
   std::pair<std::array<uint8_t, hexchars / 2>, bool> result = {{}, true};

   // strip the null terminator if it exists
   const auto N = [&input]() -> size_t {
      const char last_char = input[hexchars - 1];
      if(last_char == '\0') {  // string literal
         return hexchars - 1;
      } else {  // other character array
         return hexchars;
      }
   }();

   if(N % 2 == 0) {
      auto from_hex = [&result](char c) -> uint8_t {
         if(c >= '0' && c <= '9') {
            return static_cast<uint8_t>(c - '0');
         } else if(c >= 'a' && c <= 'f') {
            return static_cast<uint8_t>(c - 'a' + 10);
         } else if(c >= 'A' && c <= 'F') {
            return static_cast<uint8_t>(c - 'A' + 10);
         } else {
            result.second = false;
            return 0;
         }
      };

      for(size_t i = 0; i < N; i += 2) {
         result.first[i / 2] = static_cast<uint8_t>(from_hex(input[i]) << 4 | from_hex(input[i + 1]));
      }
   } else {
      result.second = false;
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
* @param input some hex input as a string-literal
* @return decoded hex output as an appropriately sized std::array
*/
template <size_t hexchars>
constexpr auto hex_decode_array(const char (&input)[hexchars]) -> std::array<uint8_t, hexchars / 2> {
   if(std::is_constant_evaluated()) {
      const auto result = detail::hex_decode_array(input);
      if(!result.second) {
         throw std::invalid_argument("Failed to hex decode input literal");
      }
      return result.first;
   } else {
      return hex_decode_array<hexchars / 2>(std::string_view(input));
   }
}

}  // namespace Botan

#endif
