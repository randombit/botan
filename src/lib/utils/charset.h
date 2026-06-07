/*
* Character Set Conversions
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CHARSET_H_
#define BOTAN_CHARSET_H_

#include <botan/types.h>
#include <array>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

/**
* Convert a sequence of UCS-2 (big endian) characters to a UTF-8 string
* This is used for ASN.1 BMPString type
* @param ucs2 the sequence of UCS-2 characters, length must be a multiple of 2
*/
BOTAN_TEST_API std::string ucs2_to_utf8(std::span<const uint8_t> ucs2);

/**
 * Convert a UTF-8 string to a sequence of UCS-2 (big endian) characters
 * This is used for ASN.1 BMPString type
 * @param utf8 the UTF-8 string
 * @return a vector of bytes containing the UCS-2 (big endian) encoding
 * @throws Decoding_Error if the input is not valid UTF-8 (including overlong encodings,
 *         surrogate code points, or values outside Unicode), or if a code point exceeds
 *         U+FFFF and cannot be represented in UCS-2
 */
BOTAN_TEST_API std::vector<uint8_t> utf8_to_ucs2(std::string_view utf8);

/**
* Convert a sequence of UCS-4 (big endian) characters to a UTF-8 string
* This is used for ASN.1 UniversalString type
* @param ucs4 the sequence of UCS-4 characters, length must be a multiple of 4
*/
BOTAN_TEST_API std::string ucs4_to_utf8(std::span<const uint8_t> ucs4);

/**
 * Convert a UTF-8 string to a sequence of UCS-4 (big endian) characters
 * This is used for ASN.1 UniversalString type
 * @param utf8 the UTF-8 string
 * @return a vector of bytes containing the UCS-4 (big endian) encoding
 * @throws Decoding_Error if the input is not valid UTF-8 (including overlong encodings,
 *         surrogate code points, or values outside the Unicode scalar value range U+0000..U+10FFFF)
 */
BOTAN_TEST_API std::vector<uint8_t> utf8_to_ucs4(std::string_view utf8);

BOTAN_TEST_API std::string latin1_to_utf8(std::span<const uint8_t> latin1);

/**
* Return true if this string seems to contain a valid sequence of UTF-8
*/
bool is_valid_utf8(std::string_view str);

/**
* Return true if c is a control character (0x00..0x1F) or DEL (0x7F)
*/
BOTAN_TEST_API bool is_ascii_control_char(char c);

/**
* Return true if the Unicode code point cp is a control character: a C0 control
* (U+0000..U+001F), DEL (U+007F), or a C1 control (U+0080..U+009F)
*/
BOTAN_TEST_API bool is_unicode_control_char(uint32_t cp);

/**
* Map the low four bits of b to an uppercase hex digit ('0'..'9','A'..'F')
*/
inline constexpr char nibble_to_hex(uint8_t b) {
   const uint8_t n = b & 0x0F;
   return static_cast<char>(n < 10 ? '0' + n : 'A' + (n - 10));
}

/**
* Decode the UTF-8 code point beginning at utf8[pos], advancing pos past it
* @throws Decoding_Error if the bytes at pos are not a valid UTF-8 sequence
*/
uint32_t next_utf8_codepoint(std::string_view utf8, size_t& pos);

/**
* Return a copy of utf8 with control characters escaped for safe display
*
* C0 controls (0x00..0x1F), DEL (0x7F), and C1 controls (U+0080..U+009F) are
* each replaced by a "\xHH" escape per byte; all other code points, including
* printable non-ASCII, are passed through unchanged. Any byte that is not part
* of a valid UTF-8 sequence is escaped individually.
*/
BOTAN_TEST_API std::string escape_control_chars(std::string_view utf8);

/**
* Return a string containing 'c', quoted and possibly escaped
*
* This is used when creating an error message noting an invalid character
* in some codec (for example during hex decoding)
*
* Tab, newline, and carriage return are escaped as "\t", "\n", and "\r".
* Any other control character (or DEL), and any byte above 0x7F, is escaped
* as "\xHH" where HH is the hex code.
*/
std::string format_char_for_display(char c);

/**
* Character classifier
*/
class CharacterValidityTable final {
   public:
      static constexpr CharacterValidityTable alpha_numeric_plus(std::string_view extras) {
         TableStorage tbl{};

         set_tbl_range(tbl, "0123456789");
         set_tbl_range(tbl, "abcdefghijklmnopqrstuvwxyz");
         set_tbl_range(tbl, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
         set_tbl_range(tbl, extras);

         return CharacterValidityTable(tbl);
      }

      constexpr bool operator()(char c) const {
         const uint8_t uc = static_cast<uint8_t>(c);
         return ((m_tbl[uc / 32] >> (uc % 32)) & 1) != 0;
      }

      constexpr CharacterValidityTable invert() const {
         TableStorage inverted = m_tbl;
         for(auto& v : inverted) {
            v = ~v;
         }
         return CharacterValidityTable(inverted);
      }

   private:
      using TableStorage = std::array<uint32_t, 8>;  // 256 bits of storage

      static constexpr void set_tbl_range(TableStorage& tbl, std::string_view valid_chars) {
         for(const char c : valid_chars) {
            const uint8_t uc = static_cast<uint8_t>(c);
            tbl[uc / 32] |= (uint32_t{1} << (uc % 32));
         }
      }

      explicit constexpr CharacterValidityTable(TableStorage tbl) : m_tbl(tbl) {}

      TableStorage m_tbl;
};

}  // namespace Botan

#endif
