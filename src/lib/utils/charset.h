/*
* Character Set Conversions
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CHARSET_H_
#define BOTAN_CHARSET_H_

#include <botan/types.h>
#include <string>

namespace Botan {

/**
* Convert a sequence of UCS-2 (big endian) characters to a UTF-8 string
* This is used for ASN.1 BMPString type
* @param ucs2 the sequence of UCS-2 characters
* @param len length of ucs2 in bytes, must be a multiple of 2
*/
BOTAN_TEST_API std::string ucs2_to_utf8(const uint8_t ucs2[], size_t len);

/**
* Convert a sequence of UCS-4 (big endian) characters to a UTF-8 string
* This is used for ASN.1 UniversalString type
* @param ucs4 the sequence of UCS-4 characters
* @param len length of ucs4 in bytes, must be a multiple of 4
*/
BOTAN_TEST_API std::string ucs4_to_utf8(const uint8_t ucs4[], size_t len);

BOTAN_TEST_API std::string latin1_to_utf8(const uint8_t latin1[], size_t len);

/**
* Return a string containing 'c', quoted and possibly escaped
*
* This is used when creating an error message nothing an invalid character
* in some codex (for example during hex decoding)
*
* Currently this function escapes tab, newlines and carriage return
* as "\t", "\n", and "\r", and also escapes characters > 0x7F as
* "\xHH" where HH is the hex code.
*/
std::string format_char_for_display(char c);

}  // namespace Botan

#endif
