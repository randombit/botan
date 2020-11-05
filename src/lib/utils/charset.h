/*
* Character Set Handling
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

/**
* Convert a UTF-8 string to Latin-1
* If a character outside the Latin-1 range is encountered, an exception is thrown.
*/
BOTAN_TEST_API std::string utf8_to_latin1(const std::string& utf8);

BOTAN_TEST_API std::string ucs2_to_latin1(const std::string& ucs2);

BOTAN_TEST_API std::string latin1_to_utf8(const std::string& iso8859);

namespace Charset {

/*
* Simple character classifier functions
*/
bool is_digit(char c);
bool is_space(char c);
bool caseless_cmp(char x, char y);

uint8_t char2digit(char c);
char digit2char(uint8_t b);

}

}

#endif
