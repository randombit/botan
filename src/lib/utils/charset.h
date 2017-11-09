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
* The different charsets (nominally) supported by Botan.
*/
enum Character_Set {
   LOCAL_CHARSET,
   UCS2_CHARSET,
   UTF8_CHARSET,
   LATIN1_CHARSET
};

/**
* Convert a sequence of UCS-2 (big endian) characters to a UTF-8 string
* This is used for ASN.1 BMPString type
* @param ucs2 the sequence of UCS-2 characters
* @param len length of ucs2 in bytes, must be a multiple of 2
*/
std::string BOTAN_UNSTABLE_API ucs2_to_utf8(const uint8_t ucs2[], size_t len);

/**
* Convert a sequence of UCS-4 (big endian) characters to a UTF-8 string
* This is used for ASN.1 UniversalString type
* @param ucs4 the sequence of UCS-4 characters
* @param len length of ucs4 in bytes, must be a multiple of 4
*/
std::string BOTAN_UNSTABLE_API ucs4_to_utf8(const uint8_t ucs4[], size_t len);

namespace Charset {

/*
* Character Set Handling
*/
std::string BOTAN_PUBLIC_API(2,0) transcode(const std::string& str,
                                Character_Set to,
                                Character_Set from);

bool BOTAN_PUBLIC_API(2,0) is_digit(char c);
bool BOTAN_PUBLIC_API(2,0) is_space(char c);
bool BOTAN_PUBLIC_API(2,0) caseless_cmp(char x, char y);

uint8_t BOTAN_PUBLIC_API(2,0) char2digit(char c);
char BOTAN_PUBLIC_API(2,0) digit2char(uint8_t b);

}

}

#endif
