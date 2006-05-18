/*************************************************
* Character Set Handling Header File             *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_CHARSET_H__
#define BOTAN_CHARSET_H__

#include <botan/types.h>
#include <string>

namespace Botan {

/*************************************************
* Character Set Handling                         *
*************************************************/
bool is_digit(char);
bool is_space(char);
char to_lower(char);

byte char2digit(char);
char digit2char(byte);

std::string local2iso(const std::string&);
std::string iso2local(const std::string&);

std::string utf2iso(const std::string&);
std::string iso2utf(const std::string&);

}

#endif
