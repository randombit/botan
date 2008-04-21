/*************************************************
* Character Set Handling Header File             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_CHARSET_H__
#define BOTAN_CHARSET_H__

#include <botan/types.h>
#include <botan/enums.h>
#include <string>

namespace Botan {

namespace Charset {

/*************************************************
* Character Set Handling                         *
*************************************************/
std::string transcode(const std::string&, Character_Set, Character_Set);

bool is_digit(char);
bool is_space(char);
bool caseless_cmp(char, char);

byte char2digit(char);
char digit2char(byte);

}

}

#endif
