/*
* Read out bytes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GET_BYTE_H__
#define BOTAN_GET_BYTE_H__

#include <botan/types.h>

namespace Botan {

/*
* Byte Extraction Function
*/
template<typename T> inline byte get_byte(u32bit byte_num, T input)
   {
   return static_cast<byte>(
      input >> ((sizeof(T)-1-(byte_num&(sizeof(T)-1))) << 3)
      );
   }

}

#endif
