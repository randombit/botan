/*
* Word Rotation Operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_WORD_ROTATE_H__
#define BOTAN_WORD_ROTATE_H__

#include <botan/types.h>

namespace Botan {

/*
* Word Rotation Functions
*/
template<typename T> inline T rotate_left(T input, u32bit rot)
   {
   return static_cast<T>((input << rot) | (input >> (8*sizeof(T)-rot)));;
   }

template<typename T> inline T rotate_right(T input, u32bit rot)
   {
   return static_cast<T>((input >> rot) | (input << (8*sizeof(T)-rot)));
   }

}

#endif
