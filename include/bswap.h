/*************************************************
* Byte Swapping Operations Header File           *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BSWAP_H__
#define BOTAN_BSWAP_H__

#include <botan/types.h>
#include <botan/rotate.h>

namespace Botan {

/*************************************************
* Byte Swapping Functions                        *
*************************************************/
inline u16bit reverse_bytes(u16bit input)
   {
   return rotate_left(input, 8);
   }

inline u32bit reverse_bytes(u32bit input)
   {
   input = ((input & 0xFF00FF00) >> 8) | ((input & 0x00FF00FF) << 8);
   return rotate_left(input, 16);
   }

inline u64bit reverse_bytes(u64bit input)
   {
   u32bit hi = ((input >> 40) & 0x00FF00FF) | ((input >> 24) & 0xFF00FF00);
   u32bit lo = ((input & 0xFF00FF00) >> 8) | ((input & 0x00FF00FF) << 8);
   hi = (hi << 16) | (hi >> 16);
   lo = (lo << 16) | (lo >> 16);
   return (static_cast<u64bit>(lo) << 32) | hi;
   }

}

#endif
