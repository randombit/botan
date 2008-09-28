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
   asm("bswapl %0" : "=r" (input) : "0" (input));
   return input;
   }

inline u64bit reverse_bytes(u64bit input)
   {
   asm("bswapq %0" : "=r" (input) : "0" (input));
   return input;
   }

}

#endif
