/*
* Integer Rounding Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ROUNDING_H__
#define BOTAN_ROUNDING_H__

#include <botan/types.h>

namespace Botan {

/*
* Round up n to multiple of align_to
*/
inline u32bit round_up(u32bit n, u32bit align_to)
   {
   if(n % align_to || n == 0)
      n += align_to - (n % align_to);
   return n;
   }

/*
* Round down n to multiple of align_to
*/
inline u32bit round_down(u32bit n, u32bit align_to)
   {
   return (n - (n % align_to));
   }

}

#endif
