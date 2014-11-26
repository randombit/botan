/*
* Timing Attack Countermeasure Functions
* (C) 2010 Falko Strenzke, Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/ta_utils.h>

namespace Botan {

namespace TA_CM {

/*
* We use volatile in these functions in an attempt to ensure that the
* compiler doesn't optimize in a way that would create branching
* operations.
*
* Note: this needs further testing; on at least x86-64 with GCC,
* volatile is not required to get branch-free operations, it just
* makes the functions much longer/slower. It may not be required
* anywhere.
*/

namespace {

template<typename T>
T expand_mask(T x)
   {
   volatile T r = x;
   for(size_t i = 1; i != sizeof(T) * 8; i *= 2)
      r |= r >> i;
   r &= 1;
   r = ~(r - 1);
   return r;
   }

}

u32bit expand_mask_u32bit(u32bit in)
   {
   return expand_mask<u32bit>(in);
   }

u16bit expand_mask_u16bit(u16bit in)
   {
   return expand_mask<u16bit>(in);
   }

u32bit max_32(u32bit a, u32bit b)
   {
   const u32bit a_larger = b - a; /* negative if a larger */
   const u32bit mask = expand_mask<u32bit>(a_larger >> 31);
   return (a & mask) | (b & ~mask);
   }

u32bit min_32(u32bit a, u32bit b)
   {
   const u32bit a_larger = b - a; /* negative if a larger */
   const u32bit mask = expand_mask<u32bit>(a_larger >> 31);
   return (a & ~mask) | (b & mask);
   }

}

}
