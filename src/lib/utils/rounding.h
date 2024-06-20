/*
* Integer Rounding Functions
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ROUNDING_H_
#define BOTAN_ROUNDING_H_

#include <botan/types.h>

namespace Botan {

/**
* Integer rounding
*
* Returns an integer z such that n <= z <= n + align_to
* and z % align_to == 0
*
* @param n an integer
* @param align_to the alignment boundary
* @return n rounded up to a multiple of align_to
*/
constexpr inline size_t round_up(size_t n, size_t align_to) {
   // Arguably returning n in this case would also be sensible
   BOTAN_ARG_CHECK(align_to != 0, "align_to must not be 0");

   if(n % align_to > 0) {
      const size_t adj = align_to - (n % align_to);
      BOTAN_ARG_CHECK(n + adj >= n, "Integer overflow during rounding");
      n += adj;
   }
   return n;
}

}  // namespace Botan

#endif
