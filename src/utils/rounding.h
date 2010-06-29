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

/**
* Round up
* @param n an integer
* @param align_to the alignment boundary
* @return n rounded up to a multiple of align_to
*/
template<typename T>
inline T round_up(T n, T align_to)
   {
   if(n % align_to || n == 0)
      n += align_to - (n % align_to);
   return n;
   }

/**
* Round down
* @param n an integer
* @param align_to the alignment boundary
* @return n rounded down to a multiple of align_to
*/
template<typename T>
inline T round_down(T n, T align_to)
   {
   return (n - (n % align_to));
   }

}

#endif
