/*
* Utility Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_UTIL_H__
#define BOTAN_UTIL_H__

#include <botan/types.h>

namespace Botan {

/*
* Time Access Functions
*/
BOTAN_DLL u64bit system_time();

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

/*
* Work Factor Estimates
*/
BOTAN_DLL u32bit dl_work_factor(u32bit);

}

#endif
