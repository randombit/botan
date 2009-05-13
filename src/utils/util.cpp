/*
* Utility Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/util.h>
#include <algorithm>
#include <cmath>

namespace Botan {

/*
* Round up n to multiple of align_to
*/
u32bit round_up(u32bit n, u32bit align_to)
   {
   if(n % align_to || n == 0)
      n += align_to - (n % align_to);
   return n;
   }

/*
* Round down n to multiple of align_to
*/
u32bit round_down(u32bit n, u32bit align_to)
   {
   return (n - (n % align_to));
   }

/*
* Choose the exponent size for a DL group
*/
u32bit dl_work_factor(u32bit bits)
   {
#if 0
   /*
   These values were taken from RFC 3526
   */
   if(bits <= 1536)
      return 90;
   else if(bits <= 2048)
      return 110;
   else if(bits <= 3072)
      return 130;
   else if(bits <= 4096)
      return 150;
   else if(bits <= 6144)
      return 170;
   else if(bits <= 8192)
      return 190;
   return 256;
#else
   const u32bit MIN_ESTIMATE = 64;

   const double log_x = bits / 1.44;

   const double strength =
      2.76 * std::pow(log_x, 1.0/3.0) * std::pow(std::log(log_x), 2.0/3.0);

   if(strength > MIN_ESTIMATE)
      return static_cast<u32bit>(strength);
   return MIN_ESTIMATE;
#endif
   }

}
