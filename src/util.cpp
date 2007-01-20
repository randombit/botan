/*************************************************
* Utility Functions Source File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/util.h>
#include <botan/bit_ops.h>
#include <algorithm>
#include <cmath>

namespace Botan {

/*************************************************
* Round up n to multiple of align_to             *
*************************************************/
u32bit round_up(u32bit n, u32bit align_to)
   {
   if(n % align_to || n == 0)
      n += align_to - (n % align_to);
   return n;
   }

/*************************************************
* Round down n to multiple of align_to           *
*************************************************/
u32bit round_down(u32bit n, u32bit align_to)
   {
   return (n - (n % align_to));
   }

/*************************************************
* Return the work required for solving DL        *
*************************************************/
u32bit dl_work_factor(u32bit n_bits)
   {
   const u32bit MIN_ESTIMATE = 64;

   if(n_bits < 32)
      return 0;

   const double log_x = n_bits / 1.44;

   u32bit estimate = (u32bit)(2.76 * std::pow(log_x, 1.0/3.0) *
                                     std::pow(std::log(log_x), 2.0/3.0));

   return std::max(estimate, MIN_ESTIMATE);
   }

/*************************************************
* Estimate the entropy of the buffer             *
*************************************************/
u32bit entropy_estimate(const byte buffer[], u32bit length)
   {
   if(length <= 4)
      return 0;

   u32bit estimate = 0;
   byte last = 0, last_delta = 0, last_delta2 = 0;

   for(u32bit j = 0; j != length; ++j)
      {
      byte delta = last ^ buffer[j];
      last = buffer[j];

      byte delta2 = delta ^ last_delta;
      last_delta = delta;

      byte delta3 = delta2 ^ last_delta2;
      last_delta2 = delta2;

      byte min_delta = delta;
      if(min_delta > delta2) min_delta = delta2;
      if(min_delta > delta3) min_delta = delta3;

      estimate += hamming_weight(min_delta);
      }

   return (estimate / 2);
   }

}
