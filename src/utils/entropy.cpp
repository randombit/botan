/*************************************************
* Entropy_Estimator Source File                  *
* (C) 2008 Jack Lloyd                            *
*************************************************/

#include <botan/entropy.h>
#include <botan/bit_ops.h>

namespace Botan {

/**
Update the estimate
*/
void Entropy_Estimator::update(const byte buffer[], u32bit length,
                               u32bit upper_limit)
   {
   u32bit this_buf_estimate = 0;

   /*
   This is pretty naive
   */
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

      this_buf_estimate += hamming_weight(min_delta);
      }

   this_buf_estimate /= 2;

   if(upper_limit)
      estimate += std::min(upper_limit, this_buf_estimate);
   else
      estimate += this_buf_estimate;
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
