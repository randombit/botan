/*************************************************
* Entropy_Estimator Header File                  *
* (C) 2008 Jack Lloyd                            *
*************************************************/

#ifndef BOTAN_ENTROPY_ESTIMATOR_H__
#define BOTAN_ENTROPY_ESTIMATOR_H__

#include <botan/types.h>
#include <algorithm>

namespace Botan {

/**
Naive Entropy Estimation using first, second, and third order deltas

@todo It would be nice to extend this to test using zlib or bzip2 if
those modules are compiled in to the library
*/
class BOTAN_DLL Entropy_Estimator
   {
   public:
      Entropy_Estimator()
         { last = last_delta = last_delta2 = 0; estimate = 0; }

      /**
      Return the current estimate
      */
      u32bit value() const { return estimate; }

      /**
      Set an upper bound on the estimate so far
      */
      void set_upper_bound(u32bit upper_limit)
         { estimate = std::min(estimate, upper_limit); }

      /**
      Add more entropy data to the current estimation
      */
      void update(const byte buffer[], u32bit length, u32bit upper_limit = 0);
   private:
      u32bit estimate;
      byte last, last_delta, last_delta2;
   };

}

#endif
