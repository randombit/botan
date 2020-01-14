/*
* Public Key Work Factor Functions
* (C) 1999-2007,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/workfactor.h>
#include <algorithm>
#include <cmath>

namespace Botan {

size_t ecp_work_factor(size_t bits)
   {
   return bits / 2;
   }

namespace {

size_t nfs_workfactor(size_t bits, double log2_k)
   {
   // approximates natural logarithm of an integer of given bitsize
   const double log2_e = 1.44269504088896340736;
   const double log_p = bits / log2_e;

   const double log_log_p = std::log(log_p);

   // RFC 3766: k * e^((1.92 + o(1)) * cubrt(ln(n) * (ln(ln(n)))^2))
   const double est = 1.92 * std::pow(log_p * log_log_p * log_log_p, 1.0/3.0);

   // return log2 of the workfactor
   return static_cast<size_t>(log2_k + log2_e * est);
   }

}

size_t if_work_factor(size_t bits)
   {
   // RFC 3766 estimates k at .02 and o(1) to be effectively zero for sizes of interest

   const double log2_k = -5.6438; // log2(.02)
   return nfs_workfactor(bits, log2_k);
   }

size_t dl_work_factor(size_t bits)
   {
   // Lacking better estimates...
   return if_work_factor(bits);
   }

size_t dl_exponent_size(size_t bits)
   {
   /*
   This uses a slightly tweaked version of the standard work factor
   function above. It assumes k is 1 (thus overestimating the strength
   of the prime group by 5-6 bits), and always returns at least 128 bits
   (this only matters for very small primes).
   */
   const size_t min_workfactor = 64;
   const double log2_k = 0;

   return 2 * std::max<size_t>(min_workfactor, nfs_workfactor(bits, log2_k));
   }

}
