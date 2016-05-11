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

size_t if_work_factor(size_t bits)
   {
   // RFC 3766: k * e^((1.92 + o(1)) * cubrt(ln(n) * (ln(ln(n)))^2))
   // It estimates k at .02 and o(1) to be effectively zero for sizes of interest
   const double k = .02;

   // approximates natural logarithm of p
   const double log2_e = std::log2(std::exp(1));
   const double log_p = bits / log2_e;

   const double est = 1.92 * std::pow(log_p * std::log(log_p) * std::log(log_p), 1.0/3.0);

   return static_cast<size_t>(std::log2(k) + log2_e * est);
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
   const size_t MIN_WORKFACTOR = 64;
   const double log2_e = std::log2(std::exp(1));
   const double log_p = bits / log2_e;

   const double strength = 1.92 * std::pow(log_p, 1.0/3.0) * std::pow(std::log(log_p), 2.0/3.0);

   return 2 * std::max<size_t>(MIN_WORKFACTOR, static_cast<size_t>(log2_e * strength));
   }

}
