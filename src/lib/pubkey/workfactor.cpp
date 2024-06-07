/*
* Public Key Work Factor Functions
* (C) 1999-2007,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/workfactor.h>
#include <cmath>
#include <numbers>

namespace Botan {

size_t ecp_work_factor(size_t bits) {
   return bits / 2;
}

namespace {

size_t nfs_workfactor(size_t bits, double log2_k) {
   // approximates natural logarithm of an integer of given bitsize
   const double log_p = bits / std::numbers::log2e;

   const double log_log_p = std::log(log_p);

   // RFC 3766: k * e^((1.92 + o(1)) * cubrt(ln(n) * (ln(ln(n)))^2))
   const double est = 1.92 * std::pow(log_p * log_log_p * log_log_p, 1.0 / 3.0);

   // return log2 of the workfactor
   return static_cast<size_t>(log2_k + std::numbers::log2e * est);
}

}  // namespace

size_t if_work_factor(size_t bits) {
   if(bits < 512) {
      return 0;
   }

   // RFC 3766 estimates k at .02 and o(1) to be effectively zero for sizes of interest

   const double log2_k = -5.6438;  // log2(.02)
   return nfs_workfactor(bits, log2_k);
}

size_t dl_work_factor(size_t bits) {
   // Lacking better estimates...
   return if_work_factor(bits);
}

size_t dl_exponent_size(size_t bits) {
   if(bits == 0) {
      return 0;
   }
   if(bits <= 256) {
      return bits - 1;
   }
   if(bits <= 1024) {
      return 192;
   }
   if(bits <= 1536) {
      return 224;
   }
   if(bits <= 2048) {
      return 256;
   }
   if(bits <= 4096) {
      return 384;
   }
   return 512;
}

}  // namespace Botan
