/*
* Public Key Work Factor Functions
* (C) 1999-2007,2012,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/workfactor.h>

#include <botan/assert.h>
#include <cmath>
#include <numbers>

namespace Botan {

size_t ecp_work_factor(size_t bits) {
   return bits / 2;
}

namespace {

size_t nfs_workfactor(size_t bits, double log2_k) {
   // approximates natural logarithm of an integer of given bitsize
   const double log_p = static_cast<double>(bits) / std::numbers::log2e;

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

size_t dl_exponent_size(size_t p_bits) {
   BOTAN_ARG_CHECK(p_bits > 1, "Invalid prime length");

   /*
   For relevant sizes we follow the suggestions in
   NIST SP 800-56B Rev 2 Appendix D
   "Maximum Security Strength Estimates for IFC Modulus Lengths"

   For sizes outside the range considered in the SP we use some sensible values

   Note that we return twice the value given in Table 4 since we are choosing
   the exponent size as twice the estimated security strength.

   See also NIST SP 800-56A Rev 3 Appendix D, Tables 25 and 26
   */

   if(p_bits <= 256) {
      /*
      * For stupidly small groups we might return a value larger than the group
      * size if we fell into the conditionals below. Just use the maximum
      * possible exponent size - for all the good it will do you with a group
      * this weak.
      */
      return p_bits - 1;
   } else if(p_bits <= 1024) {
      /*
      Not in the SP, but general estimates are that a 1024 bit group provides at
      most 80 bits security, so using an exponent appropriate for 96 bit security
      is more than sufficient.
      */
      return 192;
   } else if(p_bits <= 2048) {
      return 224;  // SP 800-56B
   } else if(p_bits <= 3072) {
      return 256;  // SP 800-56B
   } else if(p_bits <= 4096) {
      return 304;  // SP 800-56B
   } else if(p_bits <= 6144) {
      return 352;  // SP 800-56B
   } else if(p_bits <= 8192) {
      return 400;  // SP 800-56B
   } else {
      // For values larger than we know about, just saturate to 256 bit security
      // which is Good Enough for FFDH
      //
      // NIST puts 15360 bit groups at exactly 256 bits security
      return 512;
   }
}

}  // namespace Botan
