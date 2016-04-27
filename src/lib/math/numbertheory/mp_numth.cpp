/*
* Fused and Important MP Algorithms
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/numthry.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/rounding.h>
#include <algorithm>

namespace Botan {

/*
* Square a BigInt
*/
BigInt square(const BigInt& x)
   {
   const size_t x_sw = x.sig_words();

   BigInt z(BigInt::Positive, round_up(2*x_sw, 16));
   secure_vector<word> workspace(z.size());

   bigint_sqr(z.mutable_data(), z.size(),
              workspace.data(),
              x.data(), x.size(), x_sw);
   return z;
   }

/*
* Multiply-Add Operation
*/
BigInt mul_add(const BigInt& a, const BigInt& b, const BigInt& c)
   {
   if(c.is_negative() || c.is_zero())
      throw Invalid_Argument("mul_add: Third argument must be > 0");

   BigInt::Sign sign = BigInt::Positive;
   if(a.sign() != b.sign())
      sign = BigInt::Negative;

   const size_t a_sw = a.sig_words();
   const size_t b_sw = b.sig_words();
   const size_t c_sw = c.sig_words();

   BigInt r(sign, std::max(a.size() + b.size(), c_sw) + 1);
   secure_vector<word> workspace(r.size());

   bigint_mul(r.mutable_data(), r.size(),
              workspace.data(),
              a.data(), a.size(), a_sw,
              b.data(), b.size(), b_sw);

   const size_t r_size = std::max(r.sig_words(), c_sw);
   bigint_add2(r.mutable_data(), r_size, c.data(), c_sw);
   return r;
   }

/*
* Subtract-Multiply Operation
*/
BigInt sub_mul(const BigInt& a, const BigInt& b, const BigInt& c)
   {
   if(a.is_negative() || b.is_negative())
      throw Invalid_Argument("sub_mul: First two arguments must be >= 0");

   BigInt r = a;
   r -= b;
   r *= c;
   return r;
   }

/*
* Multiply-Subtract Operation
*/
BigInt mul_sub(const BigInt& a, const BigInt& b, const BigInt& c)
   {
   if(c.is_negative() || c.is_zero())
      throw Invalid_Argument("mul_sub: Third argument must be > 0");

   BigInt r = a;
   r *= b;
   r -= c;
   return r;
   }

}
