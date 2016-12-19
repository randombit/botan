/*
* Fused and Important MP Algorithms
* (C) 1999-2007 Jack Lloyd
*     2016 Matthias Gierlings
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
BigInt square(const BigInt& x) {
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
BigInt mul_add(const BigInt& a, const BigInt& b, const BigInt& c) {
  if (c.is_negative() || c.is_zero()) {
    throw Invalid_Argument("mul_add: Third argument must be > 0");
  }

  BigInt::Sign sign = BigInt::Positive;
  if (a.sign() != b.sign()) {
    sign = BigInt::Negative;
  }

  BigInt r(sign, std::max(a.size() + b.size(), c.sig_words()) + 1);
  secure_vector<word> workspace(r.size());

  bigint_mul(r, a, b, workspace.data());

  const size_t r_size = std::max(r.sig_words(), c.sig_words());
  bigint_add2(r.mutable_data(), r_size, c.data(), c.sig_words());
  return r;
}

/*
* Subtract-Multiply Operation
*/
BigInt sub_mul(const BigInt& a, const BigInt& b, const BigInt& c) {
  if (a.is_negative() || b.is_negative()) {
    throw Invalid_Argument("sub_mul: First two arguments must be >= 0");
  }

  BigInt r = a;
  r -= b;
  r *= c;
  return r;
}

/*
* Multiply-Subtract Operation
*/
BigInt mul_sub(const BigInt& a, const BigInt& b, const BigInt& c) {
  if (c.is_negative() || c.is_zero()) {
    throw Invalid_Argument("mul_sub: Third argument must be > 0");
  }

  BigInt r = a;
  r *= b;
  r -= c;
  return r;
}

}
