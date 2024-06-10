/*
* Division Algorithms
* (C) 1999-2007,2012,2018,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/divide.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>

namespace Botan {

namespace {

/*
* Handle signed operands, if necessary
*/
void sign_fixup(const BigInt& x, const BigInt& y, BigInt& q, BigInt& r) {
   q.cond_flip_sign(x.sign() != y.sign());

   if(x.is_negative() && r.is_nonzero()) {
      q -= 1;
      r = y.abs() - r;
   }
}

inline bool division_check(word q, word y2, word y1, word x3, word x2, word x1) {
   /*
   Compute (y3,y2,y1) = (y2,y1) * q
   and return true if (y3,y2,y1) > (x3,x2,x1)
   */

   word y3 = 0;
   y1 = word_madd2(q, y1, &y3);
   y2 = word_madd2(q, y2, &y3);

   const word x[3] = {x1, x2, x3};
   const word y[3] = {y1, y2, y3};

   return bigint_ct_is_lt(x, 3, y, 3).as_bool();
}

}  // namespace

void ct_divide(const BigInt& x, const BigInt& y, BigInt& q_out, BigInt& r_out) {
   if(y.is_zero()) {
      throw Invalid_Argument("ct_divide: cannot divide by zero");
   }

   const size_t x_words = x.sig_words();
   const size_t y_words = y.sig_words();

   const size_t x_bits = x.bits();

   BigInt q = BigInt::with_capacity(x_words);
   BigInt r = BigInt::with_capacity(y_words);
   BigInt t = BigInt::with_capacity(y_words);  // a temporary

   for(size_t i = 0; i != x_bits; ++i) {
      const size_t b = x_bits - 1 - i;
      const bool x_b = x.get_bit(b);

      r *= 2;
      r.conditionally_set_bit(0, x_b);

      const bool r_gte_y = bigint_sub3(t.mutable_data(), r._data(), r.size(), y._data(), y_words) == 0;

      q.conditionally_set_bit(b, r_gte_y);
      r.ct_cond_swap(r_gte_y, t);
   }

   sign_fixup(x, y, q, r);
   r_out = r;
   q_out = q;
}

void ct_divide_word(const BigInt& x, word y, BigInt& q_out, word& r_out) {
   if(y == 0) {
      throw Invalid_Argument("ct_divide_word: cannot divide by zero");
   }

   const size_t x_words = x.sig_words();
   const size_t x_bits = x.bits();

   BigInt q = BigInt::with_capacity(x_words);
   word r = 0;

   for(size_t i = 0; i != x_bits; ++i) {
      const size_t b = x_bits - 1 - i;
      const bool x_b = x.get_bit(b);

      const auto r_carry = CT::Mask<word>::expand_top_bit(r);

      r *= 2;
      r += x_b;

      const auto r_gte_y = CT::Mask<word>::is_gte(r, y) | r_carry;
      q.conditionally_set_bit(b, r_gte_y.as_bool());
      r = r_gte_y.select(r - y, r);
   }

   if(x.is_negative()) {
      q.flip_sign();
      if(r != 0) {
         --q;
         r = y - r;
      }
   }

   r_out = r;
   q_out = q;
}

BigInt ct_modulo(const BigInt& x, const BigInt& y) {
   if(y.is_negative() || y.is_zero()) {
      throw Invalid_Argument("ct_modulo requires y > 0");
   }

   const size_t y_words = y.sig_words();

   const size_t x_bits = x.bits();

   BigInt r = BigInt::with_capacity(y_words);
   BigInt t = BigInt::with_capacity(y_words);

   for(size_t i = 0; i != x_bits; ++i) {
      const size_t b = x_bits - 1 - i;
      const bool x_b = x.get_bit(b);

      r *= 2;
      r.conditionally_set_bit(0, x_b);

      const bool r_gte_y = bigint_sub3(t.mutable_data(), r._data(), r.size(), y._data(), y_words) == 0;

      r.ct_cond_swap(r_gte_y, t);
   }

   if(x.is_negative()) {
      if(r.is_nonzero()) {
         r = y - r;
      }
   }

   return r;
}

/*
* Solve x = q * y + r
*
* See Handbook of Applied Cryptography section 14.2.5
*/
void vartime_divide(const BigInt& x, const BigInt& y_arg, BigInt& q_out, BigInt& r_out) {
   if(y_arg.is_zero()) {
      throw Invalid_Argument("vartime_divide: cannot divide by zero");
   }

   const size_t y_words = y_arg.sig_words();

   BOTAN_ASSERT_NOMSG(y_words > 0);

   BigInt y = y_arg;

   BigInt r = x;
   BigInt q = BigInt::zero();
   secure_vector<word> ws;

   r.set_sign(BigInt::Positive);
   y.set_sign(BigInt::Positive);

   // Calculate shifts needed to normalize y with high bit set
   const size_t shifts = y.top_bits_free();

   y <<= shifts;
   r <<= shifts;

   // we know y has not changed size, since we only shifted up to set high bit
   const size_t t = y_words - 1;
   const size_t n = std::max(y_words, r.sig_words()) - 1;  // r may have changed size however

   BOTAN_ASSERT_NOMSG(n >= t);

   q.grow_to(n - t + 1);

   word* q_words = q.mutable_data();

   BigInt shifted_y = y << (BOTAN_MP_WORD_BITS * (n - t));

   // Set q_{n-t} to number of times r > shifted_y
   q_words[n - t] = r.reduce_below(shifted_y, ws);

   const word y_t0 = y.word_at(t);
   const word y_t1 = y.word_at(t - 1);
   BOTAN_DEBUG_ASSERT((y_t0 >> (BOTAN_MP_WORD_BITS - 1)) == 1);

   for(size_t j = n; j != t; --j) {
      const word x_j0 = r.word_at(j);
      const word x_j1 = r.word_at(j - 1);
      const word x_j2 = r.word_at(j - 2);

      word qjt = bigint_divop_vartime(x_j0, x_j1, y_t0);

      qjt = CT::Mask<word>::is_equal(x_j0, y_t0).select(WordInfo<word>::max, qjt);

      // Per HAC 14.23, this operation is required at most twice
      qjt -= division_check(qjt, y_t0, y_t1, x_j0, x_j1, x_j2);
      qjt -= division_check(qjt, y_t0, y_t1, x_j0, x_j1, x_j2);
      BOTAN_DEBUG_ASSERT(division_check(qjt, y_t0, y_t1, x_j0, x_j1, x_j2) == false);

      shifted_y >>= BOTAN_MP_WORD_BITS;
      // Now shifted_y == y << (BOTAN_MP_WORD_BITS * (j-t-1))

      // TODO this sequence could be better
      r -= qjt * shifted_y;
      qjt -= r.is_negative();
      r += static_cast<word>(r.is_negative()) * shifted_y;

      q_words[j - t - 1] = qjt;
   }

   r >>= shifts;

   sign_fixup(x, y_arg, q, r);

   r_out = r;
   q_out = q;
}

}  // namespace Botan
