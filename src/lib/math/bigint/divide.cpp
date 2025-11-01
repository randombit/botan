/*
* Division Algorithms
* (C) 1999-2007,2012,2018,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/divide.h>

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

inline bool division_check_vartime(word q, word y2, word y1, word x3, word x2, word x1) {
   /*
   Compute (y3,y2,y1) = (y2,y1) * q
   and return true if (y3,y2,y1) > (x3,x2,x1)
   */

   word y3 = 0;
   y1 = word_madd2(q, y1, &y3);
   y2 = word_madd2(q, y2, &y3);

   if(x3 != y3) {
      return (y3 > x3);
   }
   if(x2 != y2) {
      return (y2 > x2);
   }
   return (y1 > x1);
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

      r <<= 1;
      r.conditionally_set_bit(0, x_b);

      const bool r_gte_y = bigint_sub3(t.mutable_data(), r._data(), r.size(), y._data(), y_words) == 0;

      q.conditionally_set_bit(b, r_gte_y);
      r.ct_cond_swap(r_gte_y, t);
   }

   sign_fixup(x, y, q, r);
   r_out = r;
   q_out = q;
}

BigInt ct_divide_pow2k(size_t k, const BigInt& y) {
   BOTAN_ARG_CHECK(!y.is_zero(), "Cannot divide by zero");
   BOTAN_ARG_CHECK(!y.is_negative(), "Negative divisor not supported");
   BOTAN_ARG_CHECK(k > 1, "Invalid k");

   const size_t x_bits = k + 1;
   const size_t y_bits = y.bits();

   if(x_bits < y_bits) {
      return BigInt::zero();
   }

   BOTAN_ASSERT_NOMSG(y_bits >= 1);
   const size_t x_words = (x_bits + WordInfo<word>::bits - 1) / WordInfo<word>::bits;
   const size_t y_words = y.sig_words();

   BigInt q = BigInt::with_capacity(x_words);
   BigInt r = BigInt::with_capacity(y_words + 1);
   BigInt t = BigInt::with_capacity(y_words + 1);  // a temporary

   r.set_bit(y_bits - 1);
   for(size_t i = y_bits - 1; i != x_bits; ++i) {
      const size_t b = x_bits - 1 - i;

      if(i >= y_bits) {
         bigint_shl1(r.mutable_data(), r.size(), r.size(), 1);
      }

      const bool r_gte_y = bigint_sub3(t.mutable_data(), r._data(), r.size(), y._data(), y_words) == 0;

      q.conditionally_set_bit(b, r_gte_y);

      bigint_cnd_swap(static_cast<word>(r_gte_y), r.mutable_data(), t.mutable_data(), y_words + 1);
   }

   // No need for sign fixup

   return q;
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

      r <<= 1;
      r += static_cast<word>(x_b);

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

BigInt ct_divide_word(const BigInt& x, word y) {
   BigInt q;
   word r = 0;
   ct_divide_word(x, y, q, r);
   BOTAN_UNUSED(r);
   return q;
}

word ct_mod_word(const BigInt& x, word y) {
   BOTAN_ARG_CHECK(x.is_positive(), "The argument x must be positive");
   BOTAN_ARG_CHECK(y != 0, "Cannot divide by zero");

   const size_t x_bits = x.bits();

   word r = 0;

   for(size_t i = 0; i != x_bits; ++i) {
      const size_t b = x_bits - 1 - i;
      const bool x_b = x.get_bit(b);

      const auto r_carry = CT::Mask<word>::expand_top_bit(r);

      r <<= 1;
      r += static_cast<word>(x_b);

      const auto r_gte_y = CT::Mask<word>::is_gte(r, y) | r_carry;
      r = r_gte_y.select(r - y, r);
   }

   return r;
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

      r <<= 1;
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

BigInt vartime_divide_pow2k(size_t k, const BigInt& y_arg) {
   constexpr size_t WB = WordInfo<word>::bits;

   BOTAN_ARG_CHECK(!y_arg.is_zero(), "Cannot divide by zero");
   BOTAN_ARG_CHECK(!y_arg.is_negative(), "Negative divisor not supported");
   BOTAN_ARG_CHECK(k > 1, "Invalid k");

   BigInt y = y_arg;

   const size_t y_words = y.sig_words();

   BOTAN_ASSERT_NOMSG(y_words > 0);

   // Calculate shifts needed to normalize y with high bit set
   const size_t shifts = y.top_bits_free();

   if(shifts > 0) {
      y <<= shifts;
   }

   BigInt r;
   r.set_bit(k + shifts);  // (2^k) << shifts

   // we know y has not changed size, since we only shifted up to set high bit
   const size_t t = y_words - 1;
   const size_t n = std::max(y_words, r.sig_words()) - 1;

   BOTAN_ASSERT_NOMSG(n >= t);

   BigInt q = BigInt::zero();
   q.grow_to(n - t + 1);

   word* q_words = q.mutable_data();

   BigInt shifted_y = y << (WB * (n - t));

   // Set q_{n-t} to number of times r > shifted_y
   secure_vector<word> ws;
   q_words[n - t] = r.reduce_below(shifted_y, ws);

   const word y_t0 = y.word_at(t);
   const word y_t1 = y.word_at(t - 1);
   BOTAN_DEBUG_ASSERT((y_t0 >> (WB - 1)) == 1);

   divide_precomp div_y_t0(y_t0);

   for(size_t i = n; i != t; --i) {
      const word x_i0 = r.word_at(i);
      const word x_i1 = r.word_at(i - 1);
      const word x_i2 = r.word_at(i - 2);

      word qit = (x_i0 == y_t0) ? WordInfo<word>::max : div_y_t0.vartime_div_2to1(x_i0, x_i1);

      // Per HAC 14.23, this operation is required at most twice
      for(size_t j = 0; j != 2; ++j) {
         if(division_check_vartime(qit, y_t0, y_t1, x_i0, x_i1, x_i2)) {
            BOTAN_ASSERT_NOMSG(qit > 0);
            qit--;
         } else {
            break;
         }
      }

      shifted_y >>= WB;
      // Now shifted_y == y << (WB * (i-t-1))

      /*
      * Special case qit == 0 and qit == 1 which occurs relatively often here due to a
      * combination of the fixed 2^k and in many cases the typical structure of
      * public moduli (as this function is called by Barrett_Reduction::for_public_modulus).
      *
      * Over the test suite, about 5% of loop iterations have qit == 1 and 10% have qit == 0
      */

      if(qit != 0) {
         if(qit == 1) {
            r -= shifted_y;
         } else {
            r -= qit * shifted_y;
         }

         if(r.is_negative()) {
            BOTAN_ASSERT_NOMSG(qit > 0);
            qit--;
            r += shifted_y;
            BOTAN_ASSERT_NOMSG(r.is_positive());
         }
      }

      q_words[i - t - 1] = qit;
   }

   return q;
}

/*
* Solve x = q * y + r
*
* See Handbook of Applied Cryptography algorithm 14.20
*/
void vartime_divide(const BigInt& x, const BigInt& y_arg, BigInt& q_out, BigInt& r_out) {
   constexpr size_t WB = WordInfo<word>::bits;

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

   if(shifts > 0) {
      y <<= shifts;
      r <<= shifts;
   }

   // we know y has not changed size, since we only shifted up to set high bit
   const size_t t = y_words - 1;
   const size_t n = std::max(y_words, r.sig_words()) - 1;  // r may have changed size however

   BOTAN_ASSERT_NOMSG(n >= t);

   q.grow_to(n - t + 1);

   word* q_words = q.mutable_data();

   BigInt shifted_y = y << (WB * (n - t));

   // Set q_{n-t} to number of times r > shifted_y
   q_words[n - t] = r.reduce_below(shifted_y, ws);

   const word y_t0 = y.word_at(t);
   const word y_t1 = y.word_at(t - 1);
   BOTAN_DEBUG_ASSERT((y_t0 >> (WB - 1)) == 1);

   divide_precomp div_y_t0(y_t0);

   for(size_t i = n; i != t; --i) {
      const word x_i0 = r.word_at(i);
      const word x_i1 = r.word_at(i - 1);
      const word x_i2 = r.word_at(i - 2);

      word qit = (x_i0 == y_t0) ? WordInfo<word>::max : div_y_t0.vartime_div_2to1(x_i0, x_i1);

      // Per HAC 14.23, this operation is required at most twice
      for(size_t j = 0; j != 2; ++j) {
         if(division_check_vartime(qit, y_t0, y_t1, x_i0, x_i1, x_i2)) {
            BOTAN_ASSERT_NOMSG(qit > 0);
            qit--;
         } else {
            break;
         }
      }

      shifted_y >>= WB;
      // Now shifted_y == y << (WB * (i-t-1))

      if(qit != 0) {
         r -= qit * shifted_y;
         if(r.is_negative()) {
            BOTAN_ASSERT_NOMSG(qit > 0);
            qit--;
            r += shifted_y;
            BOTAN_ASSERT_NOMSG(r.is_positive());
         }
      }

      q_words[i - t - 1] = qit;
   }

   if(shifts > 0) {
      r >>= shifts;
   }

   sign_fixup(x, y_arg, q, r);

   r_out = r;
   q_out = q;
}

}  // namespace Botan
