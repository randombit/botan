/*
* Division Algorithms
* (C) 1999-2007,2012,2018,2021,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/divide.h>

#include <botan/exceptn.h>
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

   if(x.signum() < 0 && r.signum() != 0) {
      if(y.signum() > 0) {
         q -= 1;
      } else {
         q += 1;
      }
      r = y.abs() - r;
   }
}

/*
* Computes (y3,y2,y1) = (y2,y1) * q and returns a mask which is set
* if (y3,y2,y1) > (x3,x2,x1)
*/
inline CT::Mask<word> division_check_ct(word q, word y2, word y1, word x3, word x2, word x1) {
   word y3 = 0;
   y1 = word_madd2(q, y1, &y3);
   y2 = word_madd2(q, y2, &y3);

   const auto gt3 = CT::Mask<word>::is_gt(y3, x3);
   const auto eq3 = CT::Mask<word>::is_equal(y3, x3);
   const auto gt2 = CT::Mask<word>::is_gt(y2, x2);
   const auto eq2 = CT::Mask<word>::is_equal(y2, x2);
   const auto gt1 = CT::Mask<word>::is_gt(y1, x1);

   return gt3 | (eq3 & (gt2 | (eq2 & gt1)));
}

/*
* Word-serial constant time unsigned division
*
* Sets q = |x| / |y| and r = |x| % |y|, using schoolbook long division
* (HAC Algorithm 14.20) with a quotient digit estimate from a
* precomputed reciprocal of the normalized divisor, and with the digit
* selection, corrections, and add-back all computed as masked updates.
*
* All control flow and memory indexing depends only on the word lengths
* of x and y, which are treated as public. The normalization shift
* depends on the bit length of y's top word, but is used only as a
* shift count or mask input, never for control flow or indexing.
*/
void ct_divide_impl(BigInt& q_out, BigInt& r_out, const BigInt& x, const BigInt& y) {
   constexpr size_t WB = WordInfo<word>::bits;

   const size_t x_words = x.sig_words();
   const size_t y_words = y.sig_words();
   BOTAN_ASSERT_NOMSG(y_words > 0);

   if(x_words < y_words) {
      // Here |x| < |y| so q = 0 and r = |x|
      r_out = x.abs();
      q_out = BigInt::zero();
      return;
   }

   const size_t r_words = x_words + 1;
   const size_t q_words = x_words - y_words + 1;

   // The number of leading zero bits of y, in [0,WB)
   const word s = static_cast<word>(WB) - static_cast<word>(high_bit(CT::value_barrier(y._data()[y_words - 1])));
   const auto s_mask = CT::Mask<word>::expand(s);
   const word s_comp = s_mask.if_set_return(static_cast<word>(WB) - s);

   secure_vector<word> yn(y_words);
   secure_vector<word> rw(r_words);
   secure_vector<word> qw(q_words);

   // Normalize: yn = |y| << s (which sets the top bit of yn) and rw = |x| << s;
   // shifting y stays within y_words words, shifting x adds at most one word
   word carry = 0;
   for(size_t i = 0; i != y_words; ++i) {
      const word w = y._data()[i];
      yn[i] = (w << s) | carry;
      carry = s_mask.if_set_return(w >> s_comp);
   }

   carry = 0;
   for(size_t i = 0; i != x_words; ++i) {
      const word w = x._data()[i];
      rw[i] = (w << s) | carry;
      carry = s_mask.if_set_return(w >> s_comp);
   }
   rw[x_words] = carry;

   const auto div_by_yn = divide_precomp<word>::setup(CT::value_barrier(yn[y_words - 1]));

   if(y_words == 1) {
      /*
      * 2/1 word-serial division. The initial remainder is the shift-out
      * carry, which is less than 2^s and so less than the divisor.
      */
      word r = rw[x_words];
      for(size_t i = x_words; i > 0; --i) {
         const auto [qi, ri] = div_by_yn.divmod_2to1_ct(r, rw[i - 1]);
         qw[i - 1] = qi;
         r = ri;
      }

      rw[0] = r >> s;
   } else {
      const word yn1 = yn[y_words - 1];
      const word yn2 = yn[y_words - 2];

      for(size_t i = q_words; i > 0; --i) {
         const size_t j = i - 1;  // current window is rw[j ... j + y_words]

         const word u2 = rw[j + y_words];
         const word u1 = rw[j + y_words - 1];
         const word u0 = rw[j + y_words - 2];

         /*
         * Estimate the quotient digit from the top two words of the window.
         * The window invariant gives u2 <= yn1; if u2 == yn1 the 2/1
         * division precondition does not hold, and instead the digit
         * estimate is the maximum word value.
         */
         const auto top_eq = CT::Mask<word>::is_equal(u2, yn1);
         const word q_est = div_by_yn.divmod_2to1_ct(u2, u1).first;
         word qhat = top_eq.select(WordInfo<word>::max, q_est);

         // Per HAC 14.23, this correction is required at most twice
         qhat -= division_check_ct(qhat, yn1, yn2, u2, u1, u0).if_set_return(1);
         qhat -= division_check_ct(qhat, yn1, yn2, u2, u1, u0).if_set_return(1);

         // Subtract qhat * yn from the window
         const word bw = bigint_submul(&rw[j], yn.data(), y_words, qhat);
         word borrow = 0;
         rw[j + y_words] = word_sub(u2, bw, &borrow);

         // If the digit was still one too large, the subtraction
         // underflowed; add back and decrement the digit
         const word cb = bigint_cnd_add(borrow, &rw[j], yn.data(), y_words);
         rw[j + y_words] += cb;
         qhat -= borrow;

         qw[j] = qhat;
      }

      // The remainder is in rw[0:y_words], still shifted left by s, and
      // rw[y_words] is zero
      for(size_t i = 0; i != y_words; ++i) {
         rw[i] = (rw[i] >> s) | s_mask.if_set_return(CT::value_barrier(rw[i + 1]) << s_comp);
      }
   }

   BigInt q = BigInt::_from_words(qw);
   rw.resize(y_words);
   BigInt r = BigInt::_from_words(rw);

   r_out = std::move(r);
   q_out = std::move(q);
}

}  // namespace

void ct_divide(const BigInt& x, const BigInt& y, BigInt& q_out, BigInt& r_out) {
   if(y.is_zero()) {
      throw Invalid_Argument("ct_divide: cannot divide by zero");
   }

   BigInt q;
   BigInt r;
   ct_divide_impl(q, r, x, y);

   sign_fixup(x, y, q, r);
   r_out = r;
   q_out = q;
}

BigInt ct_divide_pow2k(size_t k, const BigInt& y) {
   BOTAN_ARG_CHECK(y.signum() != 0, "Cannot divide by zero");
   BOTAN_ARG_CHECK(y.signum() >= 0, "Negative divisor not supported");
   BOTAN_ARG_CHECK(k > 1, "Invalid k");

   BigInt q;
   BigInt r;
   ct_divide_impl(q, r, BigInt::power_of_2(k), y);
   return q;
}

void ct_divide_word(const BigInt& x, word y, BigInt& q_out, word& r_out) {
   if(y == 0) {
      throw Invalid_Argument("ct_divide_word: cannot divide by zero");
   }

   const size_t x_words = x.sig_words();

   // The divisor is public here; setup is variable time in it
   const auto div_y = divide_precomp<word>::setup_vartime(y);

   secure_vector<word> qw(x_words);
   word r = 0;

   // Each step depends on r < y, which holds since r is a remainder mod y
   for(size_t i = x_words; i > 0; --i) {
      const auto [qi, ri] = div_y.divmod_2to1_vartime(r, x._data()[i - 1]);
      qw[i - 1] = qi;
      r = ri;
   }

   BigInt q = BigInt::_from_words(qw);

   if(x.signum() < 0) {
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
   BOTAN_ARG_CHECK(x.signum() >= 0, "The argument x must be non-negative");
   BOTAN_ARG_CHECK(y != 0, "Cannot divide by zero");

   // The divisor is public here; setup is variable time in it
   const auto div_y = divide_precomp<word>::setup_vartime(y);

   word r = 0;
   for(size_t i = x.sig_words(); i > 0; --i) {
      r = div_y.mod_2to1(r, x._data()[i - 1]);
   }

   return r;
}

BigInt ct_modulo(const BigInt& x, const BigInt& y) {
   if(y.signum() <= 0) {
      throw Invalid_Argument("ct_modulo requires y > 0");
   }

   BigInt q;
   BigInt r;
   ct_divide_impl(q, r, x, y);

   if(x.signum() < 0) {
      if(r.signum() != 0) {
         r = y - r;
      }
   }

   return r;
}

}  // namespace Botan
