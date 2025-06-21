/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/barrett.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/divide.h>
#include <botan/internal/mp_core.h>

namespace Botan {

Barrett_Reduction::Barrett_Reduction(const BigInt& m, BigInt mu, size_t mw) :
      m_modulus(m), m_mu(std::move(mu)), m_mod_words(mw), m_modulus_bits(m.bits()) {
   // Give some extra space for Karatsuba
   m_modulus.grow_to(m_mod_words + 8);
   m_mu.grow_to(m_mod_words + 8);
}

Barrett_Reduction Barrett_Reduction::for_secret_modulus(const BigInt& mod) {
   BOTAN_ARG_CHECK(!mod.is_zero(), "Modulus cannot be zero");
   BOTAN_ARG_CHECK(!mod.is_negative(), "Modulus cannot be negative");

   size_t mod_words = mod.sig_words();

   // Compute mu = floor(2^{2k} / m)
   const size_t mu_bits = 2 * WordInfo<word>::bits * mod_words;
   return Barrett_Reduction(mod, ct_divide_pow2k(mu_bits, mod), mod_words);
}

Barrett_Reduction Barrett_Reduction::for_public_modulus(const BigInt& mod) {
   BOTAN_ARG_CHECK(!mod.is_zero(), "Modulus cannot be zero");
   BOTAN_ARG_CHECK(!mod.is_negative(), "Modulus cannot be negative");

   size_t mod_words = mod.sig_words();

   // Compute mu = floor(2^{2k} / m)
   const size_t mu_bits = 2 * WordInfo<word>::bits * mod_words;
   return Barrett_Reduction(mod, BigInt::power_of_2(mu_bits) / mod, mod_words);
}

namespace {

/*
* Barrett Reduction
*
* This function assumes that the significant size of x_words (ie the number of
* words with a value other than zero) is at most 2 * mod_words. In any case, any
* larger value cannot be reduced using Barrett reduction; callers should have
* already checked for this.
*/
BigInt barrett_reduce(
   size_t mod_words, const BigInt& modulus, const BigInt& mu, std::span<const word> x_words, secure_vector<word>& ws) {
   BOTAN_ASSERT_NOMSG(modulus.sig_words() == mod_words);
   // Normally mod_words + 1 but can be + 2 if the modulus is a power of 2
   const size_t mu_words = mu.sig_words();
   BOTAN_ASSERT_NOMSG(mu_words <= mod_words + 2);

   if(ws.size() < 2 * (mod_words + 2)) {
      ws.resize(2 * (mod_words + 2));
   }

   CT::poison(x_words);

   /*
   * Following the notation of Handbook of Applied Cryptography
   * Algorithm 14.42 "Barrett modular reduction", page 604
   * <https://cacr.uwaterloo.ca/hac/about/chap14.pdf>
   *
   * Using `mu` for μ in the code
   */

   // Compute q1 = floor(x / 2^(k - 1)) which is equivalent to ignoring the low (k-1) words

   // 2 * mod_words + 1 is sufficient, extra is to enable Karatsuba
   secure_vector<word> r(2 * mu_words + 2);

   const size_t usable_words = std::min(x_words.size(), 2 * mod_words);

   if(usable_words >= mod_words - 1) {
      copy_mem(r.data(), x_words.data() + (mod_words - 1), usable_words - (mod_words - 1));
   }

   // Now compute q2 = q1 * μ

   // We allocate more size than required since this allows Karatsuba more often;
   // just `mu_words + (mod_words + 1)` is sufficient
   const size_t q2_size = 2 * mu_words + 2;

   secure_vector<word> q2(q2_size);

   bigint_mul(
      q2.data(), q2.size(), r.data(), r.size(), mod_words + 1, mu._data(), mu.size(), mu_words, ws.data(), ws.size());

   // Compute r2 = (floor(q2 / b^(k+1)) * m) mod 2^(k+1)
   // The division/floor is again effected by just ignoring the low k + 1 words
   bigint_mul(r.data(),
              r.size(),
              &q2[mod_words + 1],  // ignoring the low mod_words + 1 words of the first product
              q2.size() - (mod_words + 1),
              mod_words + 1,
              modulus._data(),
              modulus.size(),
              mod_words,
              ws.data(),
              ws.size());

   // Clear the high words of the product, equivalent to computing mod 2^(k+1)
   // TODO add masked mul to avoid computing high bits at all
   clear_mem(std::span{r}.subspan(mod_words + 1));

   // Compute r = r1 - r2

   clear_mem(ws.data(), ws.size());

   const int32_t relative_size =
      bigint_sub_abs(ws.data(), r.data(), mod_words + 1, x_words.data(), std::min(x_words.size(), mod_words + 1));

   r.swap(ws);

   /*
   If r is negative then we have to set r to r + 2^(k+1)

   However for r negative computing this sum is equivalent to computing 2^(k+1) - r
   */
   word borrow = 0;
   for(size_t i = 0; i != mod_words + 1; ++i) {
      ws[i] = word_sub(static_cast<word>(0), r[i], &borrow);
   }
   ws[mod_words + 1] = word_sub(static_cast<word>(1), r[mod_words + 1], &borrow);

   // If relative_size > 0 then assign r to 2^(k+1) - r
   CT::Mask<word>::is_equal(static_cast<word>(relative_size), 1).select_n(r.data(), ws.data(), r.data(), mod_words + 2);

   /*
   * Per HAC Note 14.44 (ii) "step 4 is repeated at most twice since 0 ≤ r < 3m"
   */
   const size_t bound = 2;

   BOTAN_ASSERT_NOMSG(r.size() >= mod_words + 1);
   for(size_t i = 0; i != bound; ++i) {
      borrow = bigint_sub3(ws.data(), r.data(), mod_words + 1, modulus._data(), mod_words);
      CT::Mask<word>::is_zero(borrow).select_n(r.data(), ws.data(), r.data(), mod_words + 1);
   }

   CT::unpoison(q2);
   CT::unpoison(r);
   CT::unpoison(ws);
   CT::unpoison(x_words);

   return BigInt::_from_words(r);
}

CT::Choice acceptable_barrett_input(const BigInt& x, const BigInt& modulus) {
   auto x_is_positive = CT::Choice::from_int(static_cast<uint32_t>(x.is_positive()));
   auto x_lt_mod = bigint_ct_is_lt(x._data(), x.size(), modulus._data(), modulus.sig_words()).as_choice();
   return x_is_positive && x_lt_mod;
}

}  // namespace

BigInt Barrett_Reduction::multiply(const BigInt& x, const BigInt& y) const {
   BOTAN_ARG_CHECK(acceptable_barrett_input(x, m_modulus).as_bool(), "Invalid x param for Barrett multiply");
   BOTAN_ARG_CHECK(acceptable_barrett_input(y, m_modulus).as_bool(), "Invalid y param for Barrett multiply");

   secure_vector<word> ws(2 * (m_mod_words + 2));
   secure_vector<word> xy(2 * m_mod_words);

   bigint_mul(xy.data(),
              xy.size(),
              x._data(),
              x.size(),
              std::min(x.size(), m_mod_words),
              y._data(),
              y.size(),
              std::min(y.size(), m_mod_words),
              ws.data(),
              ws.size());

   return barrett_reduce(m_mod_words, m_modulus, m_mu, xy, ws);
}

BigInt Barrett_Reduction::square(const BigInt& x) const {
   BOTAN_ARG_CHECK(acceptable_barrett_input(x, m_modulus).as_bool(), "Invalid x param for Barrett square");

   secure_vector<word> ws(2 * (m_mod_words + 2));
   secure_vector<word> x2(2 * m_mod_words);

   bigint_sqr(x2.data(), x2.size(), x._data(), x.size(), std::min(x.size(), m_mod_words), ws.data(), ws.size());

   return barrett_reduce(m_mod_words, m_modulus, m_mu, x2, ws);
}

BigInt Barrett_Reduction::reduce(const BigInt& x) const {
   BOTAN_ARG_CHECK(x.is_positive(), "Argument must be positive");

   const size_t x_sw = x.sig_words();
   BOTAN_ARG_CHECK(x_sw <= 2 * m_mod_words, "Argument is too large for Barrett reduction");

   secure_vector<word> ws;
   return barrett_reduce(m_mod_words, m_modulus, m_mu, x._as_span(), ws);
}

}  // namespace Botan
