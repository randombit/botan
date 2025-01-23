/*
* Modular Reducer
* (C) 1999-2011,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/reducer.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/divide.h>
#include <botan/internal/mp_core.h>

namespace Botan {

/*
* Modular_Reducer Constructor
*/
Modular_Reducer::Modular_Reducer(const BigInt& mod) {
   if(mod < 0) {
      throw Invalid_Argument("Modular_Reducer: modulus must be positive");
   }

   // Left uninitialized if mod == 0
   m_mod_words = 0;

   if(mod > 0) {
      *this = Modular_Reducer::for_secret_modulus(mod);
   }
}

Modular_Reducer Modular_Reducer::for_secret_modulus(const BigInt& mod) {
   BOTAN_ARG_CHECK(!mod.is_zero(), "Modulus cannot be zero");
   BOTAN_ARG_CHECK(!mod.is_negative(), "Modulus cannot be negative");

   size_t mod_words = mod.sig_words();

   // Compute mu = floor(2^{2k} / m)
   const size_t mu_bits = 2 * BOTAN_MP_WORD_BITS * mod_words;
   return Modular_Reducer(mod, ct_divide_pow2k(mu_bits, mod), mod_words);
}

Modular_Reducer Modular_Reducer::for_public_modulus(const BigInt& mod) {
   BOTAN_ARG_CHECK(!mod.is_zero(), "Modulus cannot be zero");
   BOTAN_ARG_CHECK(!mod.is_negative(), "Modulus cannot be negative");

   size_t mod_words = mod.sig_words();

   // Compute mu = floor(2^{2k} / m)
   const size_t mu_bits = 2 * BOTAN_MP_WORD_BITS * mod_words;
   return Modular_Reducer(mod, BigInt::power_of_2(mu_bits) / mod, mod_words);
}

BigInt Modular_Reducer::reduce(const BigInt& x) const {
   BigInt r;
   secure_vector<word> ws;
   reduce(r, x, ws);
   return r;
}

BigInt Modular_Reducer::square(const BigInt& x) const {
   secure_vector<word> ws;
   BigInt x2 = x;
   x2.square(ws);
   BigInt r;
   reduce(r, x2, ws);
   return r;
}

namespace {

/*
* Like if(cnd) x.rev_sub(...) but in const time
*/
void cnd_rev_sub(bool cnd, BigInt& x, const word y[], size_t y_sw, secure_vector<word>& ws) {
   if(x.sign() != BigInt::Positive) {
      throw Invalid_State("BigInt::sub_rev requires this is positive");
   }

   const size_t x_sw = x.sig_words();

   const size_t max_words = std::max(x_sw, y_sw);
   ws.resize(std::max(x_sw, y_sw));
   clear_mem(ws.data(), ws.size());
   x.grow_to(max_words);

   const int32_t relative_size = bigint_sub_abs(ws.data(), x._data(), x_sw, y, y_sw);

   x.cond_flip_sign((relative_size > 0) && cnd);
   bigint_cnd_swap(static_cast<word>(cnd), x.mutable_data(), ws.data(), max_words);
}

}  // namespace

void Modular_Reducer::reduce(BigInt& t1, const BigInt& x, secure_vector<word>& ws) const {
   if(&t1 == &x) {
      throw Invalid_State("Modular_Reducer arguments cannot alias");
   }
   if(m_mod_words == 0) {
      throw Invalid_State("Modular_Reducer: Never initalized");
   }

   const size_t x_sw = x.sig_words();

   if(x_sw > 2 * m_mod_words) {
      // too big, fall back to slow boat division
      t1 = ct_modulo(x, m_modulus);
      return;
   }

   t1 = x;
   t1.set_sign(BigInt::Positive);
   t1 >>= (BOTAN_MP_WORD_BITS * (m_mod_words - 1));

   t1.mul(m_mu, ws);
   t1 >>= (BOTAN_MP_WORD_BITS * (m_mod_words + 1));

   // TODO add masked mul to avoid computing high bits
   t1.mul(m_modulus, ws);
   t1.mask_bits(BOTAN_MP_WORD_BITS * (m_mod_words + 1));

   t1.rev_sub(x._data(), std::min(x_sw, m_mod_words + 1), ws);

   /*
   * If t1 < 0 then we must add b^(k+1) where b = 2^w. To avoid a
   * side channel perform the addition unconditionally, with ws set
   * to either b^(k+1) or else 0.
   */
   const word t1_neg = t1.is_negative();

   if(ws.size() < m_mod_words + 2) {
      ws.resize(m_mod_words + 2);
   }
   clear_mem(ws.data(), ws.size());
   ws[m_mod_words + 1] = t1_neg;

   t1.add(ws.data(), m_mod_words + 2, BigInt::Positive);

   // Per HAC this step requires at most 2 subtractions
   t1.ct_reduce_below(m_modulus, ws, 2);

   cnd_rev_sub(t1.is_nonzero() && x.is_negative(), t1, m_modulus._data(), m_modulus.size(), ws);
}

}  // namespace Botan
