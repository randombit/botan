/*
* Blinding for public key operations
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/blinding.h>

#include <botan/internal/ct_utils.h>

namespace Botan {

Blinder::Blinder(const Montgomery_Params& monty,
                 RandomNumberGenerator& rng,
                 std::function<BigInt(const BigInt&)> fwd,
                 std::function<BigInt(const BigInt&)> inv) :
      m_rng(rng),
      m_fwd_fn(std::move(fwd)),
      m_inv_fn(std::move(inv)),
      m_modulus_bits(monty.p_bits()),
      m_e(monty),
      m_d(monty),
      m_counter{} {
   const BigInt k = blinding_nonce();
   m_e = Montgomery_Int(monty, m_fwd_fn(k));
   m_d = Montgomery_Int(monty, m_inv_fn(k));
   _const_time_unpoison();
}

BigInt Blinder::blinding_nonce() const {
   return CT::driveby_poison(BigInt(m_rng, m_modulus_bits - 1));
}

namespace {

// Multiply a standard form x by a Montgomery form y, yielding x*y in standard form
BigInt mul_by_monty(const BigInt& x, const Montgomery_Int& y) {
   const auto& monty = y._params();
   BOTAN_ARG_CHECK(x.signum() >= 0 && x.is_less_than(monty.p()), "Invalid input for blinding");
   secure_vector<word> ws;
   BigInt z;
   monty.mul(z, x, y.repr(), ws);
   return z;
}

}  // namespace

BigInt Blinder::blind(const BigInt& i) const {
   ++m_counter;

   if((ReinitInterval > 0) && (m_counter > ReinitInterval)) {
      const BigInt k = blinding_nonce();
      const auto& monty = m_e._params();
      m_e = Montgomery_Int(monty, m_fwd_fn(k));
      m_d = Montgomery_Int(monty, m_inv_fn(k));
      m_counter = 0;
   } else {
      secure_vector<word> ws;
      m_e.square_this_n_times(ws, 1);
      m_d.square_this_n_times(ws, 1);
   }

   return mul_by_monty(i, m_e);
}

BigInt Blinder::unblind(const BigInt& i) const {
   return mul_by_monty(i, m_d);
}

}  // namespace Botan
