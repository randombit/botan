/*
* Blinding for public key operations
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/blinding.h>
#include <botan/numthry.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#else
  #include <botan/auto_rng.h>
#endif

namespace Botan {

Blinder::Blinder(const BigInt& modulus,
                 std::function<BigInt (const BigInt&)> fwd,
                 std::function<BigInt (const BigInt&)> inv) :
      m_reducer{Modular_Reducer(modulus)}, m_rng{}, m_fwd_fn(fwd), m_inv_fn(inv), m_modulus_bits{modulus.bits()}, m_e{}, m_d{}, m_counter{}
   {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   m_rng.reset(new System_RNG);
#else
   m_rng.reset(new AutoSeeded_RNG);
#endif

   const BigInt k = blinding_nonce();
   m_e = m_fwd_fn(k);
   m_d = m_inv_fn(k);
   }

BigInt Blinder::blinding_nonce() const
   {
   return BigInt(*m_rng, m_modulus_bits - 1);
   }

BigInt Blinder::blind(const BigInt& i) const
   {
   if(!m_reducer.initialized())
      throw Exception("Blinder not initialized, cannot blind");

   ++m_counter;

   if(BOTAN_BLINDING_REINIT_INTERVAL > 0 && (m_counter % BOTAN_BLINDING_REINIT_INTERVAL == 0))
      {
      const BigInt k = blinding_nonce();
      m_e = m_fwd_fn(k);
      m_d = m_inv_fn(k);
      }
   else
      {
      m_e = m_reducer.square(m_e);
      m_d = m_reducer.square(m_d);
      }

   return m_reducer.multiply(i, m_e);
   }

BigInt Blinder::unblind(const BigInt& i) const
   {
   if(!m_reducer.initialized())
      throw Exception("Blinder not initialized, cannot unblind");

   return m_reducer.multiply(i, m_d);
   }

}
