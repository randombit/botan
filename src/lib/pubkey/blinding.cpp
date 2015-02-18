/*
* Blinding for public key operations
* (C) 1999-2010 Jack Lloyd
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

// TODO: use Montgomery

Blinder::Blinder(const BigInt& modulus,
                 std::function<BigInt (const BigInt&)> fwd_func,
                 std::function<BigInt (const BigInt&)> inv_func)
   {
   m_reducer = Modular_Reducer(modulus);

#if defined(BOTAN_HAS_SYSTEM_RNG)
   auto& rng = system_rng();
#else
   AutoSeeded_RNG rng;
#endif

   const BigInt k(rng, modulus.bits() - 1);

   m_e = fwd_func(k);
   m_d = inv_func(k);
   }

BigInt Blinder::blind(const BigInt& i) const
   {
   if(!m_reducer.initialized())
      throw std::runtime_error("Blinder not initialized, cannot blind");

   m_e = m_reducer.square(m_e);
   m_d = m_reducer.square(m_d);
   return m_reducer.multiply(i, m_e);
   }

BigInt Blinder::unblind(const BigInt& i) const
   {
   if(!m_reducer.initialized())
      throw std::runtime_error("Blinder not initialized, cannot unblind");

   return m_reducer.multiply(i, m_d);
   }

}
