/*
* Blinding for public key operations
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/blinding.h>
#include <botan/numthry.h>

namespace Botan {

Blinder::Blinder(const BigInt& modulus,
                 RandomNumberGenerator& rng,
                 std::function<BigInt(const BigInt&)> fwd,
                 std::function<BigInt(const BigInt&)> inv) :
  m_reducer(modulus),
  m_rng(rng),
  m_fwd_fn(fwd),
  m_inv_fn(inv),
  m_modulus_bits(modulus.bits()),
  m_e{},
  m_d{},
  m_counter{} {
  const BigInt k = blinding_nonce();
  m_e = m_fwd_fn(k);
  m_d = m_inv_fn(k);
}

BigInt Blinder::blinding_nonce() const {
  return BigInt(m_rng, m_modulus_bits - 1);
}

BigInt Blinder::blind(const BigInt& i) const {
  if (!m_reducer.initialized()) {
    throw Exception("Blinder not initialized, cannot blind");
  }

  ++m_counter;

  if ((BOTAN_BLINDING_REINIT_INTERVAL > 0) && (m_counter > BOTAN_BLINDING_REINIT_INTERVAL)) {
    const BigInt k = blinding_nonce();
    m_e = m_fwd_fn(k);
    m_d = m_inv_fn(k);
    m_counter = 0;
  }
  else {
    m_e = m_reducer.square(m_e);
    m_d = m_reducer.square(m_d);
  }

  return m_reducer.multiply(i, m_e);
}

BigInt Blinder::unblind(const BigInt& i) const {
  if (!m_reducer.initialized()) {
    throw Exception("Blinder not initialized, cannot unblind");
  }

  return m_reducer.multiply(i, m_d);
}

}
