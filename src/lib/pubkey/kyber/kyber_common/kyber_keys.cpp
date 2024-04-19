/*
 * Crystals Kyber Internal Key Types
 *
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/kyber_keys.h>

#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/stl_util.h>

namespace Botan {

Kyber_PublicKeyInternal::Kyber_PublicKeyInternal(KyberConstants mode, PolynomialVector t, KyberSeedRho rho) :
      m_mode(std::move(mode)),
      m_t(std::move(t)),
      m_rho(std::move(rho)),
      m_public_key_bits_raw(concat(m_t.to_bytes(), m_rho)),
      m_H_public_key_bits_raw(m_mode.symmetric_primitives().H(m_public_key_bits_raw)) {}

/**
 * NIST FIPS 203 IPD, Algorithm 13 (K-PKE.Encrypt)
 */
Ciphertext Kyber_PublicKeyInternal::indcpa_encrypt(StrongSpan<const KyberMessage> m,
                                                   StrongSpan<const KyberEncryptionRandomness> r) const {
   auto at = PolynomialMatrix::generate(m_rho, true /* transposed */, m_mode);

   auto rv = PolynomialVector::getnoise_eta1(r, 0, m_mode);
   auto e1 = PolynomialVector::getnoise_eta2(r, m_mode.k(), m_mode);
   auto e2 = Polynomial::getnoise_eta2(r, 2 * m_mode.k(), m_mode);

   rv.ntt();

   auto u = at.pointwise_acc_montgomery(rv);
   u.invntt_tomont();
   u += e1;
   u.reduce();

   auto mu = Polynomial::from_message(m);
   auto v = PolynomialVector::pointwise_acc_montgomery(m_t, rv);
   v.invntt_tomont();
   v += e2;
   v += mu;
   v.reduce();

   return Ciphertext(std::move(u), v, m_mode);
}

/**
 * NIST FIPS 203 IPD, Algorithm 14 (K-PKE.Decrypt)
 */
KyberMessage Kyber_PrivateKeyInternal::indcpa_decrypt(Ciphertext ct) const {
   auto& u = ct.b();
   const auto& v = ct.v();

   u.ntt();
   auto w = PolynomialVector::pointwise_acc_montgomery(m_s, u);
   w.invntt_tomont();

   w -= v;
   w.reduce();
   return w.to_message();
}

}  // namespace Botan
