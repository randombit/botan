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

Kyber_PublicKeyInternal::Kyber_PublicKeyInternal(KyberConstants mode, PolynomialVector polynomials, KyberSeedRho seed) :
      m_mode(std::move(mode)),
      m_polynomials(std::move(polynomials)),
      m_seed(std::move(seed)),
      m_public_key_bits_raw(concat(m_polynomials.to_bytes(), m_seed)),
      m_H_public_key_bits_raw(m_mode.symmetric_primitives().H(m_public_key_bits_raw)) {}

Ciphertext Kyber_PublicKeyInternal::indcpa_encrypt(StrongSpan<const KyberMessage> m,
                                                   StrongSpan<const KyberEncryptionRandomness> r) const {
   auto sp = PolynomialVector::getnoise_eta1(r, 0, m_mode);
   auto ep = PolynomialVector::getnoise_eta2(r, m_mode.k(), m_mode);
   auto epp = Polynomial::getnoise_eta2(r, 2 * m_mode.k(), m_mode);

   auto k = Polynomial::from_message(m);

   sp.ntt();

   auto at = PolynomialMatrix::generate(m_seed, true, m_mode);
   auto bp = at.pointwise_acc_montgomery(sp);
   auto v = PolynomialVector::pointwise_acc_montgomery(m_polynomials, sp);

   bp.invntt_tomont();
   v.invntt_tomont();

   bp += ep;
   v += epp;
   v += k;
   bp.reduce();
   v.reduce();

   return Ciphertext(std::move(bp), v, m_mode);
}

KyberMessage Kyber_PrivateKeyInternal::indcpa_decrypt(Ciphertext ct) const {
   ct.b().ntt();
   auto mp = PolynomialVector::pointwise_acc_montgomery(m_polynomials, ct.b());
   mp.invntt_tomont();

   mp -= ct.v();
   mp.reduce();
   return mp.to_message();
}

}  // namespace Botan
