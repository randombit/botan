/*
 * Crystals Kyber Internal Key Types
 *
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Fabian Albert, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/kyber_keys.h>

#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/stl_util.h>

namespace Botan {

Kyber_PublicKeyInternal::Kyber_PublicKeyInternal(KyberConstants mode, KyberPolyVecNTT t, KyberSeedRho rho) :
      m_mode(std::move(mode)),
      m_t(std::move(t)),
      m_rho(std::move(rho)),
      m_public_key_bits_raw(concat(Kyber_Algos::encode_polynomial_vector<std::vector<uint8_t>>(m_t, m_mode), m_rho)),
      m_H_public_key_bits_raw(m_mode.symmetric_primitives().H(m_public_key_bits_raw)) {}

/**
 * NIST FIPS 203 IPD, Algorithm 13 (K-PKE.Encrypt)
 */
void Kyber_PublicKeyInternal::indcpa_encrypt(StrongSpan<KyberCompressedCiphertext> out_ct,
                                             StrongSpan<const KyberMessage> m,
                                             StrongSpan<const KyberEncryptionRandomness> r,
                                             const KyberPolyMat& At) const {
   Kyber_Algos::PolynomialSampler ps(r, m_mode);

   const auto rv = ntt(ps.sample_polynomial_vector_cbd_eta1());
   const auto e1 = ps.sample_polynomial_vector_cbd_eta2();
   const auto e2 = ps.sample_polynomial_cbd_eta2();

   auto u = inverse_ntt(At * rv);
   u += e1;
   u.reduce();

   const auto mu = Kyber_Algos::polynomial_from_message(m);
   auto v = inverse_ntt(m_t * rv);
   v += e2;
   v += mu;
   v.reduce();

   Kyber_Algos::compress_ciphertext(out_ct, u, v, m_mode);
}

/**
 * NIST FIPS 203 IPD, Algorithm 14 (K-PKE.Decrypt)
 */
KyberMessage Kyber_PrivateKeyInternal::indcpa_decrypt(StrongSpan<const KyberCompressedCiphertext> ct) const {
   auto [u, v] = Kyber_Algos::decompress_ciphertext(ct, m_mode);
   v -= inverse_ntt(m_s * ntt(std::move(u)));
   v.reduce();
   return Kyber_Algos::polynomial_to_message(v);
}

}  // namespace Botan
