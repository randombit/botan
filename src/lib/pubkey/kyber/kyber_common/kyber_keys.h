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

#ifndef BOTAN_KYBER_INTERNAL_KEYS_H_
#define BOTAN_KYBER_INTERNAL_KEYS_H_

#include <botan/internal/kyber_algos.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_types.h>

namespace Botan {

class Kyber_PublicKeyInternal {
   public:
      Kyber_PublicKeyInternal(KyberConstants mode, KyberPolyVecNTT polynomials, KyberSeedRho seed);

      Kyber_PublicKeyInternal(const KyberConstants& mode, std::span<const uint8_t> polynomials, KyberSeedRho seed) :
            Kyber_PublicKeyInternal(mode, Kyber_Algos::decode_polynomial_vector(polynomials, mode), std::move(seed)) {}

      Kyber_PublicKeyInternal(const Kyber_PublicKeyInternal& other) :
            m_mode(other.m_mode),
            m_t(other.m_t.clone()),
            m_rho(other.m_rho),
            m_public_key_bits_raw(other.m_public_key_bits_raw),
            m_H_public_key_bits_raw(other.m_H_public_key_bits_raw) {}

      void indcpa_encrypt(StrongSpan<KyberCompressedCiphertext> out_ct,
                          StrongSpan<const KyberMessage> m,
                          StrongSpan<const KyberEncryptionRandomness> r,
                          const KyberPolyMat& At) const;

      KyberCompressedCiphertext indcpa_encrypt(const KyberMessage& m,
                                               const KyberEncryptionRandomness& r,
                                               const KyberPolyMat& At) const {
         KyberCompressedCiphertext ct(m_mode.ciphertext_bytes());
         indcpa_encrypt(ct, m, r, At);
         return ct;
      }

      const KyberPolyVecNTT& t() const { return m_t; }

      const KyberSeedRho& rho() const { return m_rho; }

      const KyberConstants& mode() const { return m_mode; }

      const KyberSerializedPublicKey& public_key_bits_raw() const { return m_public_key_bits_raw; }

      const KyberHashedPublicKey& H_public_key_bits_raw() const { return m_H_public_key_bits_raw; }

      Kyber_PublicKeyInternal() = delete;

   private:
      const KyberConstants m_mode;
      KyberPolyVecNTT m_t;
      const KyberSeedRho m_rho;
      const KyberSerializedPublicKey m_public_key_bits_raw;
      const KyberHashedPublicKey m_H_public_key_bits_raw;
};

class Kyber_PrivateKeyInternal {
   public:
      Kyber_PrivateKeyInternal(KyberConstants mode, KyberPolyVecNTT s, KyberImplicitRejectionValue z) :
            m_mode(std::move(mode)), m_s(std::move(s)), m_z(std::move(z)) {}

      KyberMessage indcpa_decrypt(StrongSpan<const KyberCompressedCiphertext> ct) const;

      KyberPolyVecNTT& s() { return m_s; }

      const KyberPolyVecNTT& s() const { return m_s; }

      const KyberImplicitRejectionValue& z() const { return m_z; }

      const KyberConstants& mode() const { return m_mode; }

      Kyber_PrivateKeyInternal() = delete;

   private:
      KyberConstants m_mode;
      KyberPolyVecNTT m_s;
      KyberImplicitRejectionValue m_z;
};

}  // namespace Botan

#endif
