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

#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_structures.h>
#include <botan/internal/kyber_types.h>

namespace Botan {

class Kyber_PublicKeyInternal {
   public:
      Kyber_PublicKeyInternal(KyberConstants mode, PolynomialVector polynomials, KyberSeedRho seed);

      Kyber_PublicKeyInternal(const KyberConstants& mode, std::span<const uint8_t> polynomials, KyberSeedRho seed) :
            Kyber_PublicKeyInternal(mode, PolynomialVector::from_bytes(polynomials, mode), std::move(seed)) {}

      Ciphertext indcpa_encrypt(StrongSpan<const KyberMessage> m, StrongSpan<const KyberEncryptionRandomness> r) const;

      const PolynomialVector& t() const { return m_t; }

      const KyberSeedRho& rho() const { return m_rho; }

      const KyberConstants& mode() const { return m_mode; }

      const KyberSerializedPublicKey& public_key_bits_raw() const { return m_public_key_bits_raw; }

      const KyberHashedPublicKey& H_public_key_bits_raw() const { return m_H_public_key_bits_raw; }

      Kyber_PublicKeyInternal() = delete;

   private:
      const KyberConstants m_mode;
      PolynomialVector m_t;
      const KyberSeedRho m_rho;
      const KyberSerializedPublicKey m_public_key_bits_raw;
      const KyberHashedPublicKey m_H_public_key_bits_raw;
};

class Kyber_PrivateKeyInternal {
   public:
      Kyber_PrivateKeyInternal(KyberConstants mode, PolynomialVector s, KyberImplicitRejectionValue z) :
            m_mode(std::move(mode)), m_s(std::move(s)), m_z(std::move(z)) {}

      KyberMessage indcpa_decrypt(Ciphertext ct) const;

      PolynomialVector& s() { return m_s; }

      const PolynomialVector& s() const { return m_s; }

      const KyberImplicitRejectionValue& z() const { return m_z; }

      const KyberConstants& mode() const { return m_mode; }

      Kyber_PrivateKeyInternal() = delete;

   private:
      KyberConstants m_mode;
      PolynomialVector m_s;
      KyberImplicitRejectionValue m_z;
};

}  // namespace Botan

#endif
