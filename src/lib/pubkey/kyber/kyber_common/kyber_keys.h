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

      const PolynomialVector& polynomials() const { return m_polynomials; }

      const KyberSeedRho& seed() const { return m_seed; }

      const KyberConstants& mode() const { return m_mode; }

      const KyberSerializedPublicKey& public_key_bits_raw() const { return m_public_key_bits_raw; }

      const KyberHashedPublicKey& H_public_key_bits_raw() const { return m_H_public_key_bits_raw; }

      Kyber_PublicKeyInternal() = delete;

   private:
      const KyberConstants m_mode;
      PolynomialVector m_polynomials;
      const KyberSeedRho m_seed;
      const KyberSerializedPublicKey m_public_key_bits_raw;
      const KyberHashedPublicKey m_H_public_key_bits_raw;
};

class Kyber_PrivateKeyInternal {
   public:
      Kyber_PrivateKeyInternal(KyberConstants mode, PolynomialVector polynomials, KyberImplicitRejectionValue z) :
            m_mode(std::move(mode)), m_polynomials(std::move(polynomials)), m_z(std::move(z)) {}

      KyberMessage indcpa_decrypt(Ciphertext ct) const;

      PolynomialVector& polynomials() { return m_polynomials; }

      const PolynomialVector& polynomials() const { return m_polynomials; }

      const KyberImplicitRejectionValue& z() const { return m_z; }

      const KyberConstants& mode() const { return m_mode; }

      Kyber_PrivateKeyInternal() = delete;

   private:
      KyberConstants m_mode;
      PolynomialVector m_polynomials;
      KyberImplicitRejectionValue m_z;
};

}  // namespace Botan

#endif
