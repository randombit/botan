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

#include <botan/internal/ct_utils.h>
#include <botan/internal/kyber_algos.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_types.h>

namespace Botan {

class Kyber_Keypair_Codec {
   public:
      virtual ~Kyber_Keypair_Codec() = default;
      virtual secure_vector<uint8_t> encode_keypair(KyberInternalKeypair keypair) const = 0;
      virtual KyberInternalKeypair decode_keypair(std::span<const uint8_t> private_key, KyberConstants mode) const = 0;
};

class Kyber_PublicKeyInternal {
   public:
      Kyber_PublicKeyInternal(KyberConstants mode, KyberSerializedPublicKey public_key);
      Kyber_PublicKeyInternal(KyberConstants mode, KyberPolyVecNTT polynomials, KyberSeedRho seed);

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
      const KyberSerializedPublicKey m_public_key_bits_raw;
      const KyberHashedPublicKey m_H_public_key_bits_raw;
      KyberPolyVecNTT m_t;
      const KyberSeedRho m_rho;
};

class Kyber_PrivateKeyInternal {
   public:
      Kyber_PrivateKeyInternal(KyberConstants mode, KyberPolyVecNTT s, KyberPrivateKeySeed seed) :
            m_mode(std::move(mode)), m_s(std::move(s)), m_seed(std::move(seed)) {}

      KyberMessage indcpa_decrypt(StrongSpan<const KyberCompressedCiphertext> ct) const;

      KyberPolyVecNTT& s() { return m_s; }

      const KyberPolyVecNTT& s() const { return m_s; }

      const KyberPrivateKeySeed& seed() const { return m_seed; }

      const KyberImplicitRejectionValue& z() const { return m_seed.z; }

      const KyberConstants& mode() const { return m_mode; }

      Kyber_PrivateKeyInternal() = delete;

      void _const_time_poison() const { CT::poison_all(m_s, m_seed.d, m_seed.z); }

      void _const_time_unpoison() const { CT::unpoison_all(m_s, m_seed.d, m_seed.z); }

   private:
      KyberConstants m_mode;
      KyberPolyVecNTT m_s;
      KyberPrivateKeySeed m_seed;
};

}  // namespace Botan

#endif
