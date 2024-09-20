/*
 * Crystals Dilithium Internal Key Types
 *
 * (C) 2021-2024 Jack Lloyd
 *     2021-2023 Jack Lloyd
 *     2021-2022 Manuel Glaser - Rohde & Schwarz Cybersecurity
 *     2021-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 *     2024      René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_DILITHIUM_INTERNAL_KEYS_H_
#define BOTAN_DILITHIUM_INTERNAL_KEYS_H_

#include <botan/internal/dilithium_types.h>

#include <botan/internal/dilithium_algos.h>
#include <botan/internal/dilithium_symmetric_primitives.h>

namespace Botan {

class Dilithium_Keypair_Codec {
   public:
      static std::unique_ptr<Dilithium_Keypair_Codec> create(DilithiumMode mode);

      virtual ~Dilithium_Keypair_Codec() = default;
      virtual secure_vector<uint8_t> encode_keypair(DilithiumInternalKeypair keypair) const = 0;
      virtual DilithiumInternalKeypair decode_keypair(std::span<const uint8_t> private_key,
                                                      DilithiumConstants mode) const = 0;
};

class Dilithium_PublicKeyInternal {
   public:
      static std::shared_ptr<Dilithium_PublicKeyInternal> decode(
         DilithiumConstants mode, StrongSpan<const DilithiumSerializedPublicKey> raw_pk) {
         auto [rho, t1] = Dilithium_Algos::decode_public_key(raw_pk, mode);
         return std::make_shared<Dilithium_PublicKeyInternal>(std::move(mode), std::move(rho), std::move(t1));
      }

      Dilithium_PublicKeyInternal(DilithiumConstants mode, DilithiumSeedRho rho, DilithiumPolyVec t1) :
            m_mode(std::move(mode)),
            m_rho(std::move(rho)),
            m_t1(std::move(t1)),
            m_tr(m_mode.symmetric_primitives().H(raw_pk())) {
         BOTAN_ASSERT_NOMSG(!m_rho.empty());
         BOTAN_ASSERT_NOMSG(m_t1.size() > 0);
      }

   public:
      DilithiumSerializedPublicKey raw_pk() const { return Dilithium_Algos::encode_public_key(m_rho, m_t1, m_mode); }

      const DilithiumHashedPublicKey& tr() const { return m_tr; }

      const DilithiumPolyVec& t1() const { return m_t1; }

      const DilithiumSeedRho& rho() const { return m_rho; }

      const DilithiumConstants& mode() const { return m_mode; }

   private:
      const DilithiumConstants m_mode;
      DilithiumSeedRho m_rho;
      DilithiumPolyVec m_t1;
      DilithiumHashedPublicKey m_tr;
};

class Dilithium_PrivateKeyInternal {
   public:
      Dilithium_PrivateKeyInternal(DilithiumConstants mode,
                                   std::optional<DilithiumSeedRandomness> seed,
                                   DilithiumSigningSeedK signing_seed,
                                   DilithiumPolyVec s1,
                                   DilithiumPolyVec s2,
                                   DilithiumPolyVec t0) :
            m_mode(std::move(mode)),
            m_seed(std::move(seed)),
            m_signing_seed(std::move(signing_seed)),
            m_t0(std::move(t0)),
            m_s1(std::move(s1)),
            m_s2(std::move(s2)) {}

   public:
      const DilithiumConstants& mode() const { return m_mode; }

      const std::optional<DilithiumSeedRandomness>& seed() const { return m_seed; }

      const DilithiumSigningSeedK& signing_seed() const { return m_signing_seed; }

      const DilithiumPolyVec& s1() const { return m_s1; }

      const DilithiumPolyVec& s2() const { return m_s2; }

      const DilithiumPolyVec& t0() const { return m_t0; }

      void _const_time_poison() const {
         // Note: m_rho and m_tr is public knowledge
         CT::poison_all(m_signing_seed, m_s1, m_s2, m_t0);
         if(m_seed.has_value()) {
            CT::poison(m_seed.value());
         }
      }

      void _const_time_unpoison() const {
         CT::unpoison_all(m_signing_seed, m_s1, m_s2, m_t0);
         if(m_seed.has_value()) {
            CT::unpoison(m_seed.value());
         }
      }

   private:
      const DilithiumConstants m_mode;
      std::optional<DilithiumSeedRandomness> m_seed;
      DilithiumSigningSeedK m_signing_seed;
      DilithiumPolyVec m_t0;
      DilithiumPolyVec m_s1;
      DilithiumPolyVec m_s2;
};

}  // namespace Botan

#endif
