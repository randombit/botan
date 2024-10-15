/*
* Asymmetric primitives for ML-DSA
* (C) 2024 Jack Lloyd
* (C) 2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ML_DSA_SYM_PRIMITIVES_H_
#define BOTAN_ML_DSA_SYM_PRIMITIVES_H_

#include <botan/internal/dilithium_symmetric_primitives.h>

#include <botan/rng.h>
#include <botan/internal/dilithium_keys.h>
#include <botan/internal/dilithium_shake_xof.h>
#include <botan/internal/int_utils.h>

namespace Botan {

class ML_DSA_Expanding_Keypair_Codec final : public Dilithium_Keypair_Codec {
   public:
      secure_vector<uint8_t> encode_keypair(DilithiumInternalKeypair keypair) const override;
      DilithiumInternalKeypair decode_keypair(std::span<const uint8_t> private_key,
                                              DilithiumConstants mode) const override;
};

class ML_DSA_MessageHash final : public DilithiumMessageHash {
   public:
      using DilithiumMessageHash::DilithiumMessageHash;

      bool is_valid_user_context(std::span<const uint8_t> user_context) const final {
         return user_context.size() <= 255;
      }

      void start(std::span<const uint8_t> user_context) final {
         // ML-DSA introduced an application-specific context string that is
         // empty by default and can be set by the application.
         //
         // In HashML-DSA, there's an additional domain information, namely
         // the serialized OID of the hash function used to hash the message.
         //
         // See FIPS 204, Algorithm 2, line 10 and Algorithm 7, line 6, and
         // FIPS 204, Section 5.4

         DilithiumMessageHash::start(user_context);
         constexpr uint8_t domain_separator = 0x00;  // HashML-DSA would use 0x01
         const uint8_t context_length = checked_cast_to<uint8_t>(user_context.size());
         update(std::array{domain_separator, context_length});
         update(user_context);
      }
};

class ML_DSA_Symmetric_Primitives final : public Dilithium_Symmetric_Primitives_Base {
   private:
      /// Rho prime computation for ML-DSA
      DilithiumSeedRhoPrime H(StrongSpan<const DilithiumSigningSeedK> k,
                              StrongSpan<const DilithiumOptionalRandomness> rnd,
                              StrongSpan<const DilithiumMessageRepresentative> mu) const {
         return H_256<DilithiumSeedRhoPrime>(DilithiumConstants::SEED_RHOPRIME_BYTES, k, rnd, mu);
      }

   public:
      ML_DSA_Symmetric_Primitives(const DilithiumConstants& mode) :
            Dilithium_Symmetric_Primitives_Base(mode, std::make_unique<DilithiumShakeXOF>()),
            m_seed_expansion_domain_separator({mode.k(), mode.l()}) {}

      DilithiumSeedRhoPrime H_maybe_randomized(
         StrongSpan<const DilithiumSigningSeedK> k,
         StrongSpan<const DilithiumMessageRepresentative> mu,
         std::optional<std::reference_wrapper<RandomNumberGenerator>> rng) const override {
         // NIST FIPS 204, Algorithm 2 (ML-DSA.Sign), line 5-8:
         const auto rnd = [&] {
            DilithiumOptionalRandomness optional_randomness(DilithiumConstants::OPTIONAL_RANDOMNESS_BYTES);
            if(rng.has_value()) {
               rng->get().randomize(optional_randomness);
            }
            return optional_randomness;
         }();
         return H(k, rnd, mu);
      }

      StrongSpan<const DilithiumCommitmentHash> truncate_commitment_hash(
         StrongSpan<const DilithiumCommitmentHash> seed) const override {
         return seed;
      }

      std::unique_ptr<DilithiumMessageHash> get_message_hash(DilithiumHashedPublicKey tr) const override {
         return std::make_unique<ML_DSA_MessageHash>(std::move(tr));
      }

      std::optional<std::array<uint8_t, 2>> seed_expansion_domain_separator() const override {
         return m_seed_expansion_domain_separator;
      }

   private:
      std::array<uint8_t, 2> m_seed_expansion_domain_separator;
};

}  // namespace Botan

#endif
