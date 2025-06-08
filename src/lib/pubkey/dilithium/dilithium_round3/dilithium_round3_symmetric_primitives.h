/*
* Asymmetric primitives for Dilithium round 3
* (C) 2022 Jack Lloyd
*     2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
*     2024 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_ROUND3_SYM_PRIMITIVES_H_
#define BOTAN_DILITHIUM_ROUND3_SYM_PRIMITIVES_H_

#include <botan/internal/dilithium_keys.h>
#include <botan/internal/dilithium_symmetric_primitives.h>

#include <botan/rng.h>

namespace Botan {

class Dilithium_Expanded_Keypair_Codec final : public Dilithium_Keypair_Codec {
   public:
      secure_vector<uint8_t> encode_keypair(DilithiumInternalKeypair keypair) const override;
      DilithiumInternalKeypair decode_keypair(std::span<const uint8_t> private_key,
                                              DilithiumConstants mode) const override;
};

class Dilithium_Round3_Symmetric_Primitives : public Dilithium_Symmetric_Primitives_Base {
   private:
      /// Rho prime (deterministic) computation for Dilithium R3 instances
      DilithiumSeedRhoPrime H(StrongSpan<const DilithiumSigningSeedK> k,
                              StrongSpan<const DilithiumMessageRepresentative> mu) const {
         return H_256<DilithiumSeedRhoPrime>(DilithiumConstants::SEED_RHOPRIME_BYTES, k, mu);
      }

   public:
      using Dilithium_Symmetric_Primitives_Base::Dilithium_Symmetric_Primitives_Base;

      DilithiumSeedRhoPrime H_maybe_randomized(
         StrongSpan<const DilithiumSigningSeedK> k,
         StrongSpan<const DilithiumMessageRepresentative> mu,
         std::optional<std::reference_wrapper<RandomNumberGenerator>> rng) const final {
         // Dilitihium R3, Figure 4, l. 12:
         //   p' in {0, 1}^512 := H(K || mu) (or p' <- {0, 1}^512 for randomized signing)
         return (rng.has_value())
                   ? rng->get().random_vec<DilithiumSeedRhoPrime>(DilithiumConstants::SEED_RHOPRIME_BYTES)
                   : H(k, mu);
      }

      StrongSpan<const DilithiumCommitmentHash> truncate_commitment_hash(
         StrongSpan<const DilithiumCommitmentHash> seed) const final {
         return StrongSpan<const DilithiumCommitmentHash>(
            seed.get().first(DilithiumConstants::COMMITMENT_HASH_C1_BYTES));
      }

      std::optional<std::array<uint8_t, 2>> seed_expansion_domain_separator() const final {
         // Dilithium does not require domain separation when expanding its
         // seeds from the input randomness.
         return std::nullopt;
      }
};

}  // namespace Botan

#endif
