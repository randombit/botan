/*
 * Symmetric primitives for Kyber (modern)
 * (C) 2022 Jack Lloyd
 * (C) 2022 Hannes Rantzsch, René Meusel, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_SYMMETRIC_PRIMITIVES_H_
#define BOTAN_KYBER_SYMMETRIC_PRIMITIVES_H_

#include <botan/hash.h>
#include <botan/xof.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_types.h>

#include <span>
#include <tuple>

namespace Botan {

/**
 * Adapter class that uses polymorphy to distinguish
 * Kyber "modern" from Kyber "90s" modes.
 */
class Kyber_Symmetric_Primitives /* NOLINT(*-special-member-functions) */ {
   public:
      virtual ~Kyber_Symmetric_Primitives() = default;

      // TODO: remove this once Kyber-R3 is removed
      KyberMessage H(StrongSpan<const KyberMessage> m) const { return create_H()->process<KyberMessage>(m); }

      // TODO: remove this once Kyber-R3 is removed
      KyberHashedCiphertext H(StrongSpan<const KyberCompressedCiphertext> r) const {
         return create_H()->process<KyberHashedCiphertext>(r);
      }

      KyberHashedPublicKey H(StrongSpan<const KyberSerializedPublicKey> pk) const {
         return create_H()->process<KyberHashedPublicKey>(pk);
      }

      std::pair<KyberSeedRho, KyberSeedSigma> G(StrongSpan<const KyberSeedRandomness> seed,
                                                const KyberConstants& mode) const {
         if(auto domsep = seed_expansion_domain_separator(mode)) {
            return G_split<KyberSeedRho, KyberSeedSigma>(seed, *domsep);
         } else {
            return G_split<KyberSeedRho, KyberSeedSigma>(seed);
         }
      }

      std::pair<KyberSharedSecret, KyberEncryptionRandomness> G(
         StrongSpan<const KyberMessage> msg, StrongSpan<const KyberHashedPublicKey> pubkey_hash) const {
         return G_split<KyberSharedSecret, KyberEncryptionRandomness>(msg, pubkey_hash);
      }

      KyberSharedSecret J(StrongSpan<const KyberImplicitRejectionValue> rejection_value,
                          StrongSpan<const KyberCompressedCiphertext> ciphertext) const {
         auto j = create_J();
         j->update(rejection_value);
         j->update(ciphertext);
         return j->final<KyberSharedSecret>();
      }

      // TODO: remove this once Kyber-R3 is removed
      void KDF(StrongSpan<KyberSharedSecret> out,
               StrongSpan<const KyberSharedSecret> shared_secret,
               StrongSpan<const KyberHashedCiphertext> hashed_ciphertext) const {
         auto kdf = create_KDF();
         kdf->update(shared_secret);
         kdf->update(hashed_ciphertext);
         kdf->final(out);
      }

      KyberSamplingRandomness PRF(KyberSigmaOrEncryptionRandomness seed,
                                  const uint8_t nonce,
                                  const size_t outlen) const {
         auto bare_seed_span = std::visit([&](const auto s) { return s.get(); }, seed);
         return create_PRF(bare_seed_span, nonce)->output<KyberSamplingRandomness>(outlen);
      }

      /// Setup an XOF object for matrix sampling
      void setup_XOF(std::unique_ptr<Botan::XOF>& xof,
                     StrongSpan<const KyberSeedRho> seed,
                     std::tuple<uint8_t, uint8_t> matrix_position) const {
         if(!xof) {
            xof = create_XOF(seed, matrix_position);
         } else {
            init_XOF(*xof, seed, matrix_position);
         }
      }

      /// Setup a seeded PRF XOF for polynomial sampling
      void setup_PRF(std::unique_ptr<Botan::XOF>& xof, std::span<const uint8_t> seed, uint8_t nonce) const {
         if(!xof) {
            xof = create_PRF(seed, nonce);
         } else {
            init_PRF(*xof, seed, nonce);
         }
      }

   private:
      template <concepts::contiguous_strong_type T1,
                concepts::contiguous_strong_type T2,
                ranges::contiguous_range... InputTs>
      std::pair<T1, T2> G_split(const InputTs&... inputs) const {
         auto g = create_G();
         (g->update(inputs), ...);
         const auto s = g->final();

         BufferSlicer bs(s);
         std::pair<T1, T2> result;
         result.first = bs.copy<T1>(KyberConstants::SEED_BYTES);
         result.second = bs.copy<T2>(KyberConstants::SEED_BYTES);
         BOTAN_ASSERT_NOMSG(bs.empty());
         return result;
      }

   protected:
      virtual std::optional<std::array<uint8_t, 1>> seed_expansion_domain_separator(
         const KyberConstants& mode) const = 0;

      virtual std::unique_ptr<HashFunction> create_G() const = 0;
      virtual std::unique_ptr<HashFunction> create_H() const = 0;
      virtual std::unique_ptr<HashFunction> create_J() const = 0;
      virtual std::unique_ptr<HashFunction> create_KDF() const = 0;

      virtual std::unique_ptr<Botan::XOF> create_PRF(std::span<const uint8_t> seed, uint8_t nonce) const = 0;
      virtual void init_PRF(Botan::XOF& xof, std::span<const uint8_t> seed, uint8_t nonce) const = 0;

      virtual std::unique_ptr<Botan::XOF> create_XOF(std::span<const uint8_t> seed,
                                                     std::tuple<uint8_t, uint8_t> matrix_position) const = 0;
      virtual void init_XOF(Botan::XOF& xof,
                            std::span<const uint8_t> seed,
                            std::tuple<uint8_t, uint8_t> matrix_position) const = 0;
};

}  // namespace Botan

#endif
