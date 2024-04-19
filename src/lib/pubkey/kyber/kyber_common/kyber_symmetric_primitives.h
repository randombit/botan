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
#include <botan/secmem.h>
#include <botan/xof.h>

#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_types.h>
#include <botan/internal/stl_util.h>

#include <memory>
#include <span>
#include <tuple>
#include <vector>

namespace Botan {

/**
 * Adapter class that uses polymorphy to distinguish
 * Kyber "modern" from Kyber "90s" modes.
 */
class Kyber_Symmetric_Primitives {
   public:
      virtual ~Kyber_Symmetric_Primitives() = default;

      // TODO: remove this once Kyber-R3 is removed
      KyberMessage H(StrongSpan<const KyberMessage> m) const { return get_H().process<KyberMessage>(m); }

      // TODO: remove this once Kyber-R3 is removed
      KyberHashedCiphertext H(StrongSpan<const KyberCompressedCiphertext> r) const {
         return get_H().process<KyberHashedCiphertext>(r);
      }

      KyberHashedPublicKey H(StrongSpan<const KyberSerializedPublicKey> pk) const {
         return get_H().process<KyberHashedPublicKey>(pk);
      }

      std::pair<KyberSeedRho, KyberSeedSigma> G(StrongSpan<const KyberSeedRandomness> seed) const {
         return G_split<KyberSeedRho, KyberSeedSigma>(seed);
      }

      std::pair<KyberSharedSecret, KyberEncryptionRandomness> G(
         StrongSpan<const KyberMessage> msg, StrongSpan<const KyberHashedPublicKey> pubkey_hash) const {
         return G_split<KyberSharedSecret, KyberEncryptionRandomness>(msg, pubkey_hash);
      }

      // TODO: remove this once Kyber-R3 is removed
      void KDF(StrongSpan<KyberSharedSecret> out,
               StrongSpan<const KyberSharedSecret> shared_secret,
               StrongSpan<const KyberHashedCiphertext> hashed_ciphertext) const {
         auto& kdf = get_KDF();
         kdf.update(shared_secret);
         kdf.update(hashed_ciphertext);
         kdf.final(out);
      }

      KyberSamplingRandomness PRF(KyberSigmaOrEncryptionRandomness seed,
                                  const uint8_t nonce,
                                  const size_t outlen) const {
         auto bare_seed_span = std::visit([&](const auto s) { return s.get(); }, seed);
         return get_PRF(bare_seed_span, nonce).output<KyberSamplingRandomness>(outlen);
      }

      std::unique_ptr<Botan::XOF> XOF(StrongSpan<const KyberSeedRho> seed,
                                      std::tuple<uint8_t, uint8_t> matrix_position) const {
         // TODO: once we remove Kyber 90s, we should make `get_XOF()` return a
         //       reference instead of a unique pointer (for consistency), and
         //       call `get_XOF().copy_state()` here. The AES-CTR XOF doesn't
         //       support this.
         return get_XOF(seed, matrix_position);
      }

   private:
      template <concepts::contiguous_strong_type T1,
                concepts::contiguous_strong_type T2,
                ranges::contiguous_range... InputTs>
      std::pair<T1, T2> G_split(InputTs&&... inputs) const {
         auto& g = get_G();
         (g.update(inputs), ...);
         auto s = g.final();

         BufferSlicer bs(s);
         std::pair<T1, T2> result;
         result.first = bs.copy<T1>(KyberConstants::kSeedLength);
         result.second = bs.copy<T2>(KyberConstants::kSeedLength);
         BOTAN_ASSERT_NOMSG(bs.empty());
         return result;
      }

   protected:
      virtual HashFunction& get_G() const = 0;
      virtual HashFunction& get_H() const = 0;
      virtual HashFunction& get_KDF() const = 0;
      virtual Botan::XOF& get_PRF(std::span<const uint8_t> seed, uint8_t nonce) const = 0;
      virtual std::unique_ptr<Botan::XOF> get_XOF(std::span<const uint8_t> seed,
                                                  std::tuple<uint8_t, uint8_t> matrix_position) const = 0;
};

}  // namespace Botan

#endif
