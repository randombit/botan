/**
* Composite key pair that exposes the Public/Private key API but combines
* multiple key agreement schemes into a hybrid algorithm.
*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_13_HYBRID_KEM_PUBLIC_KEY_H_
#define BOTAN_TLS_13_HYBRID_KEM_PUBLIC_KEY_H_

#include <botan/pubkey.h>

#include <botan/tls_algos.h>
#include <botan/internal/hybrid_kem.h>

#include <memory>
#include <vector>

namespace Botan::TLS {

/**
 * Composes a number of public keys as defined in this IETF draft:
 * https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design-04
 *
 * To an upstream user, this composite key pair is presented as a KEM. Each
 * individual key pair must either work as a KEX or as a KEM. Currently, the
 * class can deal with ECC keys and Kyber.
 *
 * The typical use case provides exactly two keys (one traditional KEX and one
 * post-quantum secure KEM). However, this class technically allows composing
 * any number of such keys. Composing more than two keys simply generates a
 * shared secret based on more algorithms.
 *
 * Note that this class is not generic enough for arbitrary use cases but
 * serializes and parses keys and ciphertexts as described in the
 * above-mentioned IETF draft for a post-quantum TLS 1.3.
 */
class BOTAN_TEST_API Hybrid_KEM_PublicKey : public virtual Hybrid_PublicKey {
   public:
      static std::unique_ptr<Hybrid_KEM_PublicKey> load_for_group(Group_Params group,
                                                                  std::span<const uint8_t> concatenated_public_values);

   public:
      explicit Hybrid_KEM_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks);

      std::string algo_name() const override;
      AlgorithmIdentifier algorithm_identifier() const override;
      std::vector<uint8_t> raw_public_key_bits() const override;
      std::vector<uint8_t> public_key_bits() const override;
      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      // no KDF support
      std::unique_ptr<PK_Ops::KEM_Encryption> create_kem_encryption_op(
         std::string_view params, std::string_view provider = "base") const override;

   protected:
      Hybrid_KEM_PublicKey() = default;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

/**
 * Composes a number of private keys for hybrid key agreement as defined in this
 * IETF draft: https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design-04
 */
class BOTAN_TEST_API Hybrid_KEM_PrivateKey final : public Hybrid_KEM_PublicKey,
                                                   public Hybrid_PrivateKey {
   public:
      /**
       * Generate a hybrid private key for the given TLS code point.
       */
      static std::unique_ptr<Hybrid_KEM_PrivateKey> generate_from_group(Group_Params group, RandomNumberGenerator& rng);

   public:
      explicit Hybrid_KEM_PrivateKey(std::vector<std::unique_ptr<Private_Key>> private_keys);

      std::unique_ptr<Public_Key> public_key() const override {
         return std::make_unique<Hybrid_KEM_PublicKey>(extract_public_keys(private_keys()));
      }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override {
         return Hybrid_PrivateKey::check_key(rng, strong);
      }

      // no KDF support
      std::unique_ptr<PK_Ops::KEM_Decryption> create_kem_decryption_op(
         RandomNumberGenerator& rng, std::string_view params, std::string_view provider = "base") const override;
};

}  // namespace Botan::TLS

#endif
