/**
* Composite key pair that exposes the Public/Private key API but combines
* multiple key agreement schemes into a hybrid algorithm.
*
* (C) 2022 Jack Lloyd
*     2022 René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_13_COMPOUND_PUBLIC_KEY_H_
#define BOTAN_TLS_13_COMPOUND_PUBLIC_KEY_H_

#include <botan/pubkey.h>
#include <botan/tls_algos.h>

#include <memory>
#include <vector>

namespace Botan::TLS {

class Policy;

/**
 * Composes a number of public keys as defined in this IETF draft:
 * https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design-04
 *
 * To an upstream user this composite key pair is presented as a KEM.
 * Compositions of at least two (and potentially more) public keys are legal.
 * Each individual key pair must either work as a KEX or as a KEM. Currently,
 * the class can deal with ECC keys anc Kyber.
 *
 * Note that this class is not generic enough for arbitrary use cases but
 * serializes and parses keys and ciphertexts as described in above-mentioned
 * IETF draft for a post-quantum TLS 1.3.
 */
class Composite_PublicKey : public virtual Public_Key
   {
   public:
      explicit Composite_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks);

      std::string algo_name() const override;
      size_t estimated_strength() const override;
      size_t key_length() const override;
      bool check_key(RandomNumberGenerator& rng, bool strong) const override;
      AlgorithmIdentifier algorithm_identifier() const override;
      std::vector<uint8_t> public_key_bits() const override;

      std::unique_ptr<PK_Ops::KEM_Encryption>
         create_kem_encryption_op(RandomNumberGenerator& rng,
                                  const std::string& kdf,
                                  const std::string& provider = "base") const override;

   protected:
      Composite_PublicKey(Group_Params groups) : m_groups(groups) {};

   protected:
      Group_Params                             m_groups;
      std::vector<std::unique_ptr<Public_Key>> m_public_keys;
   };


/**
 * Composes a number of private keys for hybrid key agreement as defined in this
 * IETF draft: https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design-04
 */
class Composite_PrivateKey final : public Private_Key,
                                   public Composite_PublicKey
   {
   public:
      Composite_PrivateKey(RandomNumberGenerator& rng, Group_Params groups, const Policy& policy);

      secure_vector<uint8_t> private_key_bits() const override;

      std::unique_ptr<Public_Key> public_key() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::unique_ptr<PK_Ops::KEM_Decryption>
         create_kem_decryption_op(RandomNumberGenerator& rng,
                                  const std::string& kdf,
                                  const std::string& provider = "base") const override;


   private:
      friend class Composite_KEM_Decryption;

      std::vector<std::unique_ptr<Public_Key>> public_keys() const;
      secure_vector<uint8_t> decapsulate(const std::vector<std::vector<uint8_t>>& ciphertexts,
                                         RandomNumberGenerator& rng,
                                         const std::string& provider) const;

   private:
      const Policy&                             m_policy;
      std::vector<std::unique_ptr<Private_Key>> m_private_keys;
   };

}

#endif
