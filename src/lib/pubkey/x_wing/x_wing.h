/**
* Implementation of
*   X-Wing: general-purpose hybrid post-quantum KEM
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X_WING_H_
#define BOTAN_X_WING_H_

#include <botan/hybrid_kem.h>

namespace Botan {

/**
 * @brief X-Wing Public Key
 *
 * X-Wing is a hybrid post-quantum key encapsulation mechanism (KEM) that combines
 * X25519 and Kyber-768 into a hybrid KEM. The implementation is for the
 * X-Wing draft: draft-connolly-cfrg-xwing-kem-02.
 *
 * @warning Experimental: The implementation is based on a
 * draft version. Therefore, its behavior and API can change
 * in future library versions.
 */
class BOTAN_UNSTABLE_API X_Wing_PublicKey : public virtual Hybrid_PublicKey {
   public:
      X_Wing_PublicKey(std::span<const uint8_t> pk_bytes);

      std::string algo_name() const override;
      AlgorithmIdentifier algorithm_identifier() const override;
      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      std::unique_ptr<PK_Ops::KEM_Encryption> create_kem_encryption_op(
         std::string_view kdf, std::string_view provider = "base") const override;

   protected:
      X_Wing_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks);
      static std::unique_ptr<X_Wing_PublicKey> from_public_keys(std::vector<std::unique_ptr<Public_Key>> pks);
      X_Wing_PublicKey() = default;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

/**
 * @brief X-Wing Public Key
 *
 * X-Wing is a hybrid post-quantum key encapsulation mechanism (KEM) that combines
 * X25519 and Kyber-768 into a hybrid KEM. The implementation is for the
 * X-Wing draft: draft-connolly-cfrg-xwing-kem-02.
 *
 * @warning Experimental: The implementation is based on a
 * draft version. Therefore, its behavior and API can change
 * in future library versions.
 */
class BOTAN_UNSTABLE_API X_Wing_PrivateKey final : public X_Wing_PublicKey,
                                                   public Hybrid_PrivateKey {
   public:
      /// Create a new X-Wing key using the given RNG
      X_Wing_PrivateKey(RandomNumberGenerator& rng);

      /// Load a raw X-Wing private key
      X_Wing_PrivateKey(std::span<const uint8_t> key_bytes);

      std::unique_ptr<Public_Key> public_key() const override;

      secure_vector<uint8_t> raw_private_key_bits() const override;

      secure_vector<uint8_t> private_key_bits() const override { return raw_private_key_bits(); }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::unique_ptr<PK_Ops::KEM_Decryption> create_kem_decryption_op(
         RandomNumberGenerator& rng, std::string_view kdf, std::string_view provider = "base") const override;

   private:
      /// Constructor helper. Creates a private key using the underlying public keys and private keys.
      X_Wing_PrivateKey(
         std::pair<std::vector<std::unique_ptr<Public_Key>>, std::vector<std::unique_ptr<Private_Key>>> key_pairs);
};

}  // namespace Botan

#endif  // BOTAN_X_WING_H_
