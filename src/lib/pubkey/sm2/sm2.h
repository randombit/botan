/*
* SM2
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SM2_KEY_H_
#define BOTAN_SM2_KEY_H_

#include <botan/ecc_key.h>

namespace Botan {

/**
* This class represents SM2 public keys
*/
class BOTAN_PUBLIC_API(2, 2) SM2_PublicKey : public virtual EC_PublicKey {
   public:
      /**
      * Create a public key from a given public point.
      * @param group the domain parameters associated with this key
      * @param public_key the public point defining this key
      */
      SM2_PublicKey(const EC_Group& group, const EC_AffinePoint& public_key) : EC_PublicKey(group, public_key) {}

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      /**
      * Create a public key from a given public point.
      * @param group the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      SM2_PublicKey(const EC_Group& group, const EC_Point& public_point) : EC_PublicKey(group, public_point) {}
#endif

      /**
      * Load a public key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits DER encoded public key bits
      */
      SM2_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
            EC_PublicKey(alg_id, key_bits) {}

      /**
      * Get this keys algorithm name.
      * @result this keys algorithm name
      */
      std::string algo_name() const override;

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      bool supports_operation(PublicKeyOperation op) const override {
         return (op == PublicKeyOperation::Signature || op == PublicKeyOperation::Encryption);
      }

      std::optional<size_t> _signature_element_size_for_DER_encoding() const override {
         return domain().get_order_bytes();
      }

      std::unique_ptr<PK_Ops::Verification> create_verification_op(std::string_view params,
                                                                   std::string_view provider) const override;

      std::unique_ptr<PK_Ops::Encryption> create_encryption_op(RandomNumberGenerator& rng,
                                                               std::string_view params,
                                                               std::string_view provider) const override;

   protected:
      SM2_PublicKey() = default;
};

/**
* This class represents SM2 private keys
*/

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(2, 2) SM2_PrivateKey final : public SM2_PublicKey,
                                                    public EC_PrivateKey {
   public:
      /**
      * Load a private key
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits ECPrivateKey bits
      */
      SM2_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      /**
      * Create a private key from a given secret @p x
      * @param group curve parameters to bu used for this key
      * @param x      the private key
      */
      SM2_PrivateKey(EC_Group group, EC_Scalar x);

      /**
      * Create a new private key
      * @param rng a random number generator
      * @param group parameters to used for this key
      */
      SM2_PrivateKey(RandomNumberGenerator& rng, EC_Group group);

      /**
      * Create a private key.
      * @param rng a random number generator
      * @param group parameters to used for this key
      * @param x the private key (if zero, generate a new random key)
      */
      BOTAN_DEPRECATED("Use one of the other constructors")
      SM2_PrivateKey(RandomNumberGenerator& rng, EC_Group group, const BigInt& x);

      bool check_key(RandomNumberGenerator& rng, bool) const override;

      std::unique_ptr<Public_Key> public_key() const override;

      std::unique_ptr<PK_Ops::Signature> create_signature_op(RandomNumberGenerator& rng,
                                                             std::string_view params,
                                                             std::string_view provider) const override;

      std::unique_ptr<PK_Ops::Decryption> create_decryption_op(RandomNumberGenerator& rng,
                                                               std::string_view params,
                                                               std::string_view provider) const override;

      BOTAN_DEPRECATED("Deprecated no replacement") const BigInt& get_da_inv() const { return m_da_inv_legacy; }

      const EC_Scalar& _get_da_inv() const { return m_da_inv; }

   private:
      EC_Scalar m_da_inv;
      BigInt m_da_inv_legacy;
};

BOTAN_DIAGNOSTIC_POP

class HashFunction;

/*
* This is deprecated because it's not clear what it is useful for
*
* Open an issue on GH if you are using this
*/
BOTAN_DEPRECATED("Deprecated unclear usage")
std::vector<uint8_t> BOTAN_PUBLIC_API(3, 7)
   sm2_compute_za(HashFunction& hash, std::string_view user_id, const EC_Group& group, const EC_AffinePoint& pubkey);

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
/*
* This is deprecated because it's not clear what it is useful for
*
* Open an issue on GH if you are using this
*/
BOTAN_DEPRECATED("Deprecated unclear usage")
inline std::vector<uint8_t> sm2_compute_za(HashFunction& hash,
                                           std::string_view user_id,
                                           const EC_Group& group,
                                           const EC_Point& pubkey) {
   auto apoint = EC_AffinePoint(group, pubkey);
   return sm2_compute_za(hash, user_id, group, apoint);
}
#endif

// For compat with versions 2.2 - 2.7
typedef SM2_PublicKey SM2_Signature_PublicKey;
typedef SM2_PublicKey SM2_Encryption_PublicKey;

typedef SM2_PrivateKey SM2_Signature_PrivateKey;
typedef SM2_PrivateKey SM2_Encryption_PrivateKey;

}  // namespace Botan

#endif
