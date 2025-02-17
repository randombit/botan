/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ECDSA_KEY_H_
#define BOTAN_ECDSA_KEY_H_

#include <botan/ecc_key.h>

namespace Botan {

/**
* This class represents ECDSA Public Keys.
*/
class BOTAN_PUBLIC_API(2, 0) ECDSA_PublicKey : public virtual EC_PublicKey {
   public:
      /**
      * Create a public key from a given public point.
      * @param group the domain parameters associated with this key
      * @param public_key the public point defining this key
      */
      ECDSA_PublicKey(const EC_Group& group, const EC_AffinePoint& public_key) : EC_PublicKey(group, public_key) {}

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      /**
      * Create a public key from a given public point.
      * @param group the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      ECDSA_PublicKey(const EC_Group& group, const EC_Point& public_point) : EC_PublicKey(group, public_point) {}
#endif

      /**
      * Load a public key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits DER encoded public key bits
      */
      ECDSA_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
            EC_PublicKey(alg_id, key_bits) {}

      /**
      * Recover a public key from a signature/msg pair
      * See SEC section 4.6.1
      * @param group the elliptic curve group
      * @param msg the message
      * @param r the r paramter of the signature
      * @param s the s paramter of the signature
      * @param v the recovery ID
      */
      ECDSA_PublicKey(
         const EC_Group& group, const std::vector<uint8_t>& msg, const BigInt& r, const BigInt& s, uint8_t v);

      /**
      * Get this keys algorithm name.
      * @result this keys algorithm name ("ECDSA")
      */
      std::string algo_name() const override { return "ECDSA"; }

      std::optional<size_t> _signature_element_size_for_DER_encoding() const override {
         return domain().get_order_bytes();
      }

      bool supports_operation(PublicKeyOperation op) const override { return (op == PublicKeyOperation::Signature); }

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const override;

      uint8_t recovery_param(const std::vector<uint8_t>& msg, const BigInt& r, const BigInt& s) const;

      std::unique_ptr<PK_Ops::Verification> _create_verification_op(PK_Signature_Options& options) const override;

      std::unique_ptr<PK_Ops::Verification> create_x509_verification_op(const AlgorithmIdentifier& signature_algorithm,
                                                                        std::string_view provider) const override;

   protected:
      ECDSA_PublicKey() = default;
};

/**
* This class represents ECDSA Private Keys
*/

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(2, 0) ECDSA_PrivateKey final : public ECDSA_PublicKey,
                                                      public EC_PrivateKey {
   public:
      /**
      * Load a private key
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits ECPrivateKey bits
      */
      ECDSA_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
            EC_PrivateKey(alg_id, key_bits) {}

      /**
      * Create a private key from a given secret @p x
      * @param group curve parameters to bu used for this key
      * @param x      the private key
      */
      ECDSA_PrivateKey(EC_Group group, EC_Scalar x) : EC_PrivateKey(std::move(group), std::move(x)) {}

      /**
      * Create a new private key
      * @param rng a random number generator
      * @param group parameters to used for this key
      */
      ECDSA_PrivateKey(RandomNumberGenerator& rng, EC_Group group) : EC_PrivateKey(rng, std::move(group)) {}

      /**
      * Create a private key.
      * @param rng a random number generator
      * @param group parameters to used for this key
      * @param x the private key (if zero, generate a new random key)
      */
      BOTAN_DEPRECATED("Use one of the other constructors")
      ECDSA_PrivateKey(RandomNumberGenerator& rng, const EC_Group& group, const BigInt& x) :
            EC_PrivateKey(rng, group, x) {}

      bool check_key(RandomNumberGenerator& rng, bool) const override;

      std::unique_ptr<Public_Key> public_key() const override;

      std::unique_ptr<PK_Ops::Signature> _create_signature_op(RandomNumberGenerator& rng,
                                                              PK_Signature_Options& options) const override;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
