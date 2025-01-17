/*
* ECDH
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ECDH_KEY_H_
#define BOTAN_ECDH_KEY_H_

#include <botan/ecc_key.h>

namespace Botan {

/**
* This class represents ECDH Public Keys.
*/
class BOTAN_PUBLIC_API(2, 0) ECDH_PublicKey : public virtual EC_PublicKey {
   public:
      /**
      * Create an ECDH public key.
      * @param alg_id algorithm identifier
      * @param key_bits DER encoded public key bits
      */
      ECDH_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
            EC_PublicKey(alg_id, key_bits) {}

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      /**
      * Construct a public key from a given public point.
      * @param group the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      ECDH_PublicKey(const EC_Group& group, const EC_Point& public_point) : EC_PublicKey(group, public_point) {}
#endif

      /**
      * Construct a public key from a given public point.
      * @param group the domain parameters associated with this key
      * @param public_key the public point defining this key
      */
      ECDH_PublicKey(const EC_Group& group, const EC_AffinePoint& public_key) : EC_PublicKey(group, public_key) {}

      /**
      * Get this keys algorithm name.
      * @return this keys algorithm name
      */
      std::string algo_name() const override { return "ECDH"; }

      /**
      * @return public point value
      */
      std::vector<uint8_t> public_value() const { return this->public_value(EC_Point_Format::Uncompressed); }

      /**
      * @return public point value
      */
      std::vector<uint8_t> public_value(EC_Point_Format format) const;

      bool supports_operation(PublicKeyOperation op) const override { return (op == PublicKeyOperation::KeyAgreement); }

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

   protected:
      ECDH_PublicKey() = default;
};

/**
* This class represents ECDH Private Keys.
*/

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(2, 0) ECDH_PrivateKey final : public ECDH_PublicKey,
                                                     public EC_PrivateKey,
                                                     public PK_Key_Agreement_Key {
   public:
      /**
      * Load a private key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits ECPrivateKey bits
      */
      ECDH_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
            EC_PrivateKey(alg_id, key_bits) {}

      /**
      * Create a private key from a given secret @p x
      * @param group curve parameters to bu used for this key
      * @param x      the private key
      */
      ECDH_PrivateKey(EC_Group group, EC_Scalar x) : EC_PrivateKey(std::move(group), std::move(x)) {}

      /**
      * Create a new private key
      * @param rng a random number generator
      * @param group parameters to used for this key
      */
      ECDH_PrivateKey(RandomNumberGenerator& rng, EC_Group group) : EC_PrivateKey(rng, std::move(group)) {}

      /**
      * Generate a new private key
      * @param rng a random number generator
      * @param group parameters to used for this key
      * @param x the private key; if zero, a new random key is generated
      */
      BOTAN_DEPRECATED("Use one of the other constructors")
      ECDH_PrivateKey(RandomNumberGenerator& rng, const EC_Group& group, const BigInt& x) :
            EC_PrivateKey(rng, group, x) {}

      std::unique_ptr<Public_Key> public_key() const override;

      std::vector<uint8_t> public_value() const override {
         return ECDH_PublicKey::public_value(EC_Point_Format::Uncompressed);
      }

      std::vector<uint8_t> public_value(EC_Point_Format type) const { return ECDH_PublicKey::public_value(type); }

      std::unique_ptr<PK_Ops::Key_Agreement> create_key_agreement_op(RandomNumberGenerator& rng,
                                                                     std::string_view params,
                                                                     std::string_view provider) const override;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
