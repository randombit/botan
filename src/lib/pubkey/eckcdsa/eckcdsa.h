/*
* ECKCDSA (ISO/IEC 14888-3:2018)
* (C) 2016 René Korthaus, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ECKCDSA_KEY_H_
#define BOTAN_ECKCDSA_KEY_H_

#include <botan/ecc_key.h>

namespace Botan {

/**
* This class represents ECKCDSA public keys.
*/
class BOTAN_PUBLIC_API(2, 0) ECKCDSA_PublicKey : public virtual EC_PublicKey {
   public:
      /**
      * Construct a public key from a given public point.
      * @param group the domain parameters associated with this key
      * @param public_key the public point defining this key
      */
      ECKCDSA_PublicKey(const EC_Group& group, const EC_AffinePoint& public_key) : EC_PublicKey(group, public_key) {}

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      /**
      * Construct a public key from a given public point.
      * @param group the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      ECKCDSA_PublicKey(const EC_Group& group, const EC_Point& public_point) : EC_PublicKey(group, public_point) {}
#endif

      /**
      * Load a public key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits DER encoded public key bits
      */
      ECKCDSA_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
            EC_PublicKey(alg_id, key_bits) {}

      /**
      * Get this keys algorithm name.
      */
      std::string algo_name() const override { return "ECKCDSA"; }

      std::optional<size_t> _signature_element_size_for_DER_encoding() const override {
         return domain().get_order_bytes();
      }

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      bool supports_operation(PublicKeyOperation op) const override { return (op == PublicKeyOperation::Signature); }

      std::unique_ptr<PK_Ops::Verification> create_verification_op(std::string_view params,
                                                                   std::string_view provider) const override;

      std::unique_ptr<PK_Ops::Verification> create_x509_verification_op(const AlgorithmIdentifier& signature_algorithm,
                                                                        std::string_view provider) const override;

   protected:
      ECKCDSA_PublicKey() = default;
};

/**
* This class represents ECKCDSA private keys.
*/

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(2, 0) ECKCDSA_PrivateKey final : public ECKCDSA_PublicKey,
                                                        public EC_PrivateKey {
   public:
      /**
      * Load a private key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits ECPrivateKey bits
      */
      ECKCDSA_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
            EC_PrivateKey(alg_id, key_bits, true) {}

      /**
      * Create a private key from a given secret @p x
      * @param group curve parameters to bu used for this key
      * @param x      the private key
      */
      ECKCDSA_PrivateKey(EC_Group group, EC_Scalar x) : EC_PrivateKey(std::move(group), std::move(x), true) {}

      /**
      * Create a new private key
      * @param rng a random number generator
      * @param group parameters to used for this key
      */
      ECKCDSA_PrivateKey(RandomNumberGenerator& rng, EC_Group group) : EC_PrivateKey(rng, std::move(group), true) {}

      /**
      * Create a private key.
      * @param rng a random number generator
      * @param group parameters to used for this key
      * @param x the private key (if zero, generate a new random key)
      */
      BOTAN_DEPRECATED("Use one of the other constructors")
      ECKCDSA_PrivateKey(RandomNumberGenerator& rng, const EC_Group& group, const BigInt& x) :
            EC_PrivateKey(rng, group, x, true) {}

      bool check_key(RandomNumberGenerator& rng, bool) const override;

      std::unique_ptr<Public_Key> public_key() const override;

      std::unique_ptr<PK_Ops::Signature> create_signature_op(RandomNumberGenerator& rng,
                                                             std::string_view params,
                                                             std::string_view provider) const override;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
