/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ECC_PUBLIC_KEY_BASE_H_
#define BOTAN_ECC_PUBLIC_KEY_BASE_H_

#include <botan/ec_group.h>
#include <botan/pk_keys.h>
#include <memory>

namespace Botan {

class EC_PublicKey_Data;
class EC_PrivateKey_Data;

/**
* This class represents abstract ECC public keys. When encoding a key
* via an encoder that can be accessed via the corresponding member
* functions, the key will decide upon its internally stored encoding
* information whether to encode itself with or without domain
* parameters, or using the domain parameter oid. Furthermore, a public
* key without domain parameters can be decoded. In that case, it
* cannot be used for verification until its domain parameters are set
* by calling the corresponding member function.
*/
class BOTAN_PUBLIC_API(2, 0) EC_PublicKey : public virtual Public_Key {
   public:
      EC_PublicKey(const EC_PublicKey& other) = default;
      EC_PublicKey& operator=(const EC_PublicKey& other) = default;
      EC_PublicKey(EC_PublicKey&& other) = delete;
      EC_PublicKey& operator=(EC_PublicKey&& other) = delete;
      ~EC_PublicKey() override = default;

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      /**
      * Get the public point of this key.
      * @throw Invalid_State is thrown if the
      * domain parameters of this point are not set
      * @result the public point of this key
      */
      BOTAN_DEPRECATED("Avoid accessing the point directly") const EC_Point& public_point() const;
#endif

      AlgorithmIdentifier algorithm_identifier() const override;

      std::vector<uint8_t> raw_public_key_bits() const override;

      std::vector<uint8_t> public_key_bits() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      /**
      * Get the domain parameters of this key.
      * @throw Invalid_State is thrown if the
      * domain parameters of this point are not set
      * @result the domain parameters of this key
      */
      const EC_Group& domain() const;

      /**
      * Set the domain parameter encoding to be used when encoding this key.
      * @param enc the encoding to use
      *
      * This function is deprecated; in a future major release only namedCurve
      * encoding of domain parameters will be allowed.
      */
      BOTAN_DEPRECATED("Support for explicit point encoding is deprecated")
      void set_parameter_encoding(EC_Group_Encoding enc);

      /**
      * Set the point encoding method to be used when encoding this key.
      * @param enc the encoding to use
      */
      void set_point_encoding(EC_Point_Format enc);

      /**
      * Return the DER encoding of this keys domain in whatever format
      * is preset for this particular key
      */
      std::vector<uint8_t> DER_domain() const;

      /**
      * Get the domain parameter encoding to be used when encoding this key.
      * @result the encoding to use
      */
      EC_Group_Encoding domain_format() const { return m_domain_encoding; }

      /**
      * Get the point encoding method to be used when encoding this key.
      * @result the encoding to use
      */
      EC_Point_Format point_encoding() const { return m_point_encoding; }

      size_t key_length() const override;
      size_t estimated_strength() const override;

      const BigInt& get_int_field(std::string_view field) const override;

      const EC_AffinePoint& _public_ec_point() const;

   protected:
#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      /**
      * Load a public key from the point.
      *
      * @param group EC domain parameters
      * @param pub_point public point on the curve
      */
      EC_PublicKey(EC_Group group, const EC_Point& pub_point);
#endif

      /**
      * Load a public key from the point.
      *
      * @param group EC domain parameters
      * @param public_key public point on the curve
      */
      EC_PublicKey(EC_Group group, EC_AffinePoint public_key);

      /**
      * Load a public key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits DER encoded public key bits
      */
      EC_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      EC_PublicKey() = default;

      std::shared_ptr<const EC_PublicKey_Data> m_public_key;
      EC_Group_Encoding m_domain_encoding = EC_Group_Encoding::NamedCurve;
      EC_Point_Format m_point_encoding = EC_Point_Format::Uncompressed;
};

/**
* This abstract class represents ECC private keys
*/

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(2, 0) EC_PrivateKey : public virtual EC_PublicKey,
                                             public virtual Private_Key {
   public:
      secure_vector<uint8_t> private_key_bits() const final;

      secure_vector<uint8_t> raw_private_key_bits() const final;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      /**
      * Get the private key value of this key object.
      * @result the private key value of this key object
      */
      const BigInt& private_value() const;

      EC_PrivateKey(const EC_PrivateKey& other) = default;
      EC_PrivateKey& operator=(const EC_PrivateKey& other) = default;
      EC_PrivateKey(EC_PrivateKey&& other) = delete;
      EC_PrivateKey& operator=(EC_PrivateKey&& other) = delete;
      ~EC_PrivateKey() override = default;

      const BigInt& get_int_field(std::string_view field) const final;

      const EC_Scalar& _private_key() const;

   protected:
      /**
      * If x=0, creates a new private key in the domain
      * using the given rng. If with_modular_inverse is set,
      * the public key will be calculated by multiplying
      * the base point with the modular inverse of
      * x (as in ECGDSA and ECKCDSA), otherwise by
      * multiplying directly with x (as in ECDSA).
      *
      * TODO: Remove, once the respective deprecated constructors of the
      *       concrete ECC algorithms is removed.
      */
      EC_PrivateKey(RandomNumberGenerator& rng, EC_Group group, const BigInt& x, bool with_modular_inverse = false);

      /**
      * Creates a new private key
      *
      * If @p with_modular_inverse is set, the public key will be calculated by
      * multiplying the base point with the modular inverse of x (as in ECGDSA
      * and ECKCDSA), otherwise by multiplying directly with x (as in ECDSA).
      */
      EC_PrivateKey(RandomNumberGenerator& rng, EC_Group group, bool with_modular_inverse = false);

      /**
      * Load a EC private key from the secret scalar
      *
      * If @p with_modular_inverse is set, the public key will be calculated by
      * multiplying the base point with the modular inverse of x (as in ECGDSA
      * and ECKCDSA), otherwise by multiplying directly with x (as in ECDSA).
      */
      EC_PrivateKey(EC_Group group, EC_Scalar scalar, bool with_modular_inverse = false);

      /*
      * Creates a new private key object from the
      * ECPrivateKey structure given in key_bits.
      * If with_modular_inverse is set,
      * the public key will be calculated by multiplying
      * the base point with the modular inverse of
      * x (as in ECGDSA and ECKCDSA), otherwise by
      * multiplying directly with x (as in ECDSA).
      */
      EC_PrivateKey(const AlgorithmIdentifier& alg_id,
                    std::span<const uint8_t> key_bits,
                    bool with_modular_inverse = false);

      EC_PrivateKey() = default;

      std::shared_ptr<const EC_PrivateKey_Data> m_private_key;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
