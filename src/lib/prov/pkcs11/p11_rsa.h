/*
* PKCS#11 RSA
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_P11_RSA_H_
#define BOTAN_P11_RSA_H_

#include <botan/bigint.h>
#include <botan/p11_object.h>
#include <botan/p11_types.h>
#include <botan/pk_keys.h>

#if defined(BOTAN_HAS_RSA)
   #include <botan/rsa.h>
   #include <utility>

namespace Botan::PKCS11 {

/// Properties for generating a PKCS#11 RSA public key
class BOTAN_PUBLIC_API(2, 0) RSA_PublicKeyGenerationProperties final : public PublicKeyProperties {
   public:
      /// @param bits length in bits of modulus n
      explicit RSA_PublicKeyGenerationProperties(Ulong bits);

      /// @param pub_exponent public exponent e
      inline void set_pub_exponent(const BigInt& pub_exponent = BigInt::from_word(0x10001)) {
         add_binary(AttributeType::PublicExponent, pub_exponent.serialize());
      }

      ~RSA_PublicKeyGenerationProperties() override = default;
};

/// Properties for importing a PKCS#11 RSA public key
class BOTAN_PUBLIC_API(2, 0) RSA_PublicKeyImportProperties final : public PublicKeyProperties {
   public:
      /// @param modulus modulus n
      /// @param pub_exponent public exponent e
      RSA_PublicKeyImportProperties(const BigInt& modulus, const BigInt& pub_exponent);

      /// @return the modulus
      inline const BigInt& modulus() const { return m_modulus; }

      /// @return the public exponent
      inline const BigInt& pub_exponent() const { return m_pub_exponent; }

      ~RSA_PublicKeyImportProperties() override = default;

   private:
      const BigInt m_modulus;
      const BigInt m_pub_exponent;
};

/// Represents a PKCS#11 RSA public key
class BOTAN_PUBLIC_API(2, 0) PKCS11_RSA_PublicKey : public Object,
                                                    public RSA_PublicKey {
   public:
      static const ObjectClass Class = ObjectClass::PublicKey;

      /**
      * Creates a PKCS11_RSA_PublicKey object from an existing PKCS#11 RSA public key
      * @param session the session to use
      * @param handle the handle of the RSA public key
      */
      PKCS11_RSA_PublicKey(Session& session, ObjectHandle handle);

      /**
      * Imports a RSA public key
      * @param session the session to use
      * @param pubkey_props the attributes of the public key
      */
      PKCS11_RSA_PublicKey(Session& session, const RSA_PublicKeyImportProperties& pubkey_props);

      /**
       * @throws Not_Implemented as this operation is not possible in PKCS11
       */
      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator&) const final {
         throw Not_Implemented("Cannot generate a new PKCS#11 RSA keypair from this public key");
      }

      std::unique_ptr<PK_Ops::Encryption> create_encryption_op(RandomNumberGenerator& rng,
                                                               std::string_view params,
                                                               std::string_view provider) const override;

      std::unique_ptr<PK_Ops::Verification> _create_verification_op(PK_Signature_Options& options) const override;
};

/// Properties for importing a PKCS#11 RSA private key
class BOTAN_PUBLIC_API(2, 0) RSA_PrivateKeyImportProperties final : public PrivateKeyProperties {
   public:
      /**
      * @param modulus modulus n
      * @param priv_exponent private exponent d
      */
      RSA_PrivateKeyImportProperties(const BigInt& modulus, const BigInt& priv_exponent);

      /// @param pub_exponent public exponent e
      inline void set_pub_exponent(const BigInt& pub_exponent) {
         add_binary(AttributeType::PublicExponent, pub_exponent.serialize());
      }

      /// @param prime1 prime p
      inline void set_prime_1(const BigInt& prime1) { add_binary(AttributeType::Prime1, prime1.serialize()); }

      /// @param prime2 prime q
      inline void set_prime_2(const BigInt& prime2) { add_binary(AttributeType::Prime2, prime2.serialize()); }

      /// @param exp1 private exponent d modulo p-1
      inline void set_exponent_1(const BigInt& exp1) { add_binary(AttributeType::Exponent1, exp1.serialize()); }

      /// @param exp2 private exponent d modulo q-1
      inline void set_exponent_2(const BigInt& exp2) { add_binary(AttributeType::Exponent2, exp2.serialize()); }

      /// @param coeff CRT coefficient q^-1 mod p
      inline void set_coefficient(const BigInt& coeff) { add_binary(AttributeType::Coefficient, coeff.serialize()); }

      /// @return the modulus
      inline const BigInt& modulus() const { return m_modulus; }

      /// @return the private exponent
      inline const BigInt& priv_exponent() const { return m_priv_exponent; }

      ~RSA_PrivateKeyImportProperties() override = default;

   private:
      const BigInt m_modulus;
      const BigInt m_priv_exponent;
};

/// Properties for generating a PKCS#11 RSA private key
class BOTAN_PUBLIC_API(2, 0) RSA_PrivateKeyGenerationProperties final : public PrivateKeyProperties {
   public:
      RSA_PrivateKeyGenerationProperties() : PrivateKeyProperties(KeyType::Rsa) {}

      ~RSA_PrivateKeyGenerationProperties() override = default;
};

/// Represents a PKCS#11 RSA private key

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(2, 0) PKCS11_RSA_PrivateKey final : public Object,
                                                           public Private_Key,
                                                           public RSA_PublicKey {
   public:
      static const ObjectClass Class = ObjectClass::PrivateKey;

      /// Creates a PKCS11_RSA_PrivateKey object from an existing PKCS#11 RSA private key
      PKCS11_RSA_PrivateKey(Session& session, ObjectHandle handle);

      /**
      * Imports a RSA private key
      * @param session the session to use
      * @param priv_key_props the properties of the RSA private key
      */
      PKCS11_RSA_PrivateKey(Session& session, const RSA_PrivateKeyImportProperties& priv_key_props);

      /**
      * Generates a PKCS#11 RSA private key
      * @param session the session to use
      * @param bits length in bits of modulus n
      * @param priv_key_props the properties of the RSA private key
      * @note no persistent public key object will be created
      */
      PKCS11_RSA_PrivateKey(Session& session, uint32_t bits, const RSA_PrivateKeyGenerationProperties& priv_key_props);

      /// @return the exported RSA private key
      RSA_PrivateKey export_key() const;

      /**
       * If enabled, the PKCS#11 module gets to perform the raw RSA decryption
       * using a blinded ciphertext. The EME unpadding is performed in software.
       * This essenially hides the plaintext value from the PKCS#11 module.
       *
       * @param software_padding  if true, perform the unpadding in software
       */
      void set_use_software_padding(bool software_padding) { m_use_software_padding = software_padding; }

      bool uses_software_padding() const { return m_use_software_padding; }

      secure_vector<uint8_t> private_key_bits() const override;

      std::unique_ptr<Public_Key> public_key() const override;

      std::unique_ptr<PK_Ops::Decryption> create_decryption_op(RandomNumberGenerator& rng,
                                                               std::string_view params,
                                                               std::string_view provider) const override;

      std::unique_ptr<PK_Ops::Signature> _create_signature_op(RandomNumberGenerator& rng,
                                                              PK_Signature_Options& options) const override;

   private:
      bool m_use_software_padding = false;
};

BOTAN_DIAGNOSTIC_POP

using PKCS11_RSA_KeyPair = std::pair<PKCS11_RSA_PublicKey, PKCS11_RSA_PrivateKey>;

/**
* RSA key pair generation
* @param session the session that should be used for the key generation
* @param pub_props properties of the public key
* @param priv_props properties of the private key
*/
BOTAN_PUBLIC_API(2, 0)
PKCS11_RSA_KeyPair generate_rsa_keypair(Session& session,
                                        const RSA_PublicKeyGenerationProperties& pub_props,
                                        const RSA_PrivateKeyGenerationProperties& priv_props);
}  // namespace Botan::PKCS11
#endif

#endif
