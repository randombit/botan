/*
* PKCS#11 RSA
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_rsa.h>
#include <botan/pk_keys.h>

#if defined(BOTAN_HAS_RSA)

#include <botan/internal/p11_mechanism.h>
#include <botan/pk_ops.h>
#include <botan/rng.h>
#include <botan/blinding.h>

namespace Botan {

namespace PKCS11 {

RSA_PublicKeyImportProperties::RSA_PublicKeyImportProperties(const BigInt& modulus, const BigInt& pub_exponent)
   : PublicKeyProperties(KeyType::Rsa), m_modulus(modulus), m_pub_exponent(pub_exponent)
   {
   add_binary(AttributeType::Modulus, BigInt::encode(m_modulus));
   add_binary(AttributeType::PublicExponent, BigInt::encode(m_pub_exponent));
   }

RSA_PublicKeyGenerationProperties::RSA_PublicKeyGenerationProperties(Ulong bits)
   : PublicKeyProperties(KeyType::Rsa)
   {
   add_numeric(AttributeType::ModulusBits, bits);
   }

PKCS11_RSA_PublicKey::PKCS11_RSA_PublicKey(Session& session, ObjectHandle handle)
   : Object(session, handle),
     RSA_PublicKey(BigInt::decode(get_attribute_value(AttributeType::Modulus)),
                   BigInt::decode(get_attribute_value(AttributeType::PublicExponent)))
   {
   }

PKCS11_RSA_PublicKey::PKCS11_RSA_PublicKey(Session& session, const RSA_PublicKeyImportProperties& pubkey_props)
   : Object(session, pubkey_props), RSA_PublicKey(pubkey_props.modulus(), pubkey_props.pub_exponent())
   {}


RSA_PrivateKeyImportProperties::RSA_PrivateKeyImportProperties(const BigInt& modulus, const BigInt& priv_exponent)
   : PrivateKeyProperties(KeyType::Rsa), m_modulus(modulus), m_priv_exponent(priv_exponent)
   {
   add_binary(AttributeType::Modulus, BigInt::encode(m_modulus));
   add_binary(AttributeType::PrivateExponent, BigInt::encode(m_priv_exponent));
   }


PKCS11_RSA_PrivateKey::PKCS11_RSA_PrivateKey(Session& session, ObjectHandle handle)
   : Object(session, handle),
     RSA_PublicKey(BigInt::decode(get_attribute_value(AttributeType::Modulus)),
                   BigInt::decode(get_attribute_value(AttributeType::PublicExponent)))
   {
   }

PKCS11_RSA_PrivateKey::PKCS11_RSA_PrivateKey(Session& session, const RSA_PrivateKeyImportProperties& priv_key_props)
   : Object(session, priv_key_props),
     RSA_PublicKey(priv_key_props.modulus(),
                   BigInt::decode(get_attribute_value(AttributeType::PublicExponent)))
   {
   }

PKCS11_RSA_PrivateKey::PKCS11_RSA_PrivateKey(Session& session, uint32_t bits,
                                             const RSA_PrivateKeyGenerationProperties& priv_key_props)
   : Object(session), RSA_PublicKey()
   {
   RSA_PublicKeyGenerationProperties pub_key_props(bits);
   pub_key_props.set_encrypt(true);
   pub_key_props.set_verify(true);
   pub_key_props.set_token(false);    // don't create a persistent public key object

   ObjectHandle pub_key_handle = CK_INVALID_HANDLE;
   ObjectHandle priv_key_handle = CK_INVALID_HANDLE;
   Mechanism mechanism = { static_cast< CK_MECHANISM_TYPE >(MechanismType::RsaPkcsKeyPairGen), nullptr, 0 };
   session.module()->C_GenerateKeyPair(session.handle(), &mechanism,
                                       pub_key_props.data(), static_cast<Ulong>(pub_key_props.count()),
                                       priv_key_props.data(), static_cast<Ulong>(priv_key_props.count()),
                                       &pub_key_handle, &priv_key_handle);

   this->reset_handle(priv_key_handle);

   BigInt n = BigInt::decode(get_attribute_value(AttributeType::Modulus));
   BigInt e = BigInt::decode(get_attribute_value(AttributeType::PublicExponent));
   RSA_PublicKey::init(std::move(n), std::move(e));
   }

RSA_PrivateKey PKCS11_RSA_PrivateKey::export_key() const
   {
   auto p = get_attribute_value(AttributeType::Prime1);
   auto q = get_attribute_value(AttributeType::Prime2);
   auto e = get_attribute_value(AttributeType::PublicExponent);
   auto d = get_attribute_value(AttributeType::PrivateExponent);
   auto n = get_attribute_value(AttributeType::Modulus);

   return RSA_PrivateKey(  BigInt::decode(p)
                         , BigInt::decode(q)
                         , BigInt::decode(e)
                         , BigInt::decode(d)
                         , BigInt::decode(n));
   }

secure_vector<uint8_t> PKCS11_RSA_PrivateKey::private_key_bits() const
   {
   return export_key().private_key_bits();
   }


namespace {
// note: multiple-part decryption operations (with C_DecryptUpdate/C_DecryptFinal)
// are not supported (PK_Ops::Decryption does not provide an `update` method)
class PKCS11_RSA_Decryption_Operation final : public PK_Ops::Decryption
   {
   public:

      PKCS11_RSA_Decryption_Operation(const PKCS11_RSA_PrivateKey& key,
                                      const std::string& padding,
                                      RandomNumberGenerator& rng)
         : m_key(key),
           m_mechanism(MechanismWrapper::create_rsa_crypt_mechanism(padding)),
           m_blinder(m_key.get_n(), rng,
                     [ this ](const BigInt& k) { return power_mod(k, m_key.get_e(), m_key.get_n()); },
                     [ this ](const BigInt& k) { return inverse_mod(k, m_key.get_n()); })
         {
         m_bits = m_key.get_n().bits() - 1;
         }

      size_t plaintext_length(size_t) const override { return m_key.get_n().bytes(); }

      secure_vector<uint8_t> decrypt(uint8_t& valid_mask, const uint8_t ciphertext[], size_t ciphertext_len) override
         {
         valid_mask = 0;
         m_key.module()->C_DecryptInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());

         std::vector<uint8_t> encrypted_data(ciphertext, ciphertext + ciphertext_len);

         // blind for RSA/RAW decryption
         if(! m_mechanism.padding_size())
            {
            encrypted_data = BigInt::encode(m_blinder.blind(BigInt::decode(encrypted_data)));
            }

         secure_vector<uint8_t> decrypted_data;
         m_key.module()->C_Decrypt(m_key.session().handle(), encrypted_data, decrypted_data);

         // Unblind for RSA/RAW decryption
         if(!m_mechanism.padding_size())
            {
            decrypted_data = BigInt::encode_1363(m_blinder.unblind(BigInt::decode(decrypted_data)), m_key.get_n().bits() / 8 );
            }

         valid_mask = 0xFF;
         return decrypted_data;
         }

   private:
      const PKCS11_RSA_PrivateKey& m_key;
      MechanismWrapper m_mechanism;
      size_t m_bits = 0;
      Blinder m_blinder;
   };

// note: multiple-part encryption operations (with C_EncryptUpdate/C_EncryptFinal)
// are not supported (PK_Ops::Encryption does not provide an `update` method)
class PKCS11_RSA_Encryption_Operation final : public PK_Ops::Encryption
   {
   public:

      PKCS11_RSA_Encryption_Operation(const PKCS11_RSA_PublicKey& key, const std::string& padding)
         : m_key(key), m_mechanism(MechanismWrapper::create_rsa_crypt_mechanism(padding))
         {
         m_bits = 8 * (key.get_n().bytes() - m_mechanism.padding_size()) - 1;
         }

      size_t ciphertext_length(size_t) const override { return m_key.get_n().bytes(); }

      size_t max_input_bits() const override
         {
         return m_bits;
         }

      secure_vector<uint8_t> encrypt(const uint8_t msg[], size_t msg_len, RandomNumberGenerator&) override
         {
         m_key.module()->C_EncryptInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());

         secure_vector<uint8_t> encrytped_data;
         m_key.module()->C_Encrypt(m_key.session().handle(), secure_vector<uint8_t>(msg, msg + msg_len), encrytped_data);
         return encrytped_data;
         }

   private:
      const PKCS11_RSA_PublicKey& m_key;
      MechanismWrapper m_mechanism;
      size_t m_bits = 0;
   };


class PKCS11_RSA_Signature_Operation final : public PK_Ops::Signature
   {
   public:

      PKCS11_RSA_Signature_Operation(const PKCS11_RSA_PrivateKey& key, const std::string& padding)
         : m_key(key), m_mechanism(MechanismWrapper::create_rsa_sign_mechanism(padding))
         {}

      size_t signature_length() const override { return m_key.get_n().bytes(); }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         if(!m_initialized)
            {
            // first call to update: initialize and cache message because we can not determine yet whether a single- or multiple-part operation will be performed
            m_key.module()->C_SignInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
            m_initialized = true;
            m_first_message = secure_vector<uint8_t>(msg, msg + msg_len);
            return;
            }

         if(!m_first_message.empty())
            {
            // second call to update: start multiple-part operation
            m_key.module()->C_SignUpdate(m_key.session().handle(), m_first_message);
            m_first_message.clear();
            }

         m_key.module()->C_SignUpdate(m_key.session().handle(), const_cast< Byte* >(msg), static_cast<Ulong>(msg_len));
         }

      secure_vector<uint8_t> sign(RandomNumberGenerator&) override
         {
         secure_vector<uint8_t> signature;
         if(!m_first_message.empty())
            {
            // single call to update: perform single-part operation
            m_key.module()->C_Sign(m_key.session().handle(), m_first_message, signature);
            m_first_message.clear();
            }
         else
            {
            // multiple calls to update (or none): finish multiple-part operation
            m_key.module()->C_SignFinal(m_key.session().handle(), signature);
            }
         m_initialized = false;
         return signature;
         }

   private:
      const PKCS11_RSA_PrivateKey& m_key;
      bool m_initialized = false;
      secure_vector<uint8_t> m_first_message;
      MechanismWrapper m_mechanism;
   };


class PKCS11_RSA_Verification_Operation final : public PK_Ops::Verification
   {
   public:

      PKCS11_RSA_Verification_Operation(const PKCS11_RSA_PublicKey& key, const std::string& padding)
         : m_key(key), m_mechanism(MechanismWrapper::create_rsa_sign_mechanism(padding))
         {}

      void update(const uint8_t msg[], size_t msg_len) override
         {
         if(!m_initialized)
            {
            // first call to update: initialize and cache message because we can not determine yet whether a single- or multiple-part operation will be performed
            m_key.module()->C_VerifyInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
            m_initialized = true;
            m_first_message = secure_vector<uint8_t>(msg, msg + msg_len);
            return;
            }

         if(!m_first_message.empty())
            {
            // second call to update: start multiple-part operation
            m_key.module()->C_VerifyUpdate(m_key.session().handle(), m_first_message);
            m_first_message.clear();
            }

         m_key.module()->C_VerifyUpdate(m_key.session().handle(), const_cast< Byte* >(msg), static_cast<Ulong>(msg_len));
         }

      bool is_valid_signature(const uint8_t sig[], size_t sig_len) override
         {
         ReturnValue return_value = ReturnValue::SignatureInvalid;
         if(!m_first_message.empty())
            {
            // single call to update: perform single-part operation
            m_key.module()->C_Verify(m_key.session().handle(),
                                     m_first_message.data(), static_cast<Ulong>(m_first_message.size()),
                                     const_cast< Byte* >(sig), static_cast<Ulong>(sig_len), &return_value);
            m_first_message.clear();
            }
         else
            {
            // multiple calls to update (or none): finish multiple-part operation
            m_key.module()->C_VerifyFinal(m_key.session().handle(), const_cast< Byte* >(sig), static_cast<Ulong>(sig_len), &return_value);
            }
         m_initialized = false;
         if(return_value != ReturnValue::OK && return_value != ReturnValue::SignatureInvalid)
            {
            throw PKCS11_ReturnError(return_value);
            }
         return return_value == ReturnValue::OK;
         }

   private:
      const PKCS11_RSA_PublicKey& m_key;
      bool m_initialized = false;
      secure_vector<uint8_t> m_first_message;
      MechanismWrapper m_mechanism;
   };

}

std::unique_ptr<PK_Ops::Encryption>
PKCS11_RSA_PublicKey::create_encryption_op(RandomNumberGenerator& /*rng*/,
                                           const std::string& params,
                                           const std::string& /*provider*/) const
   {
   return std::unique_ptr<PK_Ops::Encryption>(new PKCS11_RSA_Encryption_Operation(*this, params));
   }

std::unique_ptr<PK_Ops::Verification>
PKCS11_RSA_PublicKey::create_verification_op(const std::string& params,
                                             const std::string& /*provider*/) const
   {
   return std::unique_ptr<PK_Ops::Verification>(new PKCS11_RSA_Verification_Operation(*this, params));
   }

std::unique_ptr<PK_Ops::Decryption>
PKCS11_RSA_PrivateKey::create_decryption_op(RandomNumberGenerator& rng,
                                            const std::string& params,
                                            const std::string& /*provider*/) const
   {
   return std::unique_ptr<PK_Ops::Decryption>(new PKCS11_RSA_Decryption_Operation(*this, params, rng));
   }

std::unique_ptr<PK_Ops::Signature>
PKCS11_RSA_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                           const std::string& params,
                                           const std::string& /*provider*/) const
   {
   return std::unique_ptr<PK_Ops::Signature>(new PKCS11_RSA_Signature_Operation(*this, params));
   }

PKCS11_RSA_KeyPair generate_rsa_keypair(Session& session, const RSA_PublicKeyGenerationProperties& pub_props,
                                        const RSA_PrivateKeyGenerationProperties& priv_props)
   {
   ObjectHandle pub_key_handle = 0;
   ObjectHandle priv_key_handle = 0;

   Mechanism mechanism = { static_cast< CK_MECHANISM_TYPE >(MechanismType::RsaPkcsKeyPairGen), nullptr, 0 };

   session.module()->C_GenerateKeyPair(session.handle(), &mechanism,
                                       pub_props.data(), static_cast<Ulong>(pub_props.count()),
                                       priv_props.data(), static_cast<Ulong>(priv_props.count()),
                                       &pub_key_handle, &priv_key_handle);

   return std::make_pair(PKCS11_RSA_PublicKey(session, pub_key_handle), PKCS11_RSA_PrivateKey(session, priv_key_handle));
   }

}
}

#endif
