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

   #include <botan/pubkey.h>
   #include <botan/rng.h>
   #include <botan/internal/blinding.h>
   #include <botan/internal/p11_mechanism.h>
   #include <botan/internal/pk_ops_impl.h>

namespace Botan::PKCS11 {

RSA_PublicKeyImportProperties::RSA_PublicKeyImportProperties(const BigInt& modulus, const BigInt& pub_exponent) :
      PublicKeyProperties(KeyType::Rsa), m_modulus(modulus), m_pub_exponent(pub_exponent) {
   add_binary(AttributeType::Modulus, m_modulus.serialize());
   add_binary(AttributeType::PublicExponent, m_pub_exponent.serialize());
}

RSA_PublicKeyGenerationProperties::RSA_PublicKeyGenerationProperties(Ulong bits) : PublicKeyProperties(KeyType::Rsa) {
   add_numeric(AttributeType::ModulusBits, bits);
}

PKCS11_RSA_PublicKey::PKCS11_RSA_PublicKey(Session& session, ObjectHandle handle) :
      Object(session, handle),
      RSA_PublicKey(BigInt::from_bytes(get_attribute_value(AttributeType::Modulus)),
                    BigInt::from_bytes(get_attribute_value(AttributeType::PublicExponent))) {}

PKCS11_RSA_PublicKey::PKCS11_RSA_PublicKey(Session& session, const RSA_PublicKeyImportProperties& pubkey_props) :
      Object(session, pubkey_props), RSA_PublicKey(pubkey_props.modulus(), pubkey_props.pub_exponent()) {}

RSA_PrivateKeyImportProperties::RSA_PrivateKeyImportProperties(const BigInt& modulus, const BigInt& priv_exponent) :
      PrivateKeyProperties(KeyType::Rsa), m_modulus(modulus), m_priv_exponent(priv_exponent) {
   add_binary(AttributeType::Modulus, m_modulus.serialize());
   add_binary(AttributeType::PrivateExponent, m_priv_exponent.serialize());
}

PKCS11_RSA_PrivateKey::PKCS11_RSA_PrivateKey(Session& session, ObjectHandle handle) :
      Object(session, handle),
      RSA_PublicKey(BigInt::from_bytes(get_attribute_value(AttributeType::Modulus)),
                    BigInt::from_bytes(get_attribute_value(AttributeType::PublicExponent))) {}

PKCS11_RSA_PrivateKey::PKCS11_RSA_PrivateKey(Session& session, const RSA_PrivateKeyImportProperties& priv_key_props) :
      Object(session, priv_key_props),
      RSA_PublicKey(priv_key_props.modulus(), BigInt::from_bytes(get_attribute_value(AttributeType::PublicExponent))) {}

PKCS11_RSA_PrivateKey::PKCS11_RSA_PrivateKey(Session& session,
                                             uint32_t bits,
                                             const RSA_PrivateKeyGenerationProperties& priv_key_props) :
      Object(session), RSA_PublicKey() {
   RSA_PublicKeyGenerationProperties pub_key_props(bits);
   pub_key_props.set_encrypt(true);
   pub_key_props.set_verify(true);
   pub_key_props.set_token(false);  // don't create a persistent public key object

   ObjectHandle pub_key_handle = CK_INVALID_HANDLE;
   ObjectHandle priv_key_handle = CK_INVALID_HANDLE;
   Mechanism mechanism = {static_cast<CK_MECHANISM_TYPE>(MechanismType::RsaPkcsKeyPairGen), nullptr, 0};
   session.module()->C_GenerateKeyPair(session.handle(),
                                       &mechanism,
                                       pub_key_props.data(),
                                       static_cast<Ulong>(pub_key_props.count()),
                                       priv_key_props.data(),
                                       static_cast<Ulong>(priv_key_props.count()),
                                       &pub_key_handle,
                                       &priv_key_handle);

   this->reset_handle(priv_key_handle);

   BigInt n = BigInt::from_bytes(get_attribute_value(AttributeType::Modulus));
   BigInt e = BigInt::from_bytes(get_attribute_value(AttributeType::PublicExponent));
   RSA_PublicKey::init(std::move(n), std::move(e));
}

RSA_PrivateKey PKCS11_RSA_PrivateKey::export_key() const {
   auto p = get_attribute_value(AttributeType::Prime1);
   auto q = get_attribute_value(AttributeType::Prime2);
   auto e = get_attribute_value(AttributeType::PublicExponent);
   auto d = get_attribute_value(AttributeType::PrivateExponent);
   auto n = get_attribute_value(AttributeType::Modulus);

   return RSA_PrivateKey(BigInt::from_bytes(p),
                         BigInt::from_bytes(q),
                         BigInt::from_bytes(e),
                         BigInt::from_bytes(d),
                         BigInt::from_bytes(n));
}

std::unique_ptr<Public_Key> PKCS11_RSA_PrivateKey::public_key() const {
   return std::make_unique<RSA_PublicKey>(BigInt::from_bytes(get_attribute_value(AttributeType::Modulus)),
                                          BigInt::from_bytes(get_attribute_value(AttributeType::PublicExponent)));
}

secure_vector<uint8_t> PKCS11_RSA_PrivateKey::private_key_bits() const {
   return export_key().private_key_bits();
}

namespace {
// note: multiple-part decryption operations (with C_DecryptUpdate/C_DecryptFinal)
// are not supported (PK_Ops::Decryption does not provide an `update` method)
class PKCS11_RSA_Decryption_Operation final : public PK_Ops::Decryption {
   public:
      PKCS11_RSA_Decryption_Operation(const PKCS11_RSA_PrivateKey& key,
                                      std::string_view padding,
                                      RandomNumberGenerator& rng) :
            m_key(key),
            m_mechanism(MechanismWrapper::create_rsa_crypt_mechanism(padding)),
            m_blinder(
               m_key.get_n(),
               rng,
               [this](const BigInt& k) { return power_mod(k, m_key.get_e(), m_key.get_n()); },
               [this](const BigInt& k) { return inverse_mod(k, m_key.get_n()); }) {
         m_bits = m_key.get_n().bits() - 1;
      }

      size_t plaintext_length(size_t /*ctext_len*/) const override { return m_key.get_n().bytes(); }

      secure_vector<uint8_t> decrypt(uint8_t& valid_mask, const uint8_t ciphertext[], size_t ciphertext_len) override {
         valid_mask = 0;
         m_key.module()->C_DecryptInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());

         std::vector<uint8_t> encrypted_data(ciphertext, ciphertext + ciphertext_len);

         const size_t modulus_bytes = (m_key.get_n().bits() + 7) / 8;

         // blind for RSA/RAW decryption
         const bool use_blinding = !m_mechanism.padding_size();

         if(use_blinding) {
            const BigInt blinded = m_blinder.blind(BigInt::from_bytes(encrypted_data));
            // SoftHSM at least requires raw RSA inputs be == the modulus size
            encrypted_data = blinded.serialize(modulus_bytes);
         }

         secure_vector<uint8_t> decrypted_data;
         m_key.module()->C_Decrypt(m_key.session().handle(), encrypted_data, decrypted_data);

         // Unblind for RSA/RAW decryption
         if(use_blinding) {
            const BigInt unblinded = m_blinder.unblind(BigInt::from_bytes(decrypted_data));
            decrypted_data.resize(modulus_bytes);
            unblinded.serialize_to(decrypted_data);
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

// note: multiple-part decryption operations (with C_DecryptUpdate/C_DecryptFinal)
// are not supported (PK_Ops::Decryption does not provide an `update` method)
class PKCS11_RSA_Decryption_Operation_Software_EME final : public PK_Ops::Decryption_with_EME {
   public:
      PKCS11_RSA_Decryption_Operation_Software_EME(const PKCS11_RSA_PrivateKey& key,
                                                   std::string_view padding,
                                                   RandomNumberGenerator& rng) :
            PK_Ops::Decryption_with_EME(padding), m_raw_decryptor(key, rng, "Raw") {}

      size_t plaintext_length(size_t ctext_len) const override { return m_raw_decryptor.plaintext_length(ctext_len); }

      secure_vector<uint8_t> raw_decrypt(const uint8_t input[], size_t input_len) override {
         return m_raw_decryptor.decrypt(input, input_len);
      }

   private:
      PK_Decryptor_EME m_raw_decryptor;
};

// note: multiple-part encryption operations (with C_EncryptUpdate/C_EncryptFinal)
// are not supported (PK_Ops::Encryption does not provide an `update` method)
class PKCS11_RSA_Encryption_Operation final : public PK_Ops::Encryption {
   public:
      PKCS11_RSA_Encryption_Operation(const PKCS11_RSA_PublicKey& key, std::string_view padding) :
            m_key(key), m_mechanism(MechanismWrapper::create_rsa_crypt_mechanism(padding)) {
         m_bits = 8 * (key.get_n().bytes() - m_mechanism.padding_size()) - 1;
      }

      size_t ciphertext_length(size_t /*ptext_len*/) const override { return m_key.get_n().bytes(); }

      size_t max_input_bits() const override { return m_bits; }

      secure_vector<uint8_t> encrypt(const uint8_t msg[], size_t msg_len, RandomNumberGenerator& /*rng*/) override {
         m_key.module()->C_EncryptInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());

         secure_vector<uint8_t> encrytped_data;
         m_key.module()->C_Encrypt(
            m_key.session().handle(), secure_vector<uint8_t>(msg, msg + msg_len), encrytped_data);
         return encrytped_data;
      }

   private:
      const PKCS11_RSA_PublicKey& m_key;
      MechanismWrapper m_mechanism;
      size_t m_bits = 0;
};

class PKCS11_RSA_Signature_Operation final : public PK_Ops::Signature {
   public:
      PKCS11_RSA_Signature_Operation(const PKCS11_RSA_PrivateKey& key, std::string_view padding) :
            m_key(key), m_mechanism(MechanismWrapper::create_rsa_sign_mechanism(padding)) {}

      size_t signature_length() const override { return m_key.get_n().bytes(); }

      void update(const uint8_t msg[], size_t msg_len) override {
         if(!m_initialized) {
            // first call to update: initialize and cache message because we can not determine yet whether a single- or multiple-part operation will be performed
            m_key.module()->C_SignInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
            m_initialized = true;
            m_first_message = secure_vector<uint8_t>(msg, msg + msg_len);
            return;
         }

         if(!m_first_message.empty()) {
            // second call to update: start multiple-part operation
            m_key.module()->C_SignUpdate(m_key.session().handle(), m_first_message);
            m_first_message.clear();
         }

         m_key.module()->C_SignUpdate(m_key.session().handle(), msg, static_cast<Ulong>(msg_len));
      }

      secure_vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
         secure_vector<uint8_t> signature;
         if(!m_first_message.empty()) {
            // single call to update: perform single-part operation
            m_key.module()->C_Sign(m_key.session().handle(), m_first_message, signature);
            m_first_message.clear();
         } else {
            // multiple calls to update (or none): finish multiple-part operation
            m_key.module()->C_SignFinal(m_key.session().handle(), signature);
         }
         m_initialized = false;
         return signature;
      }

      std::string hash_function() const override;

      AlgorithmIdentifier algorithm_identifier() const override;

   private:
      PKCS11_RSA_PrivateKey m_key;
      bool m_initialized = false;
      secure_vector<uint8_t> m_first_message;
      MechanismWrapper m_mechanism;
};

namespace {

std::string hash_function_name_from_pkcs11_rsa_mechanism_type(MechanismType type) {
   switch(type) {
      case MechanismType::Sha1RsaPkcs:
      case MechanismType::Sha1RsaPkcsPss:
      case MechanismType::Sha1RsaX931:
         return "SHA-1";

      case MechanismType::Sha224RsaPkcs:
      case MechanismType::Sha224RsaPkcsPss:
         return "SHA-224";

      case MechanismType::Sha256RsaPkcs:
      case MechanismType::Sha256RsaPkcsPss:
         return "SHA-256";

      case MechanismType::Sha384RsaPkcs:
      case MechanismType::Sha384RsaPkcsPss:
         return "SHA-384";

      case MechanismType::Sha512RsaPkcs:
      case MechanismType::Sha512RsaPkcsPss:
         return "SHA-512";

      case MechanismType::RsaX509:
      case MechanismType::RsaX931:
      case MechanismType::RsaPkcs:
      case MechanismType::RsaPkcsPss:
         return "Raw";

      default:
         throw Internal_Error("Unable to determine associated hash function of PKCS11 RSA signature operation");
   }
}

}  // namespace

std::string PKCS11_RSA_Signature_Operation::hash_function() const {
   return hash_function_name_from_pkcs11_rsa_mechanism_type(m_mechanism.mechanism_type());
}

AlgorithmIdentifier PKCS11_RSA_Signature_Operation::algorithm_identifier() const {
   const std::string hash = this->hash_function();

   switch(m_mechanism.mechanism_type()) {
      case MechanismType::Sha1RsaPkcs:
      case MechanismType::Sha224RsaPkcs:
      case MechanismType::Sha256RsaPkcs:
      case MechanismType::Sha384RsaPkcs:
      case MechanismType::Sha512RsaPkcs: {
         const OID oid = OID::from_string("RSA/EMSA3(" + hash + ")");
         return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_NULL_PARAM);
      }

      case MechanismType::Sha1RsaPkcsPss:
      case MechanismType::Sha224RsaPkcsPss:
      case MechanismType::Sha256RsaPkcsPss:
      case MechanismType::Sha384RsaPkcsPss:
      case MechanismType::Sha512RsaPkcsPss:
         throw Not_Implemented("RSA-PSS identifier encoding missing for PKCS11");

      default:
         throw Not_Implemented("No algorithm identifier defined for RSA with this PKCS11 mechanism");
   }
}

class PKCS11_RSA_Verification_Operation final : public PK_Ops::Verification {
   public:
      PKCS11_RSA_Verification_Operation(const PKCS11_RSA_PublicKey& key, std::string_view padding) :
            m_key(key), m_mechanism(MechanismWrapper::create_rsa_sign_mechanism(padding)) {}

      void update(const uint8_t msg[], size_t msg_len) override {
         if(!m_initialized) {
            // first call to update: initialize and cache message because we can not determine yet whether a single- or multiple-part operation will be performed
            m_key.module()->C_VerifyInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
            m_initialized = true;
            m_first_message = secure_vector<uint8_t>(msg, msg + msg_len);
            return;
         }

         if(!m_first_message.empty()) {
            // second call to update: start multiple-part operation
            m_key.module()->C_VerifyUpdate(m_key.session().handle(), m_first_message);
            m_first_message.clear();
         }

         m_key.module()->C_VerifyUpdate(m_key.session().handle(), msg, static_cast<Ulong>(msg_len));
      }

      bool is_valid_signature(const uint8_t sig[], size_t sig_len) override {
         ReturnValue return_value = ReturnValue::SignatureInvalid;
         if(!m_first_message.empty()) {
            // single call to update: perform single-part operation
            m_key.module()->C_Verify(m_key.session().handle(),
                                     m_first_message.data(),
                                     static_cast<Ulong>(m_first_message.size()),
                                     sig,
                                     static_cast<Ulong>(sig_len),
                                     &return_value);
            m_first_message.clear();
         } else {
            // multiple calls to update (or none): finish multiple-part operation
            m_key.module()->C_VerifyFinal(m_key.session().handle(), sig, static_cast<Ulong>(sig_len), &return_value);
         }
         m_initialized = false;
         if(return_value != ReturnValue::OK && return_value != ReturnValue::SignatureInvalid) {
            throw PKCS11_ReturnError(return_value);
         }
         return return_value == ReturnValue::OK;
      }

      std::string hash_function() const override;

   private:
      const PKCS11_RSA_PublicKey m_key;
      bool m_initialized = false;
      secure_vector<uint8_t> m_first_message;
      MechanismWrapper m_mechanism;
};

std::string PKCS11_RSA_Verification_Operation::hash_function() const {
   return hash_function_name_from_pkcs11_rsa_mechanism_type(m_mechanism.mechanism_type());
}

}  // namespace

std::unique_ptr<PK_Ops::Encryption> PKCS11_RSA_PublicKey::create_encryption_op(RandomNumberGenerator& /*rng*/,
                                                                               std::string_view params,
                                                                               std::string_view /*provider*/) const {
   return std::make_unique<PKCS11_RSA_Encryption_Operation>(*this, params);
}

std::unique_ptr<PK_Ops::Verification> PKCS11_RSA_PublicKey::create_verification_op(
   std::string_view params, std::string_view /*provider*/) const {
   return std::make_unique<PKCS11_RSA_Verification_Operation>(*this, params);
}

std::unique_ptr<PK_Ops::Decryption> PKCS11_RSA_PrivateKey::create_decryption_op(RandomNumberGenerator& rng,
                                                                                std::string_view params,
                                                                                std::string_view /*provider*/) const {
   if(params != "Raw" && m_use_software_padding) {
      return std::make_unique<PKCS11_RSA_Decryption_Operation_Software_EME>(*this, params, rng);
   } else {
      return std::make_unique<PKCS11_RSA_Decryption_Operation>(*this, params, rng);
   }
}

std::unique_ptr<PK_Ops::Signature> PKCS11_RSA_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                                                              std::string_view params,
                                                                              std::string_view /*provider*/) const {
   return std::make_unique<PKCS11_RSA_Signature_Operation>(*this, params);
}

PKCS11_RSA_KeyPair generate_rsa_keypair(Session& session,
                                        const RSA_PublicKeyGenerationProperties& pub_props,
                                        const RSA_PrivateKeyGenerationProperties& priv_props) {
   ObjectHandle pub_key_handle = 0;
   ObjectHandle priv_key_handle = 0;

   Mechanism mechanism = {static_cast<CK_MECHANISM_TYPE>(MechanismType::RsaPkcsKeyPairGen), nullptr, 0};

   session.module()->C_GenerateKeyPair(session.handle(),
                                       &mechanism,
                                       pub_props.data(),
                                       static_cast<Ulong>(pub_props.count()),
                                       priv_props.data(),
                                       static_cast<Ulong>(priv_props.count()),
                                       &pub_key_handle,
                                       &priv_key_handle);

   return std::make_pair(PKCS11_RSA_PublicKey(session, pub_key_handle),
                         PKCS11_RSA_PrivateKey(session, priv_key_handle));
}

}  // namespace Botan::PKCS11

#endif
