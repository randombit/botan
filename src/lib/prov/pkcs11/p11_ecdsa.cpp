/*
* PKCS#11 ECDSA
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_ecdsa.h>

#if defined(BOTAN_HAS_ECDSA)

   #include <botan/pk_ops.h>
   #include <botan/pk_options.h>
   #include <botan/rng.h>
   #include <botan/internal/keypair.h>
   #include <botan/internal/p11_mechanism.h>

namespace Botan::PKCS11 {

ECDSA_PublicKey PKCS11_ECDSA_PublicKey::export_key() const {
   return ECDSA_PublicKey(domain(), public_point());
}

bool PKCS11_ECDSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(!public_point().on_the_curve()) {
      return false;
   }

   if(!strong) {
      return true;
   }

   ECDSA_PublicKey pubkey(domain(), public_point());
   return KeyPair::signature_consistency_check(rng, *this, pubkey, "SHA-256");
}

ECDSA_PrivateKey PKCS11_ECDSA_PrivateKey::export_key() const {
   auto priv_key = get_attribute_value(AttributeType::Value);

   Null_RNG rng;
   return ECDSA_PrivateKey(rng, domain(), BigInt::from_bytes(priv_key));
}

secure_vector<uint8_t> PKCS11_ECDSA_PrivateKey::private_key_bits() const {
   return export_key().private_key_bits();
}

std::unique_ptr<Public_Key> PKCS11_ECDSA_PrivateKey::public_key() const {
   return std::make_unique<ECDSA_PublicKey>(domain(), public_point());
}

namespace {

class PKCS11_ECDSA_Signature_Operation final : public PK_Ops::Signature {
   public:
      PKCS11_ECDSA_Signature_Operation(const PKCS11_ECDSA_PrivateKey& key, const PK_Signature_Options& options) :
            PK_Ops::Signature(),
            m_key(key),
            m_order_bytes(key.domain().get_order_bytes()),
            m_mechanism(MechanismWrapper::create_ecdsa_mechanism(options.hash_function())),
            m_hash(options.hash_function()) {}

      void update(std::span<const uint8_t> input) override {
         if(!m_initialized) {
            // first call to update: initialize and cache message because we can not determine yet whether a single- or multiple-part operation will be performed
            m_key.module()->C_SignInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
            m_initialized = true;
            m_first_message.assign(input.begin(), input.end());
            return;
         }

         if(!m_first_message.empty()) {
            // second call to update: start multiple-part operation
            m_key.module()->C_SignUpdate(m_key.session().handle(), m_first_message);
            m_first_message.clear();
         }

         m_key.module()->C_SignUpdate(m_key.session().handle(), input.data(), static_cast<Ulong>(input.size()));
      }

      std::vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
         std::vector<uint8_t> signature;
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

      size_t signature_length() const override { return 2 * m_order_bytes; }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return m_hash; }

   private:
      const PKCS11_ECDSA_PrivateKey m_key;
      const size_t m_order_bytes;
      MechanismWrapper m_mechanism;
      const std::string m_hash;
      secure_vector<uint8_t> m_first_message;
      bool m_initialized = false;
};

AlgorithmIdentifier PKCS11_ECDSA_Signature_Operation::algorithm_identifier() const {
   const std::string full_name = "ECDSA/" + hash_function();
   const OID oid = OID::from_string(full_name);
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
}

class PKCS11_ECDSA_Verification_Operation final : public PK_Ops::Verification {
   public:
      PKCS11_ECDSA_Verification_Operation(const PKCS11_ECDSA_PublicKey& key, std::string_view hash) :
            PK_Ops::Verification(),
            m_key(key),
            m_mechanism(MechanismWrapper::create_ecdsa_mechanism(hash)),
            m_hash(hash) {}

      void update(std::span<const uint8_t> input) override {
         if(!m_initialized) {
            // first call to update: initialize and cache message because we can not determine yet whether a single- or multiple-part operation will be performed
            m_key.module()->C_VerifyInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
            m_initialized = true;
            m_first_message.assign(input.begin(), input.end());
            return;
         }

         if(!m_first_message.empty()) {
            // second call to update: start multiple-part operation
            m_key.module()->C_VerifyUpdate(m_key.session().handle(), m_first_message);
            m_first_message.clear();
         }

         m_key.module()->C_VerifyUpdate(m_key.session().handle(), input.data(), static_cast<Ulong>(input.size()));
      }

      bool is_valid_signature(std::span<const uint8_t> sig) override {
         ReturnValue return_value = ReturnValue::SignatureInvalid;
         if(!m_first_message.empty()) {
            // single call to update: perform single-part operation
            m_key.module()->C_Verify(m_key.session().handle(),
                                     m_first_message.data(),
                                     static_cast<Ulong>(m_first_message.size()),
                                     sig.data(),
                                     static_cast<Ulong>(sig.size()),
                                     &return_value);
            m_first_message.clear();
         } else {
            // multiple calls to update (or none): finish multiple-part operation
            m_key.module()->C_VerifyFinal(
               m_key.session().handle(), sig.data(), static_cast<Ulong>(sig.size()), &return_value);
         }
         m_initialized = false;
         if(return_value != ReturnValue::OK && return_value != ReturnValue::SignatureInvalid) {
            throw PKCS11_ReturnError(return_value);
         }
         return return_value == ReturnValue::OK;
      }

      std::string hash_function() const override { return m_hash; }

   private:
      const PKCS11_ECDSA_PublicKey m_key;
      MechanismWrapper m_mechanism;
      const std::string m_hash;
      secure_vector<uint8_t> m_first_message;
      bool m_initialized = false;
};

}  // namespace

std::unique_ptr<PK_Ops::Verification> PKCS11_ECDSA_PublicKey::create_verification_op(
   std::string_view params, std::string_view /*provider*/) const {
   return std::make_unique<PKCS11_ECDSA_Verification_Operation>(*this, params);
}

std::unique_ptr<PK_Ops::Signature> PKCS11_ECDSA_PrivateKey::_create_signature_op(
   RandomNumberGenerator& rng, const PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);
   return std::make_unique<PKCS11_ECDSA_Signature_Operation>(*this, options);
}

PKCS11_ECDSA_KeyPair generate_ecdsa_keypair(Session& session,
                                            const EC_PublicKeyGenerationProperties& pub_props,
                                            const EC_PrivateKeyGenerationProperties& priv_props) {
   ObjectHandle pub_key_handle = 0;
   ObjectHandle priv_key_handle = 0;

   Mechanism mechanism = {static_cast<CK_MECHANISM_TYPE>(MechanismType::EcKeyPairGen), nullptr, 0};

   session.module()->C_GenerateKeyPair(session.handle(),
                                       &mechanism,
                                       pub_props.data(),
                                       static_cast<Ulong>(pub_props.count()),
                                       priv_props.data(),
                                       static_cast<Ulong>(priv_props.count()),
                                       &pub_key_handle,
                                       &priv_key_handle);

   return std::make_pair(PKCS11_ECDSA_PublicKey(session, pub_key_handle),
                         PKCS11_ECDSA_PrivateKey(session, priv_key_handle));
}

}  // namespace Botan::PKCS11

#endif
