/*
* PKCS#11 ECDSA
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_ecdsa.h>

#if defined(BOTAN_HAS_ECDSA)

   #include <botan/p11_mechanism.h>
   #include <botan/pk_ops.h>
   #include <botan/rng.h>
   #include <botan/internal/keypair.h>
   #include <botan/internal/scan_name.h>

namespace Botan::PKCS11 {

ECDSA_PublicKey PKCS11_ECDSA_PublicKey::export_key() const {
   return ECDSA_PublicKey(domain(), _public_ec_point());
}

bool PKCS11_ECDSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(!strong) {
      return true;
   }

   const ECDSA_PublicKey pubkey(domain(), public_ec_point());
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
   return std::make_unique<ECDSA_PublicKey>(domain(), public_ec_point());
}

namespace {

// PKCS#11 ECDSA accepts EMSA1(X) as an alias for X; unwrap so callers like
// algorithm_identifier() see the normalized hash name (e.g. "SHA-256" instead
// of "EMSA1(SHA-256)") and produce a registered OID such as ECDSA/SHA-256.
std::string canonical_ecdsa_hash(std::string_view hash) {
   const SCAN_Name req((std::string(hash)));
   if(req.algo_name() == "EMSA1" && req.arg_count() == 1) {
      return req.arg(0);
   }
   return std::string(hash);
}

class PKCS11_ECDSA_Signature_Operation final : public PK_Ops::Signature {
   public:
      PKCS11_ECDSA_Signature_Operation(const PKCS11_ECDSA_PrivateKey& key, std::string_view hash) :
            PK_Ops::Signature(),
            m_key(key),
            m_order_bytes(key.domain().get_order_bytes()),
            m_mechanism(MechanismWrapper::create_ecdsa_mechanism(hash)),
            m_hash(canonical_ecdsa_hash(hash)) {}

      void update(std::span<const uint8_t> input) override {
         if(!m_initialized) {
            // first call to update: initialize and cache message because we can not determine yet whether a single- or multiple-part operation will be performed
            m_key.module()->C_SignInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
            m_initialized = true;
            m_first_message.assign(input.begin(), input.end());
            m_has_first_message = true;
            return;
         }

         if(m_has_first_message) {
            // second call to update: start multiple-part operation
            m_key.module()->C_SignUpdate(m_key.session().handle(), m_first_message);
            m_first_message.clear();
            m_has_first_message = false;
         }

         m_key.module()->C_SignUpdate(m_key.session().handle(), input.data(), checked_ulong_cast(input.size()));
      }

      std::vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
         if(!m_initialized) {
            // sign() called with no prior update(): treat as a single-part operation over the empty message
            m_key.module()->C_SignInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
            m_initialized = true;
            m_has_first_message = true;
         }
         std::vector<uint8_t> signature;
         if(m_has_first_message) {
            // single call to update: perform single-part operation
            m_key.module()->C_Sign(m_key.session().handle(), m_first_message, signature);
            m_first_message.clear();
            m_has_first_message = false;
         } else {
            // multiple calls to update: finish multiple-part operation
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
      bool m_has_first_message = false;
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
            m_hash(canonical_ecdsa_hash(hash)) {}

      void update(std::span<const uint8_t> input) override {
         if(!m_initialized) {
            // first call to update: initialize and cache message because we can not determine yet whether a single- or multiple-part operation will be performed
            m_key.module()->C_VerifyInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
            m_initialized = true;
            m_first_message.assign(input.begin(), input.end());
            m_has_first_message = true;
            return;
         }

         if(m_has_first_message) {
            // second call to update: start multiple-part operation
            m_key.module()->C_VerifyUpdate(m_key.session().handle(), m_first_message);
            m_first_message.clear();
            m_has_first_message = false;
         }

         m_key.module()->C_VerifyUpdate(m_key.session().handle(), input.data(), checked_ulong_cast(input.size()));
      }

      bool is_valid_signature(std::span<const uint8_t> sig) override {
         if(!m_initialized) {
            // is_valid_signature() called with no prior update(): treat as a single-part operation over the empty message
            m_key.module()->C_VerifyInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
            m_initialized = true;
            m_has_first_message = true;
         }
         ReturnValue return_value = ReturnValue::SignatureInvalid;
         if(m_has_first_message) {
            // single call to update: perform single-part operation
            m_key.module()->C_Verify(m_key.session().handle(),
                                     m_first_message.data(),
                                     checked_ulong_cast(m_first_message.size()),
                                     sig.data(),
                                     checked_ulong_cast(sig.size()),
                                     &return_value);
            m_first_message.clear();
            m_has_first_message = false;
         } else {
            // multiple calls to update: finish multiple-part operation
            m_key.module()->C_VerifyFinal(
               m_key.session().handle(), sig.data(), checked_ulong_cast(sig.size()), &return_value);
         }
         m_initialized = false;
         if(return_value == ReturnValue::SignatureInvalid || return_value == ReturnValue::SignatureLenRange) {
            return false;
         } else if(return_value == ReturnValue::OK) {
            return true;
         } else {
            throw PKCS11_ReturnError(return_value);
         }
      }

      std::string hash_function() const override { return m_hash; }

   private:
      const PKCS11_ECDSA_PublicKey m_key;
      MechanismWrapper m_mechanism;
      const std::string m_hash;
      secure_vector<uint8_t> m_first_message;
      bool m_initialized = false;
      bool m_has_first_message = false;
};

}  // namespace

std::unique_ptr<PK_Ops::Verification> PKCS11_ECDSA_PublicKey::create_verification_op(
   std::string_view params, std::string_view /*provider*/) const {
   return std::make_unique<PKCS11_ECDSA_Verification_Operation>(*this, params);
}

std::unique_ptr<PK_Ops::Signature> PKCS11_ECDSA_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                                                                std::string_view params,
                                                                                std::string_view /*provider*/) const {
   return std::make_unique<PKCS11_ECDSA_Signature_Operation>(*this, params);
}

PKCS11_ECDSA_KeyPair generate_ecdsa_keypair(Session& session,
                                            const EC_PublicKeyGenerationProperties& pub_props,
                                            const EC_PrivateKeyGenerationProperties& priv_props) {
   ObjectHandle pub_key_handle = 0;
   ObjectHandle priv_key_handle = 0;

   const Mechanism mechanism = {static_cast<CK_MECHANISM_TYPE>(MechanismType::EcKeyPairGen), nullptr, 0};

   session.module()->C_GenerateKeyPair(session.handle(),
                                       &mechanism,
                                       pub_props.data(),
                                       checked_ulong_cast(pub_props.count()),
                                       priv_props.data(),
                                       checked_ulong_cast(priv_props.count()),
                                       &pub_key_handle,
                                       &priv_key_handle);

   return std::make_pair(PKCS11_ECDSA_PublicKey(session, pub_key_handle),
                         PKCS11_ECDSA_PrivateKey(session, priv_key_handle));
}

}  // namespace Botan::PKCS11

#endif
