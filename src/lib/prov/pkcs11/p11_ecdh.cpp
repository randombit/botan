/*
* PKCS#11 ECDH
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_ecdh.h>

#if defined(BOTAN_HAS_ECDH)

   #include <botan/der_enc.h>
   #include <botan/ec_apoint.h>
   #include <botan/p11_mechanism.h>
   #include <botan/pk_ops.h>
   #include <botan/rng.h>
   #include <botan/internal/scoped_cleanup.h>

namespace Botan::PKCS11 {

ECDH_PublicKey PKCS11_ECDH_PublicKey::export_key() const {
   return ECDH_PublicKey(domain(), _public_ec_point());
}

ECDH_PrivateKey PKCS11_ECDH_PrivateKey::export_key() const {
   auto priv_key = get_attribute_value(AttributeType::Value);

   Null_RNG rng;
   return ECDH_PrivateKey(rng, domain(), BigInt::from_bytes(priv_key));
}

std::unique_ptr<Public_Key> PKCS11_ECDH_PrivateKey::public_key() const {
   return std::make_unique<ECDH_PublicKey>(domain(), public_ec_point());
}

secure_vector<uint8_t> PKCS11_ECDH_PrivateKey::private_key_bits() const {
   return export_key().private_key_bits();
}

namespace {
class PKCS11_ECDH_KA_Operation final : public PK_Ops::Key_Agreement {
   public:
      PKCS11_ECDH_KA_Operation(const PKCS11_ECDH_PrivateKey& key, std::string_view params) :
            PK_Ops::Key_Agreement(), m_key(key), m_mechanism(MechanismWrapper::create_ecdh_mechanism(params)) {}

      size_t agreed_value_size() const override { return m_key.domain().get_p_bytes(); }

      /// The encoding in V2.20 was not specified and resulted in different implementations choosing different encodings.
      /// Applications relying only on a V2.20 encoding (e.g. the DER variant) other than the one specified now (raw) may not work with all V2.30 compliant tokens.
      secure_vector<uint8_t> agree(size_t key_len,
                                   std::span<const uint8_t> other_key,
                                   std::span<const uint8_t> salt) override {
         const auto peer_point = EC_AffinePoint::deserialize(m_key.domain(), other_key);
         if(!peer_point) {
            throw Decoding_Error("ECDH - Invalid elliptic curve point: not on curve");
         }
         if(peer_point->is_identity()) {
            throw Decoding_Error("ECDH - Invalid elliptic curve point: identity");
         }

         std::vector<uint8_t> der_encoded_other_key;
         if(m_key.point_encoding() == PublicPointEncoding::Der) {
            DER_Encoder(der_encoded_other_key).encode(other_key.data(), other_key.size(), ASN1_Type::OctetString);
            m_mechanism.set_ecdh_other_key(der_encoded_other_key.data(), der_encoded_other_key.size());
         } else {
            m_mechanism.set_ecdh_other_key(other_key.data(), other_key.size());
         }

         const bool raw_kdf = (m_mechanism.ecdh_kdf() == KeyDerivation::Null);

         if(raw_kdf && !salt.empty()) {
            throw Invalid_Argument("PK_Key_Agreement::derive_key requires a KDF to use a salt");
         }

         if(salt.empty()) {
            m_mechanism.set_ecdh_salt(nullptr, 0);
         } else {
            m_mechanism.set_ecdh_salt(salt.data(), salt.size());
         }

         const size_t out_len = raw_kdf ? agreed_value_size() : key_len;

         ObjectHandle secret_handle = 0;
         AttributeContainer attributes;
         attributes.add_bool(AttributeType::Sensitive, false);
         attributes.add_bool(AttributeType::Extractable, true);
         attributes.add_numeric(AttributeType::Class, static_cast<CK_OBJECT_CLASS>(ObjectClass::SecretKey));
         attributes.add_numeric(AttributeType::KeyType, static_cast<CK_KEY_TYPE>(KeyType::GenericSecret));
         attributes.add_numeric(AttributeType::ValueLen, checked_ulong_cast(out_len));
         m_key.module()->C_DeriveKey(m_key.session().handle(),
                                     m_mechanism.data(),
                                     m_key.handle(),
                                     attributes.data(),
                                     checked_ulong_cast(attributes.count()),
                                     &secret_handle);

         const Object secret_object(m_key.session(), secret_handle);
         auto destroy_secret = scoped_cleanup([&]() noexcept {
            try {
               secret_object.destroy();
            } catch(...) {  // NOLINT(*-empty-catch)
            }
         });
         secure_vector<uint8_t> secret = secret_object.get_attribute_value(AttributeType::Value);
         if(secret.size() < out_len) {
            throw PKCS11_Error("ECDH key derivation secret length is too short");
         }
         secret.resize(out_len);
         return secret;
      }

   private:
      PKCS11_ECDH_PrivateKey m_key;
      MechanismWrapper m_mechanism;
};

}  // namespace

std::unique_ptr<PK_Ops::Key_Agreement> PKCS11_ECDH_PrivateKey::create_key_agreement_op(
   RandomNumberGenerator& /*rng*/, std::string_view params, std::string_view /*provider*/) const {
   return std::make_unique<PKCS11_ECDH_KA_Operation>(*this, params);
}

PKCS11_ECDH_KeyPair generate_ecdh_keypair(Session& session,
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

   return std::make_pair(PKCS11_ECDH_PublicKey(session, pub_key_handle),
                         PKCS11_ECDH_PrivateKey(session, priv_key_handle));
}

}  // namespace Botan::PKCS11

#endif
