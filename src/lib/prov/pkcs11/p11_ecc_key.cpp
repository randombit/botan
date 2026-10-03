/*
* PKCS#11 ECC
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_ecc_key.h>

#include <botan/pk_keys.h>

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)

   #include <botan/assert.h>
   #include <botan/ber_dec.h>
   #include <botan/internal/ec_key_data.h>
   #include <botan/internal/p11_object_guard.h>
   #include <botan/internal/workfactor.h>

namespace Botan::PKCS11 {

namespace {

/// Converts a DER-encoded ANSI X9.62 ECPoint to EC_Point
EC_AffinePoint decode_public_point(const EC_Group& group, std::span<const uint8_t> ec_point_data) {
   std::vector<uint8_t> ec_point;
   BER_Decoder(ec_point_data, BER_Decoder::Limits::DER()).decode(ec_point, ASN1_Type::OctetString).verify_end();
   // Throws if invalid
   return EC_AffinePoint(group, ec_point);
}

// Validate before creating the token object, so invalid input leaves nothing behind
const EC_PrivateKeyImportProperties& check_ec_params(const EC_PrivateKeyImportProperties& props) {
   const EC_Group group(props.ec_params());
   BOTAN_UNUSED(group);
   return props;  // NOLINT(*-return-const-ref-from-parameter)
}

}  // namespace

EC_PublicKeyGenerationProperties::EC_PublicKeyGenerationProperties(const std::vector<uint8_t>& ec_params) :
      PublicKeyProperties(KeyType::Ec), m_ec_params(ec_params) {
   add_binary(AttributeType::EcParams, m_ec_params);
}

EC_PublicKeyImportProperties::EC_PublicKeyImportProperties(const std::vector<uint8_t>& ec_params,
                                                           const std::vector<uint8_t>& ec_point) :
      PublicKeyProperties(KeyType::Ec), m_ec_params(ec_params), m_ec_point(ec_point) {
   add_binary(AttributeType::EcParams, m_ec_params);
   add_binary(AttributeType::EcPoint, m_ec_point);
}

PKCS11_EC_PublicKey::PKCS11_EC_PublicKey(Session& session, ObjectHandle handle) : Object(session, handle) {
   auto ec_parameters = get_attribute_value(AttributeType::EcParams);
   auto pt_bytes = get_attribute_value(AttributeType::EcPoint);

   EC_Group group(ec_parameters);
   auto pt = decode_public_point(group, pt_bytes);
   m_public_key = std::make_shared<EC_PublicKey_Data>(std::move(group), std::move(pt));
}

PKCS11_EC_PublicKey::PKCS11_EC_PublicKey(Session& session, const EC_PublicKeyImportProperties& props) :
      Object(session, props) {
   Object_Creation_Guard guard(session, {handle()});
   EC_Group group(props.ec_params());
   auto pt = decode_public_point(group, props.ec_point());
   m_public_key = std::make_shared<EC_PublicKey_Data>(std::move(group), std::move(pt));
   guard.release();
}

EC_PrivateKeyImportProperties::EC_PrivateKeyImportProperties(const std::vector<uint8_t>& ec_params,
                                                             const BigInt& value) :
      PrivateKeyProperties(KeyType::Ec), m_ec_params(ec_params), m_value(value) {
   add_binary(AttributeType::EcParams, m_ec_params);
   add_binary(AttributeType::Value, m_value.serialize());
}

PKCS11_EC_PrivateKey::PKCS11_EC_PrivateKey(Session& session, ObjectHandle handle) :
      Object(session, handle), m_domain_params(get_attribute_value(AttributeType::EcParams)) {}

PKCS11_EC_PrivateKey::PKCS11_EC_PrivateKey(Session& session, const EC_PrivateKeyImportProperties& props) :
      Object(session, check_ec_params(props)), m_domain_params(EC_Group(props.ec_params())) {}

PKCS11_EC_PrivateKey::PKCS11_EC_PrivateKey(Session& session,
                                           const std::vector<uint8_t>& ec_params,
                                           const EC_PrivateKeyGenerationProperties& props) :
      Object(session), m_domain_params(ec_params) {
   EC_PublicKeyGenerationProperties pub_key_props(ec_params);
   pub_key_props.set_verify(true);
   pub_key_props.set_private(false);
   pub_key_props.set_token(false);  // don't create a persistent public key object

   ObjectHandle pub_key_handle = CK_INVALID_HANDLE;
   ObjectHandle priv_key_handle = CK_INVALID_HANDLE;
   const Mechanism mechanism = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
   session.module()->C_GenerateKeyPair(session.handle(),
                                       &mechanism,
                                       pub_key_props.data(),
                                       checked_ulong_cast(pub_key_props.count()),
                                       props.data(),
                                       checked_ulong_cast(props.count()),
                                       &pub_key_handle,
                                       &priv_key_handle);

   // The public key object is only needed temporarily
   const Object_Creation_Guard destroy_public(session, {pub_key_handle});
   Object_Creation_Guard guard(session, {priv_key_handle});

   this->reset_handle(priv_key_handle);
   const Object public_key(session, pub_key_handle);

   auto pt_bytes = public_key.get_attribute_value(AttributeType::EcPoint);
   m_public_key = decode_public_point(m_domain_params, pt_bytes);
   guard.release();
}

size_t PKCS11_EC_PrivateKey::key_length() const {
   return m_domain_params.get_order_bits();
}

std::vector<uint8_t> PKCS11_EC_PrivateKey::raw_public_key_bits() const {
   // Matches the default of software EC keys, and public_value() for ECDH
   return public_ec_point().serialize_uncompressed();
}

std::vector<uint8_t> PKCS11_EC_PrivateKey::public_key_bits() const {
   return raw_public_key_bits();
}

size_t PKCS11_EC_PrivateKey::estimated_strength() const {
   return ecp_work_factor(key_length());
}

bool PKCS11_EC_PrivateKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   return true;
}

AlgorithmIdentifier PKCS11_EC_PrivateKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), domain().DER_encode());
}
}  // namespace Botan::PKCS11

#endif
