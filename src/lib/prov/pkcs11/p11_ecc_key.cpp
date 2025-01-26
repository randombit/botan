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

   #include <botan/ber_dec.h>
   #include <botan/internal/ec_key_data.h>
   #include <botan/internal/workfactor.h>

namespace Botan::PKCS11 {

namespace {

/// Converts a DER-encoded ANSI X9.62 ECPoint to EC_Point
EC_AffinePoint decode_public_point(const EC_Group& group, std::span<const uint8_t> ec_point_data) {
   std::vector<uint8_t> ec_point;
   BER_Decoder(ec_point_data).decode(ec_point, ASN1_Type::OctetString);
   // Throws if invalid
   return EC_AffinePoint(group, ec_point);
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
   EC_Group group(props.ec_params());
   auto pt = decode_public_point(group, props.ec_point());
   m_public_key = std::make_shared<EC_PublicKey_Data>(std::move(group), std::move(pt));
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
      Object(session, props), m_domain_params(EC_Group(props.ec_params())) {}

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
   Mechanism mechanism = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
   session.module()->C_GenerateKeyPair(session.handle(),
                                       &mechanism,
                                       pub_key_props.data(),
                                       static_cast<Ulong>(pub_key_props.count()),
                                       props.data(),
                                       static_cast<Ulong>(props.count()),
                                       &pub_key_handle,
                                       &priv_key_handle);

   this->reset_handle(priv_key_handle);
   Object public_key(session, pub_key_handle);

   auto pt_bytes = public_key.get_attribute_value(AttributeType::EcPoint);
   m_public_key = decode_public_point(m_domain_params, pt_bytes);
}

size_t PKCS11_EC_PrivateKey::key_length() const {
   return m_domain_params.get_order_bits();
}

std::vector<uint8_t> PKCS11_EC_PrivateKey::raw_public_key_bits() const {
   return public_ec_point().serialize_compressed();
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
