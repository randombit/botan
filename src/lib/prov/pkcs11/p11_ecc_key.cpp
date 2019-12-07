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

#include <botan/workfactor.h>
#include <botan/ber_dec.h>

namespace Botan {
namespace PKCS11 {
namespace {
/// Converts a DER-encoded ANSI X9.62 ECPoint to PointGFp
PointGFp decode_public_point(const secure_vector<uint8_t>& ec_point_data, const EC_Group& group)
   {
   secure_vector<uint8_t> ec_point;
   BER_Decoder(ec_point_data).decode(ec_point, OCTET_STRING);
   return group.OS2ECP(ec_point);
   }
}

EC_PublicKeyGenerationProperties::EC_PublicKeyGenerationProperties(const std::vector<uint8_t>& ec_params)
   : PublicKeyProperties(KeyType::Ec), m_ec_params(ec_params)
   {
   add_binary(AttributeType::EcParams, m_ec_params);
   }

EC_PublicKeyImportProperties::EC_PublicKeyImportProperties(const std::vector<uint8_t>& ec_params,
      const std::vector<uint8_t>& ec_point)
   : PublicKeyProperties(KeyType::Ec), m_ec_params(ec_params), m_ec_point(ec_point)
   {
   add_binary(AttributeType::EcParams, m_ec_params);
   add_binary(AttributeType::EcPoint, m_ec_point);
   }

PKCS11_EC_PublicKey::PKCS11_EC_PublicKey(Session& session, ObjectHandle handle)
   : Object(session, handle)
   {
   secure_vector<uint8_t> ec_parameters = get_attribute_value(AttributeType::EcParams);
   m_domain_params = EC_Group(unlock(ec_parameters));
   m_public_key = decode_public_point(get_attribute_value(AttributeType::EcPoint), m_domain_params);
   m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
   }

PKCS11_EC_PublicKey::PKCS11_EC_PublicKey(Session& session, const EC_PublicKeyImportProperties& props)
   : Object(session, props)
   {
   m_domain_params = EC_Group(props.ec_params());

   secure_vector<uint8_t> ec_point;
   BER_Decoder(props.ec_point()).decode(ec_point, OCTET_STRING);
   m_public_key = m_domain_params.OS2ECP(ec_point);
   m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
   }

EC_PrivateKeyImportProperties::EC_PrivateKeyImportProperties(const std::vector<uint8_t>& ec_params, const BigInt& value)
   : PrivateKeyProperties(KeyType::Ec), m_ec_params(ec_params), m_value(value)
   {
   add_binary(AttributeType::EcParams, m_ec_params);
   add_binary(AttributeType::Value, BigInt::encode(m_value));
   }

PKCS11_EC_PrivateKey::PKCS11_EC_PrivateKey(Session& session, ObjectHandle handle)
   : Object(session, handle), m_domain_params(), m_public_key()
   {
   secure_vector<uint8_t> ec_parameters = get_attribute_value(AttributeType::EcParams);
   m_domain_params = EC_Group(unlock(ec_parameters));
   }

PKCS11_EC_PrivateKey::PKCS11_EC_PrivateKey(Session& session, const EC_PrivateKeyImportProperties& props)
   : Object(session, props)
   {
   m_domain_params = EC_Group(props.ec_params());
   }

PKCS11_EC_PrivateKey::PKCS11_EC_PrivateKey(Session& session, const std::vector<uint8_t>& ec_params,
      const EC_PrivateKeyGenerationProperties& props)
   : Object(session)
   {
   m_domain_params = EC_Group(ec_params);

   EC_PublicKeyGenerationProperties pub_key_props(ec_params);
   pub_key_props.set_verify(true);
   pub_key_props.set_private(false);
   pub_key_props.set_token(false);    // don't create a persistent public key object

   ObjectHandle pub_key_handle = CK_INVALID_HANDLE;
   ObjectHandle priv_key_handle = CK_INVALID_HANDLE;
   Mechanism mechanism = { CKM_EC_KEY_PAIR_GEN, nullptr, 0 };
   session.module()->C_GenerateKeyPair(session.handle(), &mechanism,
                                       pub_key_props.data(), static_cast<Ulong>(pub_key_props.count()),
                                       props.data(), static_cast<Ulong>(props.count()),
                                       &pub_key_handle, &priv_key_handle);

   this->reset_handle(priv_key_handle);

   Object public_key(session, pub_key_handle);
   m_public_key = decode_public_point(public_key.get_attribute_value(AttributeType::EcPoint), m_domain_params);
   }

size_t PKCS11_EC_PrivateKey::key_length() const
   {
   return m_domain_params.get_order().bits();
   }

std::vector<uint8_t> PKCS11_EC_PrivateKey::public_key_bits() const
   {
   return public_point().encode(PointGFp::COMPRESSED);
   }

size_t PKCS11_EC_PrivateKey::estimated_strength() const
   {
   return ecp_work_factor(key_length());
   }

bool PKCS11_EC_PrivateKey::check_key(RandomNumberGenerator&, bool) const
   {
   return m_public_key.on_the_curve();
   }

AlgorithmIdentifier PKCS11_EC_PrivateKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(), domain().DER_encode(EC_DOMPAR_ENC_EXPLICIT));
   }
}

}

#endif
