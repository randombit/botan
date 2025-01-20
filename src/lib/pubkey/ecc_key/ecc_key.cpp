/*
* ECC Key implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*          Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ecc_key.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/secmem.h>
#include <botan/internal/ec_key_data.h>
#include <botan/internal/fmt.h>
#include <botan/internal/workfactor.h>

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
   #include <botan/ec_point.h>
#endif

namespace Botan {

size_t EC_PublicKey::key_length() const {
   return domain().get_p_bits();
}

size_t EC_PublicKey::estimated_strength() const {
   return ecp_work_factor(key_length());
}

namespace {

EC_Group_Encoding default_encoding_for(const EC_Group& group) {
   if(group.get_curve_oid().empty()) {
      return EC_Group_Encoding::Explicit;
   } else {
      return EC_Group_Encoding::NamedCurve;
   }
}

}  // namespace

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
EC_PublicKey::EC_PublicKey(EC_Group group, const EC_Point& pub_point) {
   auto pt = EC_AffinePoint(group, pub_point);
   m_public_key = std::make_shared<const EC_PublicKey_Data>(std::move(group), std::move(pt));
   m_domain_encoding = default_encoding_for(domain());
}
#endif

EC_PublicKey::EC_PublicKey(EC_Group group, EC_AffinePoint pub_point) {
   m_public_key = std::make_shared<const EC_PublicKey_Data>(std::move(group), std::move(pub_point));
   m_domain_encoding = default_encoding_for(domain());
}

EC_PublicKey::EC_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   m_public_key = std::make_shared<const EC_PublicKey_Data>(EC_Group(alg_id.parameters()), key_bits);
   m_domain_encoding = default_encoding_for(domain());
}

const EC_Group& EC_PublicKey::domain() const {
   BOTAN_STATE_CHECK(m_public_key != nullptr);
   return m_public_key->group();
}

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
const EC_Point& EC_PublicKey::public_point() const {
   BOTAN_STATE_CHECK(m_public_key != nullptr);
   return m_public_key->legacy_point();
}
#endif

const EC_AffinePoint& EC_PublicKey::_public_ec_point() const {
   BOTAN_STATE_CHECK(m_public_key != nullptr);
   return m_public_key->public_key();
}

bool EC_PublicKey::check_key(RandomNumberGenerator& rng, bool /*strong*/) const {
   // We already checked when deserializing that the point was on the curve
   return domain().verify_group(rng) && !_public_ec_point().is_identity();
}

AlgorithmIdentifier EC_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), DER_domain());
}

std::vector<uint8_t> EC_PublicKey::raw_public_key_bits() const {
   return _public_ec_point().serialize(point_encoding());
}

std::vector<uint8_t> EC_PublicKey::public_key_bits() const {
   return raw_public_key_bits();
}

std::vector<uint8_t> EC_PublicKey::DER_domain() const {
   return domain().DER_encode(domain_format());
}

void EC_PublicKey::set_point_encoding(EC_Point_Format enc) {
   if(enc != EC_Point_Format::Compressed && enc != EC_Point_Format::Uncompressed && enc != EC_Point_Format::Hybrid) {
      throw Invalid_Argument("Invalid point encoding for EC_PublicKey");
   }

   m_point_encoding = enc;
}

void EC_PublicKey::set_parameter_encoding(EC_Group_Encoding form) {
   if(form == EC_Group_Encoding::NamedCurve && domain().get_curve_oid().empty()) {
      throw Invalid_Argument("Cannot used NamedCurve encoding for a curve without an OID");
   }

   m_domain_encoding = form;
}

const BigInt& EC_PrivateKey::private_value() const {
   BOTAN_STATE_CHECK(m_private_key != nullptr);
   return m_private_key->legacy_bigint();
}

const EC_Scalar& EC_PrivateKey::_private_key() const {
   BOTAN_STATE_CHECK(m_private_key != nullptr);
   return m_private_key->private_key();
}

/**
* EC_PrivateKey constructor
*/
EC_PrivateKey::EC_PrivateKey(RandomNumberGenerator& rng,
                             EC_Group ec_group,
                             const BigInt& x,
                             bool with_modular_inverse) {
   auto scalar = (x.is_zero()) ? EC_Scalar::random(ec_group, rng) : EC_Scalar::from_bigint(ec_group, x);
   m_private_key = std::make_shared<EC_PrivateKey_Data>(std::move(ec_group), std::move(scalar));
   m_public_key = m_private_key->public_key(rng, with_modular_inverse);
   m_domain_encoding = default_encoding_for(domain());
}

EC_PrivateKey::EC_PrivateKey(RandomNumberGenerator& rng, EC_Group ec_group, bool with_modular_inverse) {
   auto scalar = EC_Scalar::random(ec_group, rng);
   m_private_key = std::make_shared<EC_PrivateKey_Data>(std::move(ec_group), std::move(scalar));
   m_public_key = m_private_key->public_key(rng, with_modular_inverse);
   m_domain_encoding = default_encoding_for(domain());
}

EC_PrivateKey::EC_PrivateKey(EC_Group ec_group, EC_Scalar x, bool with_modular_inverse) {
   m_private_key = std::make_shared<EC_PrivateKey_Data>(std::move(ec_group), std::move(x));
   m_public_key = m_private_key->public_key(with_modular_inverse);
   m_domain_encoding = default_encoding_for(domain());
}

secure_vector<uint8_t> EC_PrivateKey::raw_private_key_bits() const {
   BOTAN_STATE_CHECK(m_private_key != nullptr);
   return m_private_key->serialize<secure_vector<uint8_t>>();
}

secure_vector<uint8_t> EC_PrivateKey::private_key_bits() const {
   BOTAN_STATE_CHECK(m_private_key != nullptr && m_public_key != nullptr);

   return DER_Encoder()
      .start_sequence()
      .encode(static_cast<size_t>(1))
      .encode(raw_private_key_bits(), ASN1_Type::OctetString)
      .start_explicit_context_specific(1)
      .encode(m_public_key->public_key().serialize_uncompressed(), ASN1_Type::BitString)
      .end_cons()
      .end_cons()
      .get_contents();
}

EC_PrivateKey::EC_PrivateKey(const AlgorithmIdentifier& alg_id,
                             std::span<const uint8_t> key_bits,
                             bool with_modular_inverse) {
   EC_Group group(alg_id.parameters());

   OID key_parameters;
   secure_vector<uint8_t> private_key_bits;
   secure_vector<uint8_t> public_key_bits;

   BER_Decoder(key_bits)
      .start_sequence()
      .decode_and_check<size_t>(1, "Unknown version code for ECC key")
      .decode(private_key_bits, ASN1_Type::OctetString)
      .decode_optional(key_parameters, ASN1_Type(0), ASN1_Class::ExplicitContextSpecific)
      .decode_optional_string(public_key_bits, ASN1_Type::BitString, 1, ASN1_Class::ExplicitContextSpecific)
      .end_cons();

   m_private_key = std::make_shared<EC_PrivateKey_Data>(group, private_key_bits);

   if(public_key_bits.empty()) {
      m_public_key = m_private_key->public_key(with_modular_inverse);
   } else {
      m_public_key = std::make_shared<EC_PublicKey_Data>(group, public_key_bits);
   }

   m_domain_encoding = default_encoding_for(domain());
}

bool EC_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(!m_private_key) {
      return false;
   }

   return EC_PublicKey::check_key(rng, strong);
}

const BigInt& EC_PublicKey::get_int_field(std::string_view field) const {
   if(field == "public_x" || field == "public_y") {
      throw Not_Implemented(fmt("EC_PublicKey::get_int_field no longer implements getter for {}", field));
   } else if(field == "base_x") {
      return this->domain().get_g_x();
   } else if(field == "base_y") {
      return this->domain().get_g_y();
   } else if(field == "p") {
      return this->domain().get_p();
   } else if(field == "a") {
      return this->domain().get_a();
   } else if(field == "b") {
      return this->domain().get_b();
   } else if(field == "cofactor") {
      return this->domain().get_cofactor();
   } else if(field == "order") {
      return this->domain().get_order();
   } else {
      return Public_Key::get_int_field(field);
   }
}

const BigInt& EC_PrivateKey::get_int_field(std::string_view field) const {
   if(field == "x") {
      return this->private_value();
   } else {
      return EC_PublicKey::get_int_field(field);
   }
}

}  // namespace Botan
