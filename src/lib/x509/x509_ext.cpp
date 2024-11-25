/*
* X.509 Certificate Extensions
* (C) 1999-2010,2012 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
* (C) 2017 Fabian Weissberg, Rohde & Schwarz Cybersecurity
* (C) 2024 Anton Einax, Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_ext.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/x509cert.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <algorithm>
#include <set>
#include <sstream>

namespace Botan {

namespace {

std::unique_ptr<Certificate_Extension> extension_from_oid(const OID& oid) {
   if(oid == Cert_Extension::Subject_Key_ID::static_oid()) {
      return std::make_unique<Cert_Extension::Subject_Key_ID>();
   }

   if(oid == Cert_Extension::Key_Usage::static_oid()) {
      return std::make_unique<Cert_Extension::Key_Usage>();
   }

   if(oid == Cert_Extension::Subject_Alternative_Name::static_oid()) {
      return std::make_unique<Cert_Extension::Subject_Alternative_Name>();
   }

   if(oid == Cert_Extension::Issuer_Alternative_Name::static_oid()) {
      return std::make_unique<Cert_Extension::Issuer_Alternative_Name>();
   }

   if(oid == Cert_Extension::Basic_Constraints::static_oid()) {
      return std::make_unique<Cert_Extension::Basic_Constraints>();
   }

   if(oid == Cert_Extension::CRL_Number::static_oid()) {
      return std::make_unique<Cert_Extension::CRL_Number>();
   }

   if(oid == Cert_Extension::CRL_ReasonCode::static_oid()) {
      return std::make_unique<Cert_Extension::CRL_ReasonCode>();
   }

   if(oid == Cert_Extension::Authority_Key_ID::static_oid()) {
      return std::make_unique<Cert_Extension::Authority_Key_ID>();
   }

   if(oid == Cert_Extension::Name_Constraints::static_oid()) {
      return std::make_unique<Cert_Extension::Name_Constraints>();
   }

   if(oid == Cert_Extension::CRL_Distribution_Points::static_oid()) {
      return std::make_unique<Cert_Extension::CRL_Distribution_Points>();
   }

   if(oid == Cert_Extension::CRL_Issuing_Distribution_Point::static_oid()) {
      return std::make_unique<Cert_Extension::CRL_Issuing_Distribution_Point>();
   }

   if(oid == Cert_Extension::Certificate_Policies::static_oid()) {
      return std::make_unique<Cert_Extension::Certificate_Policies>();
   }

   if(oid == Cert_Extension::Extended_Key_Usage::static_oid()) {
      return std::make_unique<Cert_Extension::Extended_Key_Usage>();
   }

   if(oid == Cert_Extension::Authority_Information_Access::static_oid()) {
      return std::make_unique<Cert_Extension::Authority_Information_Access>();
   }

   if(oid == Cert_Extension::TNAuthList::static_oid()) {
      return std::make_unique<Cert_Extension::TNAuthList>();
   }

   if(oid == Cert_Extension::IPAddressBlocks::static_oid()) {
      return std::make_unique<Cert_Extension::IPAddressBlocks>();
   }

   if(oid == Cert_Extension::ASBlocks::static_oid()) {
      return std::make_unique<Cert_Extension::ASBlocks>();
   }

   return nullptr;  // unknown
}

bool is_valid_telephone_number(const ASN1_String& tn) {
   //TelephoneNumber ::= IA5String (SIZE (1..15)) (FROM ("0123456789#*"))
   static std::string valid_tn_chars("0123456789#*");

   if(tn.empty() || (tn.size() > 15)) {
      return false;
   }

   if(tn.value().find_first_not_of(valid_tn_chars) != std::string::npos) {
      return false;
   }

   return true;
}

}  // namespace

/*
* Create a Certificate_Extension object of some kind to handle
*/
std::unique_ptr<Certificate_Extension> Extensions::create_extn_obj(const OID& oid,
                                                                   bool critical,
                                                                   const std::vector<uint8_t>& body) {
   auto extn = extension_from_oid(oid);

   if(!extn) {
      // some other unknown extension type
      extn = std::make_unique<Cert_Extension::Unknown_Extension>(oid, critical);
   }

   try {
      extn->decode_inner(body);
   } catch(Decoding_Error&) {
      extn = std::make_unique<Cert_Extension::Unknown_Extension>(oid, critical);
      extn->decode_inner(body);
   }
   return extn;
}

const Certificate_Extension& Extensions::Extensions_Info::obj() const {
   BOTAN_ASSERT_NONNULL(m_obj.get());
   return *m_obj;
}

/*
* Validate the extension (the default implementation is a NOP)
*/
void Certificate_Extension::validate(const X509_Certificate& /*unused*/,
                                     const X509_Certificate& /*unused*/,
                                     const std::vector<X509_Certificate>& /*unused*/,
                                     std::vector<std::set<Certificate_Status_Code>>& /*unused*/,
                                     size_t /*unused*/) {}

/*
* Add a new cert
*/
void Extensions::add(std::unique_ptr<Certificate_Extension> extn, bool critical) {
   // sanity check: we don't want to have the same extension more than once
   if(m_extension_info.contains(extn->oid_of())) {
      const std::string name = extn->oid_name();
      throw Invalid_Argument("Extension " + name + " already present in Extensions::add");
   }

   const OID oid = extn->oid_of();
   Extensions_Info info(critical, std::move(extn));
   m_extension_oids.push_back(oid);
   m_extension_info.emplace(oid, info);
}

bool Extensions::add_new(std::unique_ptr<Certificate_Extension> extn, bool critical) {
   if(m_extension_info.contains(extn->oid_of())) {
      return false;  // already exists
   }

   const OID oid = extn->oid_of();
   Extensions_Info info(critical, std::move(extn));
   m_extension_oids.push_back(oid);
   m_extension_info.emplace(oid, info);
   return true;
}

bool Extensions::remove(const OID& oid) {
   const bool erased = m_extension_info.erase(oid) > 0;

   if(erased) {
      m_extension_oids.erase(std::find(m_extension_oids.begin(), m_extension_oids.end(), oid));
   }

   return erased;
}

void Extensions::replace(std::unique_ptr<Certificate_Extension> extn, bool critical) {
   // Remove it if it existed
   remove(extn->oid_of());

   const OID oid = extn->oid_of();
   Extensions_Info info(critical, std::move(extn));
   m_extension_oids.push_back(oid);
   m_extension_info.emplace(oid, info);
}

bool Extensions::extension_set(const OID& oid) const {
   return (m_extension_info.find(oid) != m_extension_info.end());
}

bool Extensions::critical_extension_set(const OID& oid) const {
   auto i = m_extension_info.find(oid);
   if(i != m_extension_info.end()) {
      return i->second.is_critical();
   }
   return false;
}

std::vector<uint8_t> Extensions::get_extension_bits(const OID& oid) const {
   auto i = m_extension_info.find(oid);
   if(i == m_extension_info.end()) {
      throw Invalid_Argument("Extensions::get_extension_bits no such extension set");
   }

   return i->second.bits();
}

const Certificate_Extension* Extensions::get_extension_object(const OID& oid) const {
   auto extn = m_extension_info.find(oid);
   if(extn == m_extension_info.end()) {
      return nullptr;
   }

   return &extn->second.obj();
}

std::unique_ptr<Certificate_Extension> Extensions::get(const OID& oid) const {
   if(const Certificate_Extension* ext = this->get_extension_object(oid)) {
      return ext->copy();
   }
   return nullptr;
}

std::vector<std::pair<std::unique_ptr<Certificate_Extension>, bool>> Extensions::extensions() const {
   std::vector<std::pair<std::unique_ptr<Certificate_Extension>, bool>> exts;
   exts.reserve(m_extension_info.size());
   for(auto&& ext : m_extension_info) {
      exts.push_back(std::make_pair(ext.second.obj().copy(), ext.second.is_critical()));
   }
   return exts;
}

std::map<OID, std::pair<std::vector<uint8_t>, bool>> Extensions::extensions_raw() const {
   std::map<OID, std::pair<std::vector<uint8_t>, bool>> out;
   for(auto&& ext : m_extension_info) {
      out.emplace(ext.first, std::make_pair(ext.second.bits(), ext.second.is_critical()));
   }
   return out;
}

/*
* Encode an Extensions list
*/
void Extensions::encode_into(DER_Encoder& to_object) const {
   for(const auto& ext_info : m_extension_info) {
      const OID& oid = ext_info.first;
      const bool should_encode = ext_info.second.obj().should_encode();

      if(should_encode) {
         const bool is_critical = ext_info.second.is_critical();
         const std::vector<uint8_t>& ext_value = ext_info.second.bits();

         to_object.start_sequence()
            .encode(oid)
            .encode_optional(is_critical, false)
            .encode(ext_value, ASN1_Type::OctetString)
            .end_cons();
      }
   }
}

/*
* Decode a list of Extensions
*/
void Extensions::decode_from(BER_Decoder& from_source) {
   m_extension_oids.clear();
   m_extension_info.clear();

   BER_Decoder sequence = from_source.start_sequence();

   while(sequence.more_items()) {
      OID oid;
      bool critical;
      std::vector<uint8_t> bits;

      sequence.start_sequence()
         .decode(oid)
         .decode_optional(critical, ASN1_Type::Boolean, ASN1_Class::Universal, false)
         .decode(bits, ASN1_Type::OctetString)
         .end_cons();

      auto obj = create_extn_obj(oid, critical, bits);
      Extensions_Info info(critical, bits, std::move(obj));

      m_extension_oids.push_back(oid);
      m_extension_info.emplace(oid, info);
   }
   sequence.verify_end();
}

namespace Cert_Extension {

/*
* Checked accessor for the path_limit member
*/
size_t Basic_Constraints::get_path_limit() const {
   if(!m_is_ca) {
      throw Invalid_State("Basic_Constraints::get_path_limit: Not a CA");
   }
   return m_path_limit;
}

/*
* Encode the extension
*/
std::vector<uint8_t> Basic_Constraints::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output)
      .start_sequence()
      .encode_if(m_is_ca, DER_Encoder().encode(m_is_ca).encode_optional(m_path_limit, NO_CERT_PATH_LIMIT))
      .end_cons();
   return output;
}

/*
* Decode the extension
*/
void Basic_Constraints::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder(in)
      .start_sequence()
      .decode_optional(m_is_ca, ASN1_Type::Boolean, ASN1_Class::Universal, false)
      .decode_optional(m_path_limit, ASN1_Type::Integer, ASN1_Class::Universal, NO_CERT_PATH_LIMIT)
      .end_cons();

   if(m_is_ca == false) {
      m_path_limit = 0;
   }
}

/*
* Encode the extension
*/
std::vector<uint8_t> Key_Usage::encode_inner() const {
   if(m_constraints.empty()) {
      throw Encoding_Error("Cannot encode empty PKIX key constraints");
   }

   const size_t constraint_bits = m_constraints.value();
   const size_t unused_bits = ctz(static_cast<uint32_t>(constraint_bits));

   std::vector<uint8_t> der;
   der.push_back(static_cast<uint8_t>(ASN1_Type::BitString));
   der.push_back(2 + ((unused_bits < 8) ? 1 : 0));
   der.push_back(unused_bits % 8);
   der.push_back((constraint_bits >> 8) & 0xFF);
   if(constraint_bits & 0xFF) {
      der.push_back(constraint_bits & 0xFF);
   }

   return der;
}

/*
* Decode the extension
*/
void Key_Usage::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder ber(in);

   BER_Object obj = ber.get_next_object();

   obj.assert_is_a(ASN1_Type::BitString, ASN1_Class::Universal, "usage constraint");

   if(obj.length() == 2 || obj.length() == 3) {
      uint16_t usage = 0;

      const uint8_t* bits = obj.bits();

      if(bits[0] >= 8) {
         throw BER_Decoding_Error("Invalid unused bits in usage constraint");
      }

      const uint8_t mask = static_cast<uint8_t>(0xFF << bits[0]);

      if(obj.length() == 2) {
         usage = make_uint16(bits[1] & mask, 0);
      } else if(obj.length() == 3) {
         usage = make_uint16(bits[1], bits[2] & mask);
      }

      m_constraints = Key_Constraints(usage);
   } else {
      m_constraints = Key_Constraints(0);
   }
}

/*
* Encode the extension
*/
std::vector<uint8_t> Subject_Key_ID::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).encode(m_key_id, ASN1_Type::OctetString);
   return output;
}

/*
* Decode the extension
*/
void Subject_Key_ID::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder(in).decode(m_key_id, ASN1_Type::OctetString).verify_end();
}

/*
* Subject_Key_ID Constructor
*/
Subject_Key_ID::Subject_Key_ID(const std::vector<uint8_t>& pub_key, std::string_view hash_name) {
   auto hash = HashFunction::create_or_throw(hash_name);

   m_key_id.resize(hash->output_length());

   hash->update(pub_key);
   hash->final(m_key_id.data());

   // Truncate longer hashes, 192 bits here seems plenty
   const size_t max_skid_len = (192 / 8);
   if(m_key_id.size() > max_skid_len) {
      m_key_id.resize(max_skid_len);
   }
}

/*
* Encode the extension
*/
std::vector<uint8_t> Authority_Key_ID::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output)
      .start_sequence()
      .encode(m_key_id, ASN1_Type::OctetString, ASN1_Type(0), ASN1_Class::ContextSpecific)
      .end_cons();
   return output;
}

/*
* Decode the extension
*/
void Authority_Key_ID::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder(in).start_sequence().decode_optional_string(m_key_id, ASN1_Type::OctetString, 0);
}

/*
* Encode the extension
*/
std::vector<uint8_t> Subject_Alternative_Name::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).encode(m_alt_name);
   return output;
}

/*
* Encode the extension
*/
std::vector<uint8_t> Issuer_Alternative_Name::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).encode(m_alt_name);
   return output;
}

/*
* Decode the extension
*/
void Subject_Alternative_Name::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder(in).decode(m_alt_name);
}

/*
* Decode the extension
*/
void Issuer_Alternative_Name::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder(in).decode(m_alt_name);
}

/*
* Encode the extension
*/
std::vector<uint8_t> Extended_Key_Usage::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).start_sequence().encode_list(m_oids).end_cons();
   return output;
}

/*
* Decode the extension
*/
void Extended_Key_Usage::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder(in).decode_list(m_oids);
}

/*
* Encode the extension
*/
std::vector<uint8_t> Name_Constraints::encode_inner() const {
   throw Not_Implemented("Name_Constraints encoding");
}

/*
* Decode the extension
*/
void Name_Constraints::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder ber(in);
   BER_Decoder inner = ber.start_sequence();

   std::vector<GeneralSubtree> permitted;
   if(inner.decode_optional_list(permitted, ASN1_Type(0), ASN1_Class::ExplicitContextSpecific)) {
      if(permitted.empty()) {
         throw Decoding_Error("Empty NameConstraint permitted list");
      }
   }

   std::vector<GeneralSubtree> excluded;
   if(inner.decode_optional_list(excluded, ASN1_Type(1), ASN1_Class::ExplicitContextSpecific)) {
      if(excluded.empty()) {
         throw Decoding_Error("Empty NameConstraint excluded list");
      }
   }

   inner.end_cons();

   if(permitted.empty() && excluded.empty()) {
      throw Decoding_Error("Empty NameConstraint extension");
   }

   m_name_constraints = NameConstraints(std::move(permitted), std::move(excluded));
}

void Name_Constraints::validate(const X509_Certificate& subject,
                                const X509_Certificate& /*issuer*/,
                                const std::vector<X509_Certificate>& cert_path,
                                std::vector<std::set<Certificate_Status_Code>>& cert_status,
                                size_t pos) {
   if(!m_name_constraints.permitted().empty() || !m_name_constraints.excluded().empty()) {
      if(!subject.is_CA_cert()) {
         cert_status.at(pos).insert(Certificate_Status_Code::NAME_CONSTRAINT_ERROR);
      }

      const bool issuer_name_constraint_critical = subject.is_critical("X509v3.NameConstraints");

      // Check that all subordinate certs pass the name constraint
      for(size_t j = 0; j < pos; ++j) {
         const auto& cert = cert_path.at(j);

         if(!m_name_constraints.is_permitted(cert, issuer_name_constraint_critical)) {
            cert_status.at(j).insert(Certificate_Status_Code::NAME_CONSTRAINT_ERROR);
            continue;
         }

         if(m_name_constraints.is_excluded(cert, issuer_name_constraint_critical)) {
            cert_status.at(j).insert(Certificate_Status_Code::NAME_CONSTRAINT_ERROR);
            continue;
         }
      }
   }
}

namespace {

/*
* A policy specifier
*/
class Policy_Information final : public ASN1_Object {
   public:
      Policy_Information() = default;

      explicit Policy_Information(const OID& oid) : m_oid(oid) {}

      const OID& oid() const { return m_oid; }

      void encode_into(DER_Encoder& codec) const override { codec.start_sequence().encode(m_oid).end_cons(); }

      void decode_from(BER_Decoder& codec) override {
         codec.start_sequence().decode(m_oid).discard_remaining().end_cons();
      }

   private:
      OID m_oid;
};

}  // namespace

/*
* Encode the extension
*/
std::vector<uint8_t> Certificate_Policies::encode_inner() const {
   std::vector<Policy_Information> policies;

   policies.reserve(m_oids.size());
   for(const auto& oid : m_oids) {
      policies.push_back(Policy_Information(oid));
   }

   std::vector<uint8_t> output;
   DER_Encoder(output).start_sequence().encode_list(policies).end_cons();
   return output;
}

/*
* Decode the extension
*/
void Certificate_Policies::decode_inner(const std::vector<uint8_t>& in) {
   std::vector<Policy_Information> policies;

   BER_Decoder(in).decode_list(policies);
   m_oids.clear();
   for(const auto& policy : policies) {
      m_oids.push_back(policy.oid());
   }
}

void Certificate_Policies::validate(const X509_Certificate& /*subject*/,
                                    const X509_Certificate& /*issuer*/,
                                    const std::vector<X509_Certificate>& /*cert_path*/,
                                    std::vector<std::set<Certificate_Status_Code>>& cert_status,
                                    size_t pos) {
   std::set<OID> oid_set(m_oids.begin(), m_oids.end());
   if(oid_set.size() != m_oids.size()) {
      cert_status.at(pos).insert(Certificate_Status_Code::DUPLICATE_CERT_POLICY);
   }
}

std::vector<uint8_t> Authority_Information_Access::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder der(output);

   der.start_sequence();
   // OCSP
   if(!m_ocsp_responder.empty()) {
      ASN1_String url(m_ocsp_responder, ASN1_Type::Ia5String);
      der.start_sequence()
         .encode(OID::from_string("PKIX.OCSP"))
         .add_object(ASN1_Type(6), ASN1_Class::ContextSpecific, url.value())
         .end_cons();
   }

   // CA Issuers
   for(const auto& ca_isser : m_ca_issuers) {
      ASN1_String asn1_ca_issuer(ca_isser, ASN1_Type::Ia5String);
      der.start_sequence()
         .encode(OID::from_string("PKIX.CertificateAuthorityIssuers"))
         .add_object(ASN1_Type(6), ASN1_Class::ContextSpecific, asn1_ca_issuer.value())
         .end_cons();
   }

   der.end_cons();
   return output;
}

void Authority_Information_Access::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder ber = BER_Decoder(in).start_sequence();

   while(ber.more_items()) {
      OID oid;

      BER_Decoder info = ber.start_sequence();

      info.decode(oid);

      if(oid == OID::from_string("PKIX.OCSP")) {
         BER_Object name = info.get_next_object();

         if(name.is_a(6, ASN1_Class::ContextSpecific)) {
            m_ocsp_responder = ASN1::to_string(name);
         }
      }
      if(oid == OID::from_string("PKIX.CertificateAuthorityIssuers")) {
         BER_Object name = info.get_next_object();

         if(name.is_a(6, ASN1_Class::ContextSpecific)) {
            m_ca_issuers.push_back(ASN1::to_string(name));
         }
      }
   }
}

/*
* Checked accessor for the crl_number member
*/
size_t CRL_Number::get_crl_number() const {
   if(!m_has_value) {
      throw Invalid_State("CRL_Number::get_crl_number: Not set");
   }
   return m_crl_number;
}

/*
* Copy a CRL_Number extension
*/
std::unique_ptr<Certificate_Extension> CRL_Number::copy() const {
   if(!m_has_value) {
      throw Invalid_State("CRL_Number::copy: Not set");
   }
   return std::make_unique<CRL_Number>(m_crl_number);
}

/*
* Encode the extension
*/
std::vector<uint8_t> CRL_Number::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).encode(m_crl_number);
   return output;
}

/*
* Decode the extension
*/
void CRL_Number::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder(in).decode(m_crl_number);
   m_has_value = true;
}

/*
* Encode the extension
*/
std::vector<uint8_t> CRL_ReasonCode::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).encode(static_cast<size_t>(m_reason), ASN1_Type::Enumerated, ASN1_Class::Universal);
   return output;
}

/*
* Decode the extension
*/
void CRL_ReasonCode::decode_inner(const std::vector<uint8_t>& in) {
   size_t reason_code = 0;
   BER_Decoder(in).decode(reason_code, ASN1_Type::Enumerated, ASN1_Class::Universal);
   m_reason = static_cast<CRL_Code>(reason_code);
}

std::vector<uint8_t> CRL_Distribution_Points::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).start_sequence().encode_list(m_distribution_points).end_cons();
   return output;
}

void CRL_Distribution_Points::decode_inner(const std::vector<uint8_t>& buf) {
   BER_Decoder(buf).decode_list(m_distribution_points).verify_end();

   std::stringstream ss;

   for(const auto& distribution_point : m_distribution_points) {
      auto contents = distribution_point.point().contents();

      for(const auto& pair : contents) {
         ss << pair.first << ": " << pair.second << " ";
      }
   }

   m_crl_distribution_urls.push_back(ss.str());
}

void CRL_Distribution_Points::Distribution_Point::encode_into(DER_Encoder& der) const {
   const auto uris = m_point.uris();

   if(uris.empty()) {
      throw Not_Implemented("Empty CRL_Distribution_Point encoding not implemented");
   }

   for(const auto& uri : uris) {
      der.start_sequence()
         .start_cons(ASN1_Type(0), ASN1_Class::ContextSpecific)
         .start_cons(ASN1_Type(0), ASN1_Class::ContextSpecific)
         .add_object(ASN1_Type(6), ASN1_Class::ContextSpecific, uri)
         .end_cons()
         .end_cons()
         .end_cons();
   }
}

void CRL_Distribution_Points::Distribution_Point::decode_from(BER_Decoder& ber) {
   ber.start_sequence()
      .start_context_specific(0)
      .decode_optional_implicit(m_point,
                                ASN1_Type(0),
                                ASN1_Class::ContextSpecific | ASN1_Class::Constructed,
                                ASN1_Type::Sequence,
                                ASN1_Class::Constructed)
      .end_cons()
      .end_cons();
}

std::vector<uint8_t> CRL_Issuing_Distribution_Point::encode_inner() const {
   throw Not_Implemented("CRL_Issuing_Distribution_Point encoding");
}

void CRL_Issuing_Distribution_Point::decode_inner(const std::vector<uint8_t>& buf) {
   BER_Decoder(buf).decode(m_distribution_point).verify_end();
}

void TNAuthList::Entry::encode_into(DER_Encoder&) const {
   throw Not_Implemented("TNAuthList extension entry serialization is not supported");
}

void TNAuthList::Entry::decode_from(class BER_Decoder& ber) {
   BER_Object obj = ber.get_next_object();

   const uint32_t type_tag = static_cast<Type>(obj.type_tag());

   if(type_tag == ServiceProviderCode) {
      m_type = ServiceProviderCode;
      ASN1_String spc_string;
      BER_Decoder(obj).decode(spc_string);
      m_data = std::move(spc_string);
   } else if(type_tag == TelephoneNumberRange) {
      m_type = TelephoneNumberRange;
      m_data = RangeContainer();
      auto& range_items = std::get<RangeContainer>(m_data);
      BER_Decoder list = BER_Decoder(obj).start_sequence();
      while(list.more_items()) {
         TelephoneNumberRangeData entry;

         list.decode(entry.start);
         if(!is_valid_telephone_number(entry.start)) {
            throw Decoding_Error(fmt("Invalid TelephoneNumberRange start {}", entry.start.value()));
         }

         list.decode(entry.count);
         if(entry.count < 2) {
            throw Decoding_Error(fmt("Invalid TelephoneNumberRange count {}", entry.count));
         }

         range_items.emplace_back(std::move(entry));
      }
      list.end_cons();

      if(range_items.empty()) {
         throw Decoding_Error("TelephoneNumberRange is empty");
      }
   } else if(type_tag == TelephoneNumber) {
      m_type = TelephoneNumber;
      ASN1_String one_string;
      BER_Decoder(obj).decode(one_string);
      if(!is_valid_telephone_number(one_string)) {
         throw Decoding_Error(fmt("Invalid TelephoneNumber {}", one_string.value()));
      }
      m_data = std::move(one_string);
   } else {
      throw Decoding_Error(fmt("Unexpected TNEntry type code {}", type_tag));
   };
}

std::vector<uint8_t> TNAuthList::encode_inner() const {
   throw Not_Implemented("TNAuthList extension serialization is not supported");
}

void TNAuthList::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder(in).decode_list(m_tn_entries).verify_end();
   if(m_tn_entries.empty()) {
      throw Decoding_Error("TNAuthorizationList is empty");
   }
}

const std::string& TNAuthList::Entry::service_provider_code() const {
   BOTAN_STATE_CHECK(type() == Type::ServiceProviderCode);
   return std::get<ASN1_String>(m_data).value();
}

const TNAuthList::Entry::RangeContainer& TNAuthList::Entry::telephone_number_range() const {
   BOTAN_STATE_CHECK(type() == Type::TelephoneNumberRange);
   return std::get<RangeContainer>(m_data);
}

const std::string& TNAuthList::Entry::telephone_number() const {
   BOTAN_STATE_CHECK(type() == Type::TelephoneNumber);
   return std::get<ASN1_String>(m_data).value();
}

std::vector<uint8_t> IPAddressBlocks::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).start_sequence().encode_list(m_ip_addr_blocks).end_cons();
   return output;
}

void IPAddressBlocks::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder(in).decode_list(m_ip_addr_blocks).verify_end();
}

void IPAddressBlocks::sort_and_merge() {
   // std::map is ordered, so a uint32_t of [afi,safi] will be in the right order
   std::map<uint32_t, std::vector<IPAddressFamily>> afam_map;
   for(IPAddressFamily& block : m_ip_addr_blocks) {
      uint32_t afam = block.afi();
      if(block.safi().has_value()) {
         afam = static_cast<uint32_t>(afam << 8) | block.safi().value();
      }
      std::vector<IPAddressFamily>& fams = afam_map[afam];
      fams.push_back(block);
   }

   std::vector<IPAddressFamily> merged_blocks;
   for(auto it = afam_map.begin(); it != afam_map.end(); it++) {
      std::vector<IPAddressFamily>& fams = it->second;

      // fams[0] has to have the same choice type as the fams in the same bucket
      if(std::holds_alternative<IPAddressChoice<Version::IPv4>>(fams[0].addr_choice())) {
         merged_blocks.push_back(merge<Version::IPv4>(fams));
      } else {
         merged_blocks.push_back(merge<Version::IPv6>(fams));
      }
   }
   m_ip_addr_blocks = merged_blocks;
}

template <IPAddressBlocks::Version V>
IPAddressBlocks::IPAddressFamily IPAddressBlocks::merge(std::vector<IPAddressFamily>& blocks) {
   if(blocks.size() == 1) {
      return blocks[0];
   }

   bool all_inherit = true;
   bool none_inherit = true;
   for(IPAddressFamily& block : blocks) {
      IPAddressChoice<V> choice = std::get<IPAddressChoice<V>>(block.addr_choice());
      all_inherit = !choice.ranges().has_value() && all_inherit;
      none_inherit = choice.ranges().has_value() && none_inherit;
   }

   if(all_inherit) {
      return IPAddressFamily(IPAddressChoice<V>(), blocks[0].safi());
   }

   if(not(all_inherit || none_inherit)) {
      throw Decoding_Error("Having AFIs that inherit and don't inherit at the same time is not allowed");
   }

   std::vector<IPAddressOrRange<V>> merged_ranges;
   for(IPAddressFamily& block : blocks) {
      IPAddressChoice<V> choice = std::get<IPAddressChoice<V>>(block.addr_choice());
      std::vector<IPAddressOrRange<V>> ranges = choice.ranges().value();
      for(IPAddressOrRange<V>& r : ranges) {
         merged_ranges.push_back(r);
      }
   }

   IPAddressChoice<V> choice(merged_ranges);
   IPAddressFamily fam(choice, blocks[0].safi());
   return fam;
}

void IPAddressBlocks::IPAddressFamily::encode_into(Botan::DER_Encoder& into) const {
   into.start_sequence();

   std::vector<uint8_t> afam = {static_cast<uint8_t>(m_afi >> 8), static_cast<uint8_t>(m_afi & 0xff)};

   if(m_safi.has_value()) {
      afam.push_back(m_safi.value());
   }

   into.add_object(ASN1_Type::OctetString, ASN1_Class::Universal, afam);

   if(std::holds_alternative<IPAddressChoice<Version::IPv4>>(m_ip_addr_choice)) {
      into.encode(std::get<IPAddressChoice<Version::IPv4>>(m_ip_addr_choice));
   } else {
      into.encode(std::get<IPAddressChoice<Version::IPv6>>(m_ip_addr_choice));
   }
   into.end_cons();
}

void IPAddressBlocks::IPAddressFamily::decode_from(Botan::BER_Decoder& from) {
   BER_Object obj = from.get_next_object();
   ASN1_Type type_tag = obj.type_tag();
   if(type_tag != ASN1_Type::Sequence) {
      throw Decoding_Error(fmt("Unexpected type for IPAddressFamily {}", static_cast<uint32_t>(type_tag)));
   }
   BER_Decoder obj_ber = BER_Decoder(obj);

   std::vector<uint8_t> addr_family;
   obj_ber.decode(addr_family, ASN1_Type::OctetString);
   size_t addr_family_length = addr_family.size();

   if(addr_family_length != 2 && addr_family_length != 3) {
      throw Decoding_Error("(S)AFI can only contain 2 or 3 bytes");
   }

   m_afi = (addr_family[0] << 8) | addr_family[1];

   if(addr_family_length == 3) {
      m_safi = addr_family[2];
   }

   if(m_afi == 1) {
      IPAddressChoice<Version::IPv4> addr_choice;
      obj_ber.decode(addr_choice);
      m_ip_addr_choice = addr_choice;
   } else if(m_afi == 2) {
      IPAddressChoice<Version::IPv6> addr_choice;
      obj_ber.decode(addr_choice);
      m_ip_addr_choice = addr_choice;
   } else {
      throw Decoding_Error("Only AFI IPv4 and IPv6 are supported.");
   }
}

template <IPAddressBlocks::Version V>
void IPAddressBlocks::IPAddressChoice<V>::encode_into(Botan::DER_Encoder& into) const {
   if(m_ip_addr_ranges.has_value()) {
      into.start_sequence().encode_list(m_ip_addr_ranges.value()).end_cons();
   } else {
      into.encode_null();
   }
}

template <IPAddressBlocks::Version V>
void IPAddressBlocks::IPAddressChoice<V>::decode_from(Botan::BER_Decoder& from) {
   ASN1_Type next_tag = from.peek_next_object().type_tag();

   if(next_tag == ASN1_Type::Null) {
      from.decode_null();
      m_ip_addr_ranges = std::nullopt;
   } else if(next_tag == ASN1_Type::Sequence) {
      std::vector<IPAddressOrRange<V>> ip_ranges;
      from.decode_list(ip_ranges);
      m_ip_addr_ranges = ip_ranges;
   } else {
      throw Decoding_Error(fmt("Unexpected type for IPAddressChoice {}", static_cast<uint32_t>(next_tag)));
   }
}

template <IPAddressBlocks::Version V>
void IPAddressBlocks::IPAddressChoice<V>::sort_and_merge() {
   if(!m_ip_addr_ranges.has_value()) {
      return;
   }
   std::vector<IPAddressOrRange<V>> current = m_ip_addr_ranges.value();
   if(current.empty()) {
      return;
   }
   bool changed = true;
   while(changed) {
      changed = false;
      // sort by the minimum address
      std::sort(current.begin(), current.end(), [](IPAddressOrRange<V>& a, IPAddressOrRange<V>& b) {
         return a.min() < b.min();
      });
      for(size_t i = 0; i < current.size() - 1; i++) {
         IPAddressOrRange<V> a = current[i];
         IPAddressOrRange<V> b = current[i + 1];
         // only ++ is implemented for IPAddress<V>, instead of +
         if(b.min() <= a.max() || b.min() == (++a.max())) {
            // erase old a and b
            current.erase(current.begin() + i, current.begin() + i + 2);
            current.insert(current.begin() + i, IPAddressOrRange<V>(a.min(), std::max(a.max(), b.max())));
            // look again at the new element we just created, might need to be merged with others still
            i -= 1;
            changed = true;
         }
      }
   }
   m_ip_addr_ranges = current;
}

template <IPAddressBlocks::Version V>
void IPAddressBlocks::IPAddressOrRange<V>::encode_into(Botan::DER_Encoder& into) const {
   const uint8_t version_octets = static_cast<uint8_t>(V);

   std::array<uint8_t, version_octets> min = m_min.value();
   std::array<uint8_t, version_octets> max = m_max.value();

   uint8_t zeros = 0;
   uint8_t ones = 0;

   bool zeros_done = false;
   bool ones_done = false;

   // count contiguos 0s/1s from the right of the min/max addresses
   for(size_t i = static_cast<size_t>(version_octets); i > 0; i--) {
      if(!zeros_done) {
         uint8_t local_zeros = static_cast<uint8_t>(std::countr_zero(min[i - 1]));
         zeros += local_zeros;
         zeros_done = (local_zeros != 8);
      }

      if(!ones_done) {
         uint8_t local_ones = static_cast<uint8_t>(std::countr_one(max[i - 1]));
         ones += local_ones;
         ones_done = (local_ones != 8);
      }

      if(zeros_done && ones_done) {
         break;
      }
   }

   // the part we want to compress
   uint8_t host = std::min(zeros, ones);

   // these we can outright drop
   uint8_t discarded_octets = host / 8;
   // in a partially used byte
   uint8_t unused_bits = host % 8;

   bool octets_match = true;
   for(size_t i = 0; i < static_cast<uint8_t>(version_octets - discarded_octets - 1); i++) {
      if(min[i] != max[i]) {
         octets_match = false;
         break;
      }
   }

   // we only partially use this octet, and the used part has to match for prefix encoding
   bool used_bits_match = true;
   // if we would discard all octets we don't actually have a partially used octet, so this doesn't matter
   if(discarded_octets < version_octets - 1) {
      uint8_t shifted_min = (min[version_octets - 1 - discarded_octets] >> unused_bits);
      uint8_t shifted_max = (max[version_octets - 1 - discarded_octets] >> unused_bits);
      used_bits_match = (shifted_min == shifted_max);
   }

   // both the full octets and the partially used one match
   if(octets_match && used_bits_match) {
      // at this point the range can be encoded as a prefix
      std::vector<uint8_t> prefix;

      prefix.push_back(unused_bits);
      for(size_t i = 0; i < static_cast<uint8_t>(version_octets - discarded_octets); i++) {
         prefix.push_back(min[i]);
      }

      into.add_object(ASN1_Type::BitString, ASN1_Class::Universal, prefix);
   } else {
      uint8_t discarded_octets_min = zeros / 8;
      uint8_t unused_bits_min = zeros % 8;

      uint8_t discarded_octets_max = ones / 8;
      uint8_t unused_bits_max = ones % 8;

      // compress the max address by setting unused bits to 0, for the min address these are already 0
      if(unused_bits_max != 0) {
         max[version_octets - 1 - discarded_octets_max] >>= unused_bits_max;
         max[version_octets - 1 - discarded_octets_max] <<= unused_bits_max;
      }

      std::vector<uint8_t> compressed_min;
      std::vector<uint8_t> compressed_max;

      // construct the address as a byte sequence of the unused bits followed by the compressed address
      compressed_min.push_back(unused_bits_min);
      for(size_t i = 0; i < static_cast<uint8_t>(version_octets - discarded_octets_min); i++) {
         compressed_min.push_back(min[i]);
      }

      compressed_max.push_back(unused_bits_max);
      for(size_t i = 0; i < static_cast<uint8_t>(version_octets - discarded_octets_max); i++) {
         compressed_max.push_back(max[i]);
      }

      into.start_sequence()
         .add_object(ASN1_Type::BitString, ASN1_Class::Universal, compressed_min)
         .add_object(ASN1_Type::BitString, ASN1_Class::Universal, compressed_max)
         .end_cons();
   }
}

template <IPAddressBlocks::Version V>
void IPAddressBlocks::IPAddressOrRange<V>::decode_from(Botan::BER_Decoder& from) {
   const uint8_t version_octets = static_cast<uint8_t>(V);

   ASN1_Type next_tag = from.peek_next_object().type_tag();

   // this can either be a prefix or a single address
   if(next_tag == ASN1_Type::BitString) {
      // construct a min and a max address from the prefix

      std::vector<uint8_t> prefix;
      from.decode(prefix, ASN1_Type::OctetString, ASN1_Type::BitString, ASN1_Class::Universal);

      // we have to account for the octet at the beginning that specifies how many bits are unused in the last octet
      if(prefix.empty() || prefix.size() > version_octets + 1) {
         throw Decoding_Error(
            fmt("IP address range entries must have a length between 2 and {} bits.", static_cast<uint8_t>(V)));
      }

      uint8_t unused = prefix.front();
      uint8_t discarded_octets = version_octets - (static_cast<uint8_t>(prefix.size()) - 1);

      prefix.erase(prefix.begin());

      for(size_t i = 0; i < discarded_octets; i++) {
         prefix.push_back(0);
      }

      IPAddress<V> addr_min(prefix);

      for(size_t i = version_octets - discarded_octets; i < version_octets; i++) {
         prefix[i] = 0xff;
      }

      // set all unused bits to 1
      for(size_t i = 0; i < unused; i++) {
         prefix[version_octets - 1 - discarded_octets] |= (1 << i);
      }

      IPAddress<V> addr_max(prefix);

      m_min = addr_min;
      m_max = addr_max;
   } else if(next_tag == ASN1_Type::Sequence) {
      // this is a range

      std::vector<uint8_t> addr_min;
      std::vector<uint8_t> addr_max;

      from.start_sequence()
         .decode(addr_min, ASN1_Type::OctetString, ASN1_Type::BitString, ASN1_Class::Universal)
         .decode(addr_max, ASN1_Type::OctetString, ASN1_Type::BitString, ASN1_Class::Universal)
         .end_cons();

      // address 1 (min)

      // again accounting for the 'unused' octet at the beginning
      if(addr_min.empty() || addr_min.size() > version_octets + 1) {
         throw Decoding_Error(
            fmt("IP address range entries must have a length between 1 and {} bytes.", static_cast<uint8_t>(V)));
      }

      addr_min.erase(addr_min.begin());  // remove 'unused' octet

      // restore trailing zeros
      size_t addr_len = addr_min.size();
      for(size_t i = 0; i < version_octets - addr_len; i++) {
         addr_min.push_back(0);
      }

      m_min = IPAddress<V>(addr_min);

      // address 2 (max)

      if(addr_max.empty() || addr_max.size() > version_octets + 1) {
         throw Decoding_Error(
            fmt("IP address range entries must have a length between 1 and {} bytes.", static_cast<uint8_t>(V)));
      }

      // here we need the unused bits to restore the least significant 1s correctly
      uint8_t unused = addr_max.front();
      addr_max.erase(addr_max.begin());

      // we were given 0 actual address octets, but the unused octet claims there are unused bits - this doesn't make sense!
      if(addr_max.empty() && unused != 0) {
         throw Decoding_Error("IP address range entry specified unused bits, but did not provide any octets.");
      }

      // restore trailing ones
      addr_len = addr_max.size();
      for(size_t i = 0; i < version_octets - addr_len; i++) {
         addr_max.push_back(0xff);
      }

      // restore ones stored in 'unused' octet (which is the last octet before trailing ones)
      for(size_t i = 0; i < unused; i++) {
         addr_max[addr_len - 1] |= (1 << i);
      }

      m_max = IPAddress<V>(addr_max);

      if(m_min > m_max) {
         throw Decoding_Error("IP address ranges must be sorted.");
      }
   } else {
      throw Decoding_Error(fmt("Unexpected type for IPAddressOrRange {}", static_cast<uint32_t>(next_tag)));
   }
}

template <IPAddressBlocks::Version V>
IPAddressBlocks::IPAddress<V>::IPAddress(std::span<uint8_t> v) {
   const size_t version_octets = static_cast<size_t>(V);
   if(v.size() != version_octets) {
      throw Decoding_Error("number of bytes does not match IP version used");
   }

   for(size_t i = 0; i < version_octets; i++) {
      m_value[i] = v[i];
   }
}

template class IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv4>;
template class IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv6>;
template class IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv4>;
template class IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv6>;
template class IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv4>;
template class IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv6>;

std::vector<uint8_t> ASBlocks::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).encode(m_as_identifiers);
   return output;
}

void ASBlocks::decode_inner(const std::vector<uint8_t>& in) {
   BER_Decoder(in).decode(m_as_identifiers).verify_end();
}

void ASBlocks::ASIdentifiers::encode_into(Botan::DER_Encoder& into) const {
   into.start_sequence();

   if(m_asnum.has_value()) {
      into.start_explicit(0);
      into.encode(m_asnum.value());
      into.end_explicit();
   }

   if(m_rdi.has_value()) {
      into.start_explicit(1);
      into.encode(m_rdi.value());
      into.end_explicit();
   }

   into.end_cons();
}

void ASBlocks::ASIdentifiers::decode_from(Botan::BER_Decoder& from) {
   BER_Object obj = from.get_next_object();
   ASN1_Type type_tag = obj.type_tag();
   if(type_tag != ASN1_Type::Sequence) {
      throw Decoding_Error(fmt("Unexpected type for ASIdentifiers {}", static_cast<uint32_t>(type_tag)));
   }
   BER_Decoder obj_ber = BER_Decoder(obj);

   BER_Object elem_obj = obj_ber.get_next_object();
   uint32_t elem_type_tag = static_cast<uint32_t>(elem_obj.type_tag());

   // asnum, potentially followed by an rdi
   if(elem_type_tag == 0) {
      BER_Decoder as_obj_ber = BER_Decoder(elem_obj);
      ASIdentifierChoice asnum;
      as_obj_ber.decode(asnum);
      m_asnum = asnum;

      BER_Object rdi_obj = obj_ber.get_next_object();
      ASN1_Type rdi_type_tag = rdi_obj.type_tag();
      if(static_cast<uint32_t>(rdi_type_tag) == 1) {
         BER_Decoder rdi_obj_ber = BER_Decoder(rdi_obj);
         ASIdentifierChoice rdi;
         rdi_obj_ber.decode(rdi);
         m_rdi = rdi;
      } else if(rdi_type_tag != ASN1_Type::NoObject) {
         throw Decoding_Error(fmt("Unexpected type for ASIdentifiers rdi: {}", static_cast<uint32_t>(rdi_type_tag)));
      }
   }

   // just an rdi
   if(elem_type_tag == 1) {
      BER_Decoder rdi_obj_ber = BER_Decoder(elem_obj);
      ASIdentifierChoice rdi;
      rdi_obj_ber.decode(rdi);
      m_rdi = rdi;
      BER_Object end = obj_ber.get_next_object();
      ASN1_Type end_type_tag = end.type_tag();
      if(end_type_tag != ASN1_Type::NoObject) {
         throw Decoding_Error(
            fmt("Unexpected element with type {} in ASIdentifiers", static_cast<uint32_t>(end_type_tag)));
      }
   }
}

void ASBlocks::ASIdentifierChoice::encode_into(Botan::DER_Encoder& into) const {
   if(m_as_ranges.has_value()) {
      into.start_sequence().encode_list(m_as_ranges.value()).end_cons();
   } else {
      into.encode_null();
   }
}

void ASBlocks::ASIdentifierChoice::decode_from(Botan::BER_Decoder& from) {
   BER_Object obj = from.get_next_object();
   ASN1_Type type_tag = obj.type_tag();

   if(type_tag == ASN1_Type::Null) {
      m_as_ranges = std::nullopt;
   } else if(type_tag == ASN1_Type::Sequence) {
      BER_Decoder obj_ber = BER_Decoder(obj);
      std::vector<ASIdOrRange> as_ranges;

      while(obj_ber.more_items()) {
         ASIdOrRange as_id_or_range;
         obj_ber.decode(as_id_or_range);
         as_ranges.push_back(as_id_or_range);
      }

      m_as_ranges = as_ranges;
      sort_and_merge();
   } else {
      throw Decoding_Error(fmt("Unexpected type for ASIdentifierChoice {}", static_cast<uint32_t>(type_tag)));
   }
}

void ASBlocks::ASIdentifierChoice::sort_and_merge() {
   if(!m_as_ranges.has_value()) {
      return;
   }
   std::vector<ASIdOrRange> current = m_as_ranges.value();
   if(current.empty()) {
      return;
   }
   bool changed = true;
   while(changed) {
      changed = false;
      std::sort(current.begin(), current.end(), [](ASIdOrRange& a, ASIdOrRange& b) { return a.min() < b.min(); });
      for(size_t i = 0; i < current.size() - 1; i++) {
         ASIdOrRange a = current[i];
         ASIdOrRange b = current[i + 1];
         if(b.min() <= a.max() || b.min() == (a.max() + 1)) {
            // erase old a and b
            current.erase(current.begin() + i, current.begin() + i + 2);
            current.insert(current.begin() + i, ASIdOrRange(a.min(), std::max(a.max(), b.max())));
            // look again at the new element we just created, might need to be merged with others still
            i -= 1;
            changed = true;
         }
      }
   }
   m_as_ranges = current;
}

void ASBlocks::ASIdOrRange::encode_into(Botan::DER_Encoder& into) const {
   if(m_min == m_max) {
      into.encode(static_cast<size_t>(m_min));
   } else {
      if(m_min >= m_max) {
         throw Encoding_Error("AS range numbers must be sorted");
      }
      into.start_sequence().encode(static_cast<size_t>(m_min)).encode(static_cast<size_t>(m_max)).end_cons();
   }
}

void ASBlocks::ASIdOrRange::decode_from(BER_Decoder& from) {
   ASN1_Type next_tag = from.peek_next_object().type_tag();

   size_t min;
   size_t max;

   if(next_tag == ASN1_Type::Integer) {
      from.decode(min);
      m_min = static_cast<uint32_t>(min);
      m_max = m_min;
   } else if(next_tag == ASN1_Type::Sequence) {
      from.start_sequence().decode(min).decode(max).end_cons();
      m_min = static_cast<uint32_t>(min);
      m_max = static_cast<uint32_t>(max);
   } else {
      throw Decoding_Error(fmt("Unexpected type for ASIdOrRange {}", static_cast<uint32_t>(next_tag)));
   }
}

void OCSP_NoCheck::decode_inner(const std::vector<uint8_t>& buf) {
   BER_Decoder(buf).verify_end();
}

std::vector<uint8_t> Unknown_Extension::encode_inner() const {
   return m_bytes;
}

void Unknown_Extension::decode_inner(const std::vector<uint8_t>& bytes) {
   // Just treat as an opaque blob at this level
   m_bytes = bytes;
}

}  // namespace Cert_Extension

}  // namespace Botan
