/*
* X.509 Certificate Extensions
* (C) 1999-2010,2012 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
* (C) 2017 Fabian Weissberg, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_ext.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/x509cert.h>
#include <botan/internal/bit_ops.h>
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

   return nullptr;  // unknown
}

}  // namespace

/*
* Create a Certificate_Extension object of some kind to handle
*/
std::unique_ptr<Certificate_Extension> Extensions::create_extn_obj(const OID& oid,
                                                                   bool critical,
                                                                   const std::vector<uint8_t>& body) {
   const std::string oid_str = oid.to_string();

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

   if(obj.length() != 2 && obj.length() != 3) {
      throw BER_Decoding_Error("Bad size for BITSTRING in usage constraint");
   }

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
   std::vector<GeneralSubtree> permit, exclude;
   BER_Decoder ber(in);
   BER_Decoder ext = ber.start_sequence();
   BER_Object per = ext.get_next_object();

   ext.push_back(per);
   if(per.is_a(0, ASN1_Class::Constructed | ASN1_Class::ContextSpecific)) {
      ext.decode_list(permit, ASN1_Type(0), ASN1_Class::Constructed | ASN1_Class::ContextSpecific);
      if(permit.empty()) {
         throw Encoding_Error("Empty Name Contraint list");
      }
   }

   BER_Object exc = ext.get_next_object();
   ext.push_back(exc);
   if(per.is_a(1, ASN1_Class::Constructed | ASN1_Class::ContextSpecific)) {
      ext.decode_list(exclude, ASN1_Type(1), ASN1_Class::Constructed | ASN1_Class::ContextSpecific);
      if(exclude.empty()) {
         throw Encoding_Error("Empty Name Contraint list");
      }
   }

   ext.end_cons();

   if(permit.empty() && exclude.empty()) {
      throw Encoding_Error("Empty Name Contraint extension");
   }

   m_name_constraints = NameConstraints(std::move(permit), std::move(exclude));
}

void Name_Constraints::validate(const X509_Certificate& subject,
                                const X509_Certificate& issuer,
                                const std::vector<X509_Certificate>& cert_path,
                                std::vector<std::set<Certificate_Status_Code>>& cert_status,
                                size_t pos) {
   if(!m_name_constraints.permitted().empty() || !m_name_constraints.excluded().empty()) {
      if(!subject.is_CA_cert()) {
         cert_status.at(pos).insert(Certificate_Status_Code::NAME_CONSTRAINT_ERROR);
      }

      const bool issuer_name_constraint_critical = issuer.is_critical("X509v3.NameConstraints");

      // Check that all subordinate certs pass the name constraint
      for(size_t j = 0; j < pos; ++j) {
         bool permitted = m_name_constraints.permitted().empty();
         bool failed = false;

         for(const auto& c : m_name_constraints.permitted()) {
            switch(c.base().matches(cert_path.at(j))) {
               case GeneralName::MatchResult::NotFound:
               case GeneralName::MatchResult::All:
                  permitted = true;
                  break;
               case GeneralName::MatchResult::UnknownType:
                  failed = issuer_name_constraint_critical;
                  permitted = true;
                  break;
               default:
                  break;
            }
         }

         for(const auto& c : m_name_constraints.excluded()) {
            switch(c.base().matches(cert_path.at(j))) {
               case GeneralName::MatchResult::All:
               case GeneralName::MatchResult::Some:
                  failed = true;
                  break;
               case GeneralName::MatchResult::UnknownType:
                  failed = issuer_name_constraint_critical;
                  break;
               default:
                  break;
            }
         }

         if(failed || !permitted) {
            cert_status.at(j).insert(Certificate_Status_Code::NAME_CONSTRAINT_ERROR);
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
   ASN1_String url(m_ocsp_responder, ASN1_Type::Ia5String);

   std::vector<uint8_t> output;
   DER_Encoder(output)
      .start_sequence()
      .start_sequence()
      .encode(OID::from_string("PKIX.OCSP"))
      .add_object(ASN1_Type(6), ASN1_Class::ContextSpecific, url.value())
      .end_cons()
      .end_cons();
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
   if(!m_point.get_attributes().contains("URI")) {
      throw Not_Implemented("Empty CRL_Distribution_Point encoding");
   }

   const auto range = m_point.get_attributes().equal_range("URI");

   for(auto i = range.first; i != range.second; ++i) {
      der.start_sequence()
         .start_cons(ASN1_Type(0), ASN1_Class::ContextSpecific)
         .start_cons(ASN1_Type(0), ASN1_Class::ContextSpecific)
         .add_object(ASN1_Type(6), ASN1_Class::ContextSpecific, i->second)
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
