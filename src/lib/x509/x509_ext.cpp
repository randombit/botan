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
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/x509_utils.h>
#include <algorithm>
#include <set>
#include <span>

namespace Botan {

namespace {

constexpr size_t MaximumKeyIdentifierLength = 64;

template <std::derived_from<Certificate_Extension> T>
auto make_extension([[maybe_unused]] const OID& oid) {
   BOTAN_DEBUG_ASSERT(oid == T::static_oid());
   return std::make_unique<T>();
}

std::unique_ptr<Certificate_Extension> extension_from_oid(const OID& oid) {
   if(auto iso_ext = is_sub_element_of(oid, {2, 5, 29})) {
      // NOLINTNEXTLINE(*-switch-missing-default-case)
      switch(*iso_ext) {
         case 14:
            return make_extension<Cert_Extension::Subject_Key_ID>(oid);
         case 15:
            return make_extension<Cert_Extension::Key_Usage>(oid);
         case 17:
            return make_extension<Cert_Extension::Subject_Alternative_Name>(oid);
         case 18:
            return make_extension<Cert_Extension::Issuer_Alternative_Name>(oid);
         case 19:
            return make_extension<Cert_Extension::Basic_Constraints>(oid);
         case 20:
            return make_extension<Cert_Extension::CRL_Number>(oid);
         case 21:
            return make_extension<Cert_Extension::CRL_ReasonCode>(oid);
         case 28:
            return make_extension<Cert_Extension::CRL_Issuing_Distribution_Point>(oid);
         case 30:
            return make_extension<Cert_Extension::Name_Constraints>(oid);
         case 31:
            return make_extension<Cert_Extension::CRL_Distribution_Points>(oid);
         case 32:
            return make_extension<Cert_Extension::Certificate_Policies>(oid);
         case 35:
            return make_extension<Cert_Extension::Authority_Key_ID>(oid);
         case 37:
            return make_extension<Cert_Extension::Extended_Key_Usage>(oid);
         case 56:
            return make_extension<Cert_Extension::NoRevocationAvailable>(oid);
      }
   }

   if(auto pkix_ext = is_sub_element_of(oid, {1, 3, 6, 1, 5, 5, 7, 1})) {
      // NOLINTNEXTLINE(*-switch-missing-default-case)
      switch(*pkix_ext) {
         case 1:
            return make_extension<Cert_Extension::Authority_Information_Access>(oid);
         case 7:
            return make_extension<Cert_Extension::IPAddressBlocks>(oid);
         case 8:
            return make_extension<Cert_Extension::ASBlocks>(oid);
         case 26:
            return make_extension<Cert_Extension::TNAuthList>(oid);
      }
   }

   if(oid == Cert_Extension::OCSP_NoCheck::static_oid()) {
      return make_extension<Cert_Extension::OCSP_NoCheck>(oid);
   }

   return nullptr;  // unknown
}

bool is_valid_telephone_number(const ASN1_String& tn) {
   //TelephoneNumber ::= IA5String (SIZE (1..15)) (FROM ("0123456789#*"))
   const std::string valid_tn_chars("0123456789#*");

   if(tn.empty() || (tn.size() > 15)) {
      return false;
   }

   if(tn.value().find_first_not_of(valid_tn_chars) != std::string::npos) {
      return false;
   }

   return true;
}

}  // namespace

std::vector<OID> Extensions::critical_extensions() const {
   std::vector<OID> crit;

   for(const auto& oid : m_extension_oids) {
      auto ext_info = m_extension_info.find(oid);
      BOTAN_ASSERT_NOMSG(ext_info != m_extension_info.end());
      if(ext_info->second.is_critical()) {
         crit.push_back(oid);
      }
   }

   return crit;
}

/*
* Create a Certificate_Extension object of some kind to handle
*/
std::unique_ptr<Certificate_Extension> Extensions::create_extn_obj(const OID& oid,
                                                                   bool critical,
                                                                   const std::vector<uint8_t>& body,
                                                                   std::optional<Extension_Context> context) {
   auto extn = extension_from_oid(oid);

   if(!extn) {
      // some other unknown extension type
      extn = std::make_unique<Cert_Extension::Unknown_Extension>(oid, critical);
   } else {
      if(context.has_value() && !extn->is_appropriate_context(*context)) {
         throw Decoding_Error(fmt("Extension {} is not allowed in this context", extn->oid_name()));
      }

      try {
         extn->decode_inner(body);
         return extn;
      } catch(const Exception&) {
         // OID was recognized but contents failed to decode
         extn = std::make_unique<Cert_Extension::Unknown_Extension>(oid, critical, /*failed_to_decode=*/true);
      }
   }

   // This is always Unknown_Extension:
   extn->decode_inner(body);
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
                                     const std::optional<X509_Certificate>& /*unused*/,
                                     const std::vector<X509_Certificate>& /*unused*/,
                                     std::vector<std::set<Certificate_Status_Code>>& /*unused*/,
                                     size_t /*unused*/) const {}

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
   return m_extension_info.contains(oid);
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

void Extensions::validate(const X509_Certificate& subject,
                          const std::optional<X509_Certificate>& issuer,
                          const std::vector<X509_Certificate>& cert_path,
                          std::vector<std::set<Certificate_Status_Code>>& cert_status,
                          size_t pos) const {
   for(const auto& ext : m_extension_info) {
      ext.second.obj().validate(subject, issuer, cert_path, cert_status, pos);
   }
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
   for(const auto& [oid, extn] : m_extension_info) {
      const bool should_encode = extn.obj().should_encode();

      if(should_encode) {
         const auto is_critical = extn.is_critical() ? std::optional<bool>{true} : std::nullopt;
         const std::vector<uint8_t>& ext_value = extn.bits();

         to_object.start_sequence()
            .encode(oid)
            .encode_optional(is_critical)
            .encode(ext_value, ASN1_Type::OctetString)
            .end_cons();
      }
   }
}

/*
* Decode a list of Extensions
*/
void Extensions::decode_from(BER_Decoder& from_source) {
   decode_from(from_source, std::nullopt);
}

void Extensions::decode_from(BER_Decoder& from_source, std::optional<Extension_Context> context) {
   m_extension_oids.clear();
   m_extension_info.clear();
   m_has_unknown_critical_extension = false;

   BER_Decoder sequence = from_source.start_sequence();

   while(sequence.more_items()) {
      OID oid;
      bool critical = false;
      std::vector<uint8_t> bits;

      sequence.start_sequence()
         .decode(oid)
         .decode_optional(critical, ASN1_Type::Boolean, ASN1_Class::Universal, false)
         .decode(bits, ASN1_Type::OctetString)
         .end_cons();

      auto obj = create_extn_obj(oid, critical, bits, context);
      // Unknown_Extension is the only Certificate_Extension with an empty oid_name
      if(critical && obj->oid_name().empty()) {
         m_has_unknown_critical_extension = true;
      }
      Extensions_Info info(critical, bits, std::move(obj));

      // RFC 5280 4.2: "A certificate MUST NOT include more than one
      // instance of a particular extension."
      if(!m_extension_info.emplace(oid, info).second) {
         throw Decoding_Error("Duplicate certificate extension encountered");
      }
      m_extension_oids.push_back(oid);
   }
   sequence.verify_end();
}

namespace Cert_Extension {

bool Basic_Constraints::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool Key_Usage::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool Subject_Key_ID::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool Authority_Key_ID::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate || context == Extension_Context::CRL;
}

bool Subject_Alternative_Name::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool Issuer_Alternative_Name::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate || context == Extension_Context::CRL;
}

bool Extended_Key_Usage::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool Name_Constraints::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool Certificate_Policies::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool Authority_Information_Access::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate || context == Extension_Context::CRL;
}

bool CRL_Number::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::CRL;
}

bool CRL_ReasonCode::is_appropriate_context(Extension_Context context) const {
   // RFC 6960 4.4.5: "All the extensions specified as CRL entry extensions
   // -- in Section 5.3 of [RFC5280] -- are also supported as singleExtensions."
   return context == Extension_Context::CRL_Entry || context == Extension_Context::OCSP_Response;
}

bool CRL_Distribution_Points::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool CRL_Issuing_Distribution_Point::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::CRL;
}

bool OCSP_NoCheck::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool NoRevocationAvailable::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool TNAuthList::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool IPAddressBlocks::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool ASBlocks::is_appropriate_context(Extension_Context context) const {
   return context == Extension_Context::Certificate;
}

bool Unknown_Extension::is_appropriate_context(Extension_Context /*context*/) const {
   return true;
}

Basic_Constraints::Basic_Constraints(bool is_ca, size_t path_length_constraint) :
      Basic_Constraints(is_ca, is_ca ? std::optional<size_t>(path_length_constraint) : std::nullopt) {}

Basic_Constraints::Basic_Constraints(bool is_ca, std::optional<size_t> path_length_constraint) :
      m_is_ca(is_ca), m_path_length_constraint(path_length_constraint) {
   if(!m_is_ca && m_path_length_constraint.has_value()) {
      // RFC 5280 Sec 4.2.1.9 "CAs MUST NOT include the pathLenConstraint field unless the cA boolean is asserted"
      throw Invalid_Argument(
         "Basic_Constraints nonsensical to set a path length constraint for a non-CA basicConstraints");
   }
}

/*
* Checked accessor for the path_length_constraint member
*/
size_t Basic_Constraints::get_path_limit() const {
   if(m_is_ca) {
      return m_path_length_constraint.value_or(NO_CERT_PATH_LIMIT);
   } else {
      throw Invalid_State("Basic_Constraints::get_path_limit: Not a CA");
   }
}

/*
* Encode the extension
*/
std::vector<uint8_t> Basic_Constraints::encode_inner() const {
   std::vector<uint8_t> output;

   if(m_is_ca) {
      DER_Encoder(output).start_sequence().encode(m_is_ca).encode_optional(m_path_length_constraint).end_cons();
   } else {
      DER_Encoder(output).start_sequence().end_cons();
   }

   return output;
}

/*
* Decode the extension
*/
void Basic_Constraints::decode_inner(const std::vector<uint8_t>& in) {
   /*
   * RFC 5280 Section 4.2.1.9
   *
   * BasicConstraints ::= SEQUENCE {
   *    cA                      BOOLEAN DEFAULT FALSE,
   *    pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
   */
   BER_Decoder(in, BER_Decoder::Limits::DER())
      .start_sequence()
      .decode_optional(m_is_ca, ASN1_Type::Boolean, ASN1_Class::Universal, false)
      .decode_optional(m_path_length_constraint, ASN1_Type::Integer, ASN1_Class::Universal)
      .end_cons()
      .verify_end();

   /* RFC 5280 Section 4.2.1.9:
   *  "CAs MUST NOT include the pathLenConstraint field unless the cA boolean
   *  is asserted and the key usage extension asserts the keyCertSign bit" */
   if(!m_is_ca && m_path_length_constraint.has_value()) {
      throw Decoding_Error("BasicConstraints pathLenConstraint must not be present when cA is FALSE");
   }
}

/*
* Encode the extension
*/
std::vector<uint8_t> Key_Usage::encode_inner() const {
   if(m_constraints.empty()) {
      throw Encoding_Error("Cannot encode empty PKIX key constraints");
   }

   std::vector<uint8_t> der;
   DER_Encoder(der).encode_named_bitstring(m_constraints.value(), 16);
   return der;
}

/*
* Decode the extension
*/
void Key_Usage::decode_inner(const std::vector<uint8_t>& in) {
   /* RFC 5280 Section 4.2.1.3 - KeyUsage ::= BIT STRING */
   uint64_t usage = 0;
   BER_Decoder(in, BER_Decoder::Limits::DER())
      .decode_named_bitstring(usage, 16, ASN1_Type::BitString, ASN1_Class::Universal)
      .verify_end();

   /* RFC 5280 Section 4.2.1.3:
   *  "When the keyUsage extension appears in a certificate, at least one of
   *  the bits MUST be set to 1." */
   if(usage == 0) {
      throw Decoding_Error("KeyUsage extension must have at least one bit set");
   }

   m_constraints = Key_Constraints(static_cast<uint32_t>(usage));
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
   /* RFC 5280 Section 4.2.1.2 - SubjectKeyIdentifier ::= KeyIdentifier */
   BER_Decoder(in, BER_Decoder::Limits::DER()).decode(m_key_id, ASN1_Type::OctetString).verify_end();

   if(m_key_id.empty()) {
      throw Decoding_Error("SubjectKeyIdentifier must not be empty");
   }
   if(m_key_id.size() > MaximumKeyIdentifierLength) {
      throw Decoding_Error(
         fmt("SubjectKeyIdentifier length {} exceeds limit of {} bytes", m_key_id.size(), MaximumKeyIdentifierLength));
   }
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
   /*
   * RFC 5280 Section 4.2.1.1
   *
   * AuthorityKeyIdentifier ::= SEQUENCE {
   *    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
   *    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
   *    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }
   */
   BER_Decoder ber(in, BER_Decoder::Limits::DER());
   BER_Decoder seq = ber.start_sequence();

   const bool key_id_present = seq.peek_next_object().is_a(0, ASN1_Class::ContextSpecific);

   seq.decode_optional_string(m_key_id, ASN1_Type::OctetString, 0).discard_remaining().end_cons();
   ber.verify_end();

   if(key_id_present) {
      if(m_key_id.empty()) {
         throw Decoding_Error("AuthorityKeyIdentifier keyIdentifier must not be empty");
      }
      if(m_key_id.size() > MaximumKeyIdentifierLength) {
         throw Decoding_Error(fmt("AuthorityKeyIdentifier keyIdentifier length {} exceeds limit of {} bytes",
                                  m_key_id.size(),
                                  MaximumKeyIdentifierLength));
      }
   }
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
   /* RFC 5280 Section 4.2.1.6 - SubjectAltName ::= GeneralNames
   *  GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName */
   BER_Decoder(in, BER_Decoder::Limits::DER()).decode(m_alt_name).verify_end();
   if(!m_alt_name.has_items()) {
      throw Decoding_Error("SubjectAlternativeName extension must contain at least one GeneralName");
   }
}

/*
* Decode the extension
*/
void Issuer_Alternative_Name::decode_inner(const std::vector<uint8_t>& in) {
   /* RFC 5280 Section 4.2.1.7 - IssuerAltName ::= GeneralNames
   *  GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName */
   BER_Decoder(in, BER_Decoder::Limits::DER()).decode(m_alt_name).verify_end();
   if(!m_alt_name.has_items()) {
      throw Decoding_Error("IssuerAlternativeName extension must contain at least one GeneralName");
   }
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
   /* RFC 5280 Section 4.2.1.12 - ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId */
   BER_Decoder(in, BER_Decoder::Limits::DER()).decode_list(m_oids).verify_end();
   if(m_oids.empty()) {
      throw Decoding_Error("ExtendedKeyUsage extension must contain at least one KeyPurposeId");
   }
}

/*
* Encode the extension
*/
std::vector<uint8_t> Name_Constraints::encode_inner() const {
   const auto& permitted = m_name_constraints.permitted();
   const auto& excluded = m_name_constraints.excluded();

   if(permitted.empty() && excluded.empty()) {
      throw Encoding_Error("Refusing to encode empty NameConstraints");
   }

   std::vector<uint8_t> output;
   DER_Encoder der(output);
   der.start_sequence();
   if(!permitted.empty()) {
      der.start_explicit_context_specific(0).encode_list(permitted).end_cons();
   }
   if(!excluded.empty()) {
      der.start_explicit_context_specific(1).encode_list(excluded).end_cons();
   }
   der.end_cons();
   return output;
}

/*
* Decode the extension
*/
void Name_Constraints::decode_inner(const std::vector<uint8_t>& in) {
   /*
   * RFC 5280 Section 4.2.1.10
   *
   * NameConstraints ::= SEQUENCE {
   *    permittedSubtrees       [0] GeneralSubtrees OPTIONAL,
   *    excludedSubtrees        [1] GeneralSubtrees OPTIONAL }
   */
   BER_Decoder ber(in, BER_Decoder::Limits::DER());
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
   ber.verify_end();

   if(permitted.empty() && excluded.empty()) {
      throw Decoding_Error("Empty NameConstraint extension");
   }

   m_name_constraints = NameConstraints(std::move(permitted), std::move(excluded));
}

void Name_Constraints::validate(const X509_Certificate& subject,
                                const std::optional<X509_Certificate>& /*issuer*/,
                                const std::vector<X509_Certificate>& cert_path,
                                std::vector<std::set<Certificate_Status_Code>>& cert_status,
                                size_t pos) const {
   if(!m_name_constraints.permitted().empty() || !m_name_constraints.excluded().empty()) {
      if(!subject.is_CA_cert()) {
         cert_status.at(pos).insert(Certificate_Status_Code::NAME_CONSTRAINT_ERROR);
      }

      const bool issuer_name_constraint_critical = subject.is_critical("X509v3.NameConstraints");

      // Check that all subordinate certs pass the name constraint
      for(size_t j = 0; j < pos; ++j) {
         const auto& cert = cert_path.at(j);

         // RFC 5280 6.1.4(b): "Name constraints are not applied to self-issued
         // certificates (unless the certificate is the final certificate in the path)"
         // Position 0 is the end entity (final certificate); skip self-issued intermediates.
         if(j > 0 && cert.issuer_dn() == cert.subject_dn()) {
            continue;
         }

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

bool policy_oids_have_duplicate(const std::vector<OID>& oids) {
   std::set<OID> seen;
   for(const auto& oid : oids) {
      if(!seen.insert(oid).second) {
         return true;
      }
   }
   return false;
}

}  // namespace

Certificate_Policies::Certificate_Policies(const std::vector<OID>& oids) :
      m_oids(oids), m_has_duplicate(policy_oids_have_duplicate(m_oids)) {}

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
   /* RFC 5280 Section 4.2.1.4 - CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation */
   std::vector<Policy_Information> policies;

   BER_Decoder(in, BER_Decoder::Limits::DER()).decode_list(policies).verify_end();
   if(policies.empty()) {
      throw Decoding_Error("CertificatePolicies extension must contain at least one PolicyInformation");
   }
   m_oids.clear();
   for(const auto& policy : policies) {
      m_oids.push_back(policy.oid());
   }
   m_has_duplicate = policy_oids_have_duplicate(m_oids);
}

void Certificate_Policies::validate(const X509_Certificate& /*subject*/,
                                    const std::optional<X509_Certificate>& /*issuer*/,
                                    const std::vector<X509_Certificate>& /*cert_path*/,
                                    std::vector<std::set<Certificate_Status_Code>>& cert_status,
                                    size_t pos) const {
   if(m_has_duplicate) {
      cert_status.at(pos).insert(Certificate_Status_Code::DUPLICATE_CERT_POLICY);
   }
}

namespace {

std::vector<URI> parse_aia_uris(const std::vector<std::string>& uris, const char* context) {
   std::vector<URI> out;
   out.reserve(uris.size());
   for(const auto& uri : uris) {
      if(auto parsed = URI::parse(uri)) {
         out.push_back(std::move(*parsed));
      } else {
         throw Invalid_Argument(fmt("Invalid URI in {}", context));
      }
   }
   return out;
}

// Convert the application provided URIs into AccessDescription entries
std::vector<Authority_Information_Access::AccessDescription> uri_access_descriptions(
   const std::vector<URI>& ocsp_responders, const std::vector<URI>& ca_issuers) {
   std::vector<Authority_Information_Access::AccessDescription> out;
   out.reserve(ocsp_responders.size() + ca_issuers.size());

   const auto append = [&](const OID& method, const std::vector<URI>& uris) {
      for(const auto& uri : uris) {
         const ASN1_String value(uri.original_input(), ASN1_Type::Ia5String);
         out.emplace_back(method,
                          ASN1_Type(6),
                          ASN1_Class::ContextSpecific,
                          std::vector<uint8_t>(value.value().begin(), value.value().end()));
      }
   };

   append(OID::from_string("PKIX.OCSP"), ocsp_responders);
   append(OID::from_string("PKIX.CertificateAuthorityIssuers"), ca_issuers);
   return out;
}

}  // namespace

Authority_Information_Access::Authority_Information_Access(std::string_view ocsp,
                                                           const std::vector<std::string>& ca_issuers) :
      m_ca_issuers(parse_aia_uris(ca_issuers, "AuthorityInformationAccess CA issuers")) {
   if(!ocsp.empty()) {
      if(auto parsed = URI::parse(ocsp)) {
         m_ocsp_responders.push_back(std::move(*parsed));
      } else {
         throw Invalid_Argument("Invalid URI in AuthorityInformationAccess OCSP responder");
      }
   }
   m_access_descriptions = uri_access_descriptions(m_ocsp_responders, m_ca_issuers);
}

Authority_Information_Access::Authority_Information_Access(const std::vector<std::string>& ocsp_responders,
                                                           const std::vector<std::string>& ca_issuers) :
      m_ocsp_responders(parse_aia_uris(ocsp_responders, "AuthorityInformationAccess OCSP responders")),
      m_ca_issuers(parse_aia_uris(ca_issuers, "AuthorityInformationAccess CA issuers")),
      m_access_descriptions(uri_access_descriptions(m_ocsp_responders, m_ca_issuers)) {}

Authority_Information_Access::Authority_Information_Access(std::vector<URI> ocsp_responders,
                                                           std::vector<URI> ca_issuers) :
      m_ocsp_responders(std::move(ocsp_responders)),
      m_ca_issuers(std::move(ca_issuers)),
      m_access_descriptions(uri_access_descriptions(m_ocsp_responders, m_ca_issuers)) {}

std::vector<std::string> Authority_Information_Access::ocsp_responders() const {
   std::vector<std::string> out;
   out.reserve(m_ocsp_responders.size());
   for(const auto& uri : m_ocsp_responders) {
      out.push_back(uri.original_input());
   }
   return out;
}

std::unique_ptr<Certificate_Extension> Authority_Information_Access::copy() const {
   return std::make_unique<Authority_Information_Access>(*this);
}

namespace {

void validate_general_name_encoding(ASN1_Type tag, ASN1_Class cls, std::span<const uint8_t> value) {
   // AlternativeName decodes GeneralNames; AIA accessLocation is a single GeneralName.
   std::vector<uint8_t> wrapped_name;
   DER_Encoder(wrapped_name).start_sequence().add_object(tag, cls, value).end_cons();

   AlternativeName decoded_name;
   BER_Decoder(wrapped_name, BER_Decoder::Limits::DER()).decode(decoded_name).verify_end();

   if((tag == ASN1_Type(1) || tag == ASN1_Type(2) || tag == ASN1_Type(6)) && value.empty()) {
      throw Decoding_Error("GeneralName IA5String value must not be empty");
   }
   if(tag == ASN1_Type(4) &&
      std::ranges::any_of(decoded_name.directory_names(), [](const X509_DN& dn) { return dn.empty(); })) {
      throw Decoding_Error("GeneralName directoryName must not be empty");
   }
}

// Construction-time validation for an AccessDescription entering
// m_access_descriptions. encode_inner repeats this as a safety net; doing it
// here means the throw lands where the caller is building the AIA.
void validate_access_description(const Authority_Information_Access::AccessDescription& ad) {
   try {
      validate_general_name_encoding(ad.location_tag(), ad.location_class(), ad.location_value());
   } catch(const Exception&) {
      throw Invalid_Argument("AccessDescription accessLocation is not a valid GeneralName");
   }
}

// Mirror the decode-time logic that populates the typed URI accessors from
// id-ad-ocsp / id-ad-caIssuers entries. Used by the AccessDescription-based
// constructor and add_access_description so the two views stay consistent.
// An id-ad-ocsp / id-ad-caIssuers entry whose URI fails to parse is rejected
// here (mirroring decode_inner) so the typed accessors and m_access_descriptions
// cannot disagree, and so the AIA cannot re-encode bytes that its own decoder
// would reject.
void populate_uri_view_from_access_description(const Authority_Information_Access::AccessDescription& ad,
                                               std::vector<URI>& ocsp_responders,
                                               std::vector<URI>& ca_issuers) {
   const auto oid_ocsp_responders = OID::from_string("PKIX.OCSP");
   const auto oid_ca_issuers = OID::from_string("PKIX.CertificateAuthorityIssuers");
   if(const auto uri_str = ad.location_as_uri_string()) {
      if(ad.access_method() == oid_ocsp_responders) {
         if(auto uri = URI::parse(*uri_str)) {
            ocsp_responders.push_back(std::move(*uri));
         } else {
            throw Invalid_Argument("Invalid URI in AuthorityInformationAccess OCSP responder");
         }
      } else if(ad.access_method() == oid_ca_issuers) {
         if(auto uri = URI::parse(*uri_str)) {
            ca_issuers.push_back(std::move(*uri));
         } else {
            throw Invalid_Argument("Invalid URI in AuthorityInformationAccess CA issuers");
         }
      }
   }
}

}  // namespace

Authority_Information_Access::Authority_Information_Access(std::vector<AccessDescription> access_descriptions) :
      m_access_descriptions(std::move(access_descriptions)) {
   for(const auto& ad : m_access_descriptions) {
      validate_access_description(ad);
      populate_uri_view_from_access_description(ad, m_ocsp_responders, m_ca_issuers);
   }
}

void Authority_Information_Access::add_access_description(AccessDescription ad) {
   validate_access_description(ad);
   populate_uri_view_from_access_description(ad, m_ocsp_responders, m_ca_issuers);
   m_access_descriptions.push_back(std::move(ad));
}

std::vector<std::string> Authority_Information_Access::ca_issuers() const {
   std::vector<std::string> out;
   out.reserve(m_ca_issuers.size());
   for(const auto& uri : m_ca_issuers) {
      out.push_back(uri.original_input());
   }
   return out;
}

std::optional<std::string> Authority_Information_Access::AccessDescription::location_as_uri_string() const {
   if(m_location_class == ASN1_Class::ContextSpecific && m_location_tag == ASN1_Type(6)) {
      return std::string(m_location_value.begin(), m_location_value.end());
   }
   return std::nullopt;
}

std::vector<uint8_t> Authority_Information_Access::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder der(output);

   der.start_sequence();

   for(const auto& ad : m_access_descriptions) {
      try {
         validate_general_name_encoding(ad.location_tag(), ad.location_class(), ad.location_value());
      } catch(const Exception&) {
         throw Encoding_Error("AccessDescription accessLocation is not a valid GeneralName");
      }
      der.start_sequence()
         .encode(ad.access_method())
         .add_object(ad.location_tag(), ad.location_class(), ad.location_value())
         .end_cons();
   }

   der.end_cons();
   return output;
}

void Authority_Information_Access::decode_inner(const std::vector<uint8_t>& in) {
   /*
   * RFC 5280 Section 4.2.2.1
   *
   * AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
   * AccessDescription ::= SEQUENCE {
   *    accessMethod          OBJECT IDENTIFIER,
   *    accessLocation        GeneralName }
   */
   BER_Decoder outer(in, BER_Decoder::Limits::DER());
   BER_Decoder ber = outer.start_sequence();

   const OID ocsp_responder = OID::from_string("PKIX.OCSP");
   const OID ca_issuer = OID::from_string("PKIX.CertificateAuthorityIssuers");

   m_access_descriptions.clear();
   m_ocsp_responders.clear();
   m_ca_issuers.clear();

   while(ber.more_items()) {
      OID oid;

      BER_Decoder info = ber.start_sequence();

      info.decode(oid);
      const BER_Object name = info.get_next_object();

      /* RFC 5280 4.2.2.1:
      *    AccessDescription  ::=  SEQUENCE {
      *         accessMethod          OBJECT IDENTIFIER,
      *         accessLocation        GeneralName  }
      */
      if(!name.is_set()) {
         throw Decoding_Error("AuthorityInformationAccess AccessDescription missing accessLocation");
      }
      validate_general_name_encoding(name.type_tag(), name.get_class(), name.data());
      info.end_cons();

      m_access_descriptions.emplace_back(
         oid, name.type_tag(), name.get_class(), std::vector<uint8_t>(name.data().begin(), name.data().end()));

      if(name.is_a(6, ASN1_Class::ContextSpecific)) {
         if(oid == ocsp_responder) {
            if(auto parsed = URI::parse(ASN1::to_string(name))) {
               m_ocsp_responders.push_back(std::move(*parsed));
            } else {
               throw Decoding_Error("Invalid URI in AuthorityInformationAccess OCSP responder");
            }
         } else if(oid == ca_issuer) {
            if(auto parsed = URI::parse(ASN1::to_string(name))) {
               m_ca_issuers.push_back(std::move(*parsed));
            } else {
               throw Decoding_Error("Invalid URI in AuthorityInformationAccess CA issuers");
            }
         }
      }
   }

   ber.end_cons();
   outer.verify_end();

   if(m_access_descriptions.empty()) {
      throw Decoding_Error("AuthorityInformationAccess extension must contain at least one AccessDescription");
   }
}

CRL_Number::CRL_Number(BigInt n) : m_has_value(true), m_crl_number(std::move(n)) {
   BOTAN_ARG_CHECK(m_crl_number.signum() >= 0, "CRL number cannot be negative");
}

const BigInt& CRL_Number::crl_number() const {
   // This can only happen via a misuse of the CRL_Number default constructor
   BOTAN_STATE_CHECK(m_has_value);
   return m_crl_number;
}

/*
* Checked accessor for the crl_number member
*/
size_t CRL_Number::get_crl_number() const {
   // This can only happen via a misuse of the CRL_Number default constructor
   BOTAN_STATE_CHECK(m_has_value);
   return m_crl_number.to_u32bit();
}

/*
* Copy a CRL_Number extension
*/
std::unique_ptr<Certificate_Extension> CRL_Number::copy() const {
   return std::make_unique<CRL_Number>(*this);
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
   /* RFC 5280 Section 5.2.3 - CRLNumber ::= INTEGER (0..MAX) */
   BER_Decoder(in, BER_Decoder::Limits::DER()).decode(m_crl_number).verify_end();
   if(m_crl_number.signum() < 0) {
      throw Decoding_Error("CRL number cannot be negative");
   }
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
   /*
   * RFC 5280 Section 5.3.1
   *
   * CRLReason ::= ENUMERATED {
   *      unspecified             (0),
   *      keyCompromise           (1),
   *      cACompromise            (2),
   *      affiliationChanged      (3),
   *      superseded              (4),
   *      cessationOfOperation    (5),
   *      certificateHold         (6),
   *           -- value 7 is not used
   *      removeFromCRL           (8),
   *      privilegeWithdrawn      (9),
   *      aACompromise           (10) }
   */
   size_t reason_code = 0;
   BER_Decoder(in, BER_Decoder::Limits::DER())
      .decode(reason_code, ASN1_Type::Enumerated, ASN1_Class::Universal)
      .verify_end();

   if(reason_code == 7 || reason_code > 10) {
      throw Decoding_Error(fmt("CRLReason has unknown enumeration value {}", reason_code));
   }

   m_reason = static_cast<CRL_Code>(reason_code);
}

namespace {

/*
* Encode an AlternativeName as `GeneralNames` but with an outer IMPLICIT
* context-specific tag rather than the universal SEQUENCE tag. Used for
* fullName [0] / cRLIssuer [2] / similar.
*/
void emit_general_names_implicit(DER_Encoder& der, const AlternativeName& names, uint32_t tag) {
   // RFC 5280 4.2.1.6: GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
   if(!names.has_items()) {
      throw Encoding_Error("Cannot encode empty GeneralNames");
   }
   if(std::ranges::any_of(names.directory_names(), [](const X509_DN& dn) { return dn.empty(); })) {
      throw Encoding_Error("GeneralNames must not contain an empty directoryName");
   }
   der.encode_implicit(names, ASN1_Type(tag));
}

constexpr size_t ReasonFlagsNamedBitWidth = 9;

void emit_reason_flags_implicit(DER_Encoder& der, uint32_t tag, ReasonFlags reasons) {
   der.encode_named_bitstring(reasons.value(), ReasonFlagsNamedBitWidth, ASN1_Type(tag), ASN1_Class::ContextSpecific);
}

ReasonFlags decode_reason_flags_implicit(BER_Decoder& decoder, uint32_t tag) {
   uint64_t bits = 0;
   decoder.decode_named_bitstring(bits, ReasonFlagsNamedBitWidth, ASN1_Type(tag), ASN1_Class::ContextSpecific);
   return ReasonFlags(checked_cast_to<uint16_t>(bits));
}

/*
* RFC 5280 4.2.1.13: "If present, the cRLIssuer MUST only contain the
* distinguished name (DN) from the issuer field of the CRL to which the
* DistributionPoint is pointing."
*
* We don't know the value of the CRL issuer at this point so we can only
* enforce that the cRLIssuer name is exactly one non-empty DN.
*/
bool crl_issuer_is_well_formed(const AlternativeName& crl_issuer) {
   const auto& dn = crl_issuer.directory_names();
   return crl_issuer.count() == 1 && dn.size() == 1 && !dn.begin()->empty();
}

std::vector<URI> crl_distribution_point_uris_from_distribution_points(
   const std::vector<CRL_Distribution_Points::Distribution_Point>& dps) {
   std::vector<URI> out;
   for(const auto& dp : dps) {
      const auto& dpn = dp.distribution_point_name();
      if(dpn.has_value() && dpn->full_name().has_value()) {
         for(const auto& uri : dpn->full_name()->uri_names()) {
            out.push_back(uri);
         }
      }
   }
   return out;
}

}  // namespace

const AlternativeName& CRL_Distribution_Points::Distribution_Point::point() const {
   BOTAN_STATE_CHECK(m_dp_name.has_value() && m_dp_name->full_name().has_value());
   return *m_dp_name->full_name();
}

CRL_Distribution_Points::CRL_Distribution_Points(const std::vector<Distribution_Point>& points) :
      m_distribution_points(points),
      m_crl_distribution_urls(crl_distribution_point_uris_from_distribution_points(m_distribution_points)) {}

const AlternativeName& CRL_Issuing_Distribution_Point::get_point() const {
   BOTAN_STATE_CHECK(m_dp_name.has_value() && m_dp_name->full_name().has_value());
   return *m_dp_name->full_name();
}

void DistributionPointName::encode_into(DER_Encoder& der) const {
   if(!m_full_name.has_value()) {
      throw Encoding_Error("DistributionPointName has no fullName to encode");
   }
   // fullName [0] IMPLICIT GeneralNames. emit_general_names_implicit rejects
   // empty AlternativeNames per RFC 5280 4.2.1.6: GeneralNames ::= SEQUENCE
   // SIZE (1..MAX).
   emit_general_names_implicit(der, *m_full_name, 0);
}

void DistributionPointName::decode_from(BER_Decoder& ber) {
   const BER_Object& obj = ber.peek_next_object();
   if(obj.is_a(0, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      AlternativeName full_name;
      ber.decode_implicit(full_name,
                          ASN1_Type(0),
                          ASN1_Class::ContextSpecific | ASN1_Class::Constructed,
                          ASN1_Type::Sequence,
                          ASN1_Class::Constructed);
      // RFC 5280 4.2.1.6: GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
      if(!full_name.has_items()) {
         throw Decoding_Error("DistributionPointName fullName must contain at least one GeneralName");
      }
      if(std::ranges::any_of(full_name.directory_names(), [](const X509_DN& dn) { return dn.empty(); })) {
         throw Decoding_Error("DistributionPointName fullName must not contain an empty directoryName");
      }
      m_full_name = std::move(full_name);
   } else if(obj.is_a(1, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      throw Decoding_Error("nameRelativeToCrlIssuer not supported in DistributionPointName");
   } else {
      throw Decoding_Error("DistributionPointName CHOICE is neither fullName nor nameRelativeToCRLIssuer");
   }
}

std::vector<uint8_t> CRL_Distribution_Points::encode_inner() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).start_sequence().encode_list(m_distribution_points).end_cons();
   return output;
}

void CRL_Distribution_Points::decode_inner(const std::vector<uint8_t>& buf) {
   /*
   * RFC 5280 Section 4.2.1.13
   *
   * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
   */
   BER_Decoder(buf, BER_Decoder::Limits::DER()).decode_list(m_distribution_points).verify_end();

   if(m_distribution_points.empty()) {
      throw Decoding_Error("CRLDistributionPoints extension must contain at least one DistributionPoint");
   }

   m_crl_distribution_urls = crl_distribution_point_uris_from_distribution_points(m_distribution_points);
}

std::vector<std::string> CRL_Distribution_Points::crl_distribution_urls() const {
   std::vector<std::string> out;
   out.reserve(m_crl_distribution_urls.size());
   for(const auto& uri : m_crl_distribution_urls) {
      out.push_back(uri.original_input());
   }
   return out;
}

void CRL_Distribution_Points::Distribution_Point::encode_into(DER_Encoder& der) const {
   /*
   * DistributionPoint ::= SEQUENCE {
   *      distributionPoint       [0]     DistributionPointName OPTIONAL,
   *      reasons                 [1]     ReasonFlags OPTIONAL,
   *      cRLIssuer               [2]     GeneralNames OPTIONAL }
   *
   * RFC 5280 4.2.1.13: "either distributionPoint or cRLIssuer MUST be present".
   */
   const bool has_dp_name = m_dp_name.has_value();
   const bool has_crl_issuer = m_crl_issuer.has_value();
   if(!has_dp_name && !has_crl_issuer) {
      throw Encoding_Error("DistributionPoint must contain either distributionPoint or cRLIssuer");
   }
   if(has_crl_issuer && !crl_issuer_is_well_formed(*m_crl_issuer)) {
      /* RFC 5280 4.2.1.13: "If present, the cRLIssuer MUST only contain the
      * distinguished name (DN) from the issuer field of the CRL". */
      throw Encoding_Error("cRLIssuer must contain exactly one non-empty directoryName GeneralName");
   }

   der.start_sequence();

   if(has_dp_name) {
      // distributionPoint [0] EXPLICIT DistributionPointName
      der.start_explicit_context_specific(0).encode(*m_dp_name).end_cons();
   }

   if(m_reasons) {
      emit_reason_flags_implicit(der, 1, *m_reasons);
   }

   if(has_crl_issuer) {
      emit_general_names_implicit(der, *m_crl_issuer, 2);
   }

   der.end_cons();
}

void CRL_Distribution_Points::Distribution_Point::decode_from(BER_Decoder& ber) {
   /*
   * DistributionPoint ::= SEQUENCE {
   *      distributionPoint       [0]     DistributionPointName OPTIONAL,
   *      reasons                 [1]     ReasonFlags OPTIONAL,
   *      cRLIssuer               [2]     GeneralNames OPTIONAL }
   */
   BER_Decoder dp = ber.start_sequence();

   m_dp_name.reset();
   m_reasons.reset();
   m_crl_issuer.reset();

   // DER: these optional fields appear at most once and in increasing tag
   // order. Decoding them in tag order and then rejecting anything left over
   // (see end_cons below) catches out-of-order, duplicate, and unknown fields.
   dp.decode_optional_field(0,
                            ASN1_Class::ContextSpecific | ASN1_Class::Constructed,
                            [&](BER_Decoder& d) {
                               DistributionPointName name;
                               d.start_context_specific(0).decode(name).verify_end();
                               m_dp_name = std::move(name);
                            })
      .decode_optional_field(
         1, ASN1_Class::ContextSpecific, [&](BER_Decoder& d) { m_reasons = decode_reason_flags_implicit(d, 1); })
      .decode_optional_field(2, ASN1_Class::ContextSpecific | ASN1_Class::Constructed, [&](BER_Decoder& d) {
         AlternativeName crl_issuer;
         d.decode_implicit(crl_issuer,
                           ASN1_Type(2),
                           ASN1_Class::ContextSpecific | ASN1_Class::Constructed,
                           ASN1_Type::Sequence,
                           ASN1_Class::Constructed);
         m_crl_issuer = std::move(crl_issuer);
      });

   dp.end_cons();

   // RFC 5280 4.2.1.6: GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
   if(m_crl_issuer.has_value() && m_crl_issuer->is_empty()) {
      throw Decoding_Error("cRLIssuer GeneralNames must contain at least one GeneralName");
   }

   if(m_crl_issuer.has_value() && !crl_issuer_is_well_formed(*m_crl_issuer)) {
      /* RFC 5280 4.2.1.13: "If present, the cRLIssuer MUST only contain the
      * distinguished name (DN) from the issuer field of the CRL". */
      throw Decoding_Error("cRLIssuer must contain exactly one non-empty directoryName GeneralName");
   }

   if(!m_dp_name.has_value() && !m_crl_issuer.has_value()) {
      throw Decoding_Error("DistributionPoint must contain either distributionPoint or cRLIssuer");
   }
}

std::vector<uint8_t> CRL_Issuing_Distribution_Point::encode_inner() const {
   /* RFC 5280 Section 5.2.5
   *
   *    Conforming CRL issuers MUST NOT issue CRLs where the DER encoding of the
   *    issuing distribution point extension is an empty sequence. [...] at most one
   *    of onlyContainsUserCerts, onlyContainsCACerts, and onlyContainsAttributeCerts
   *    may be set to TRUE
   */
   if(!should_encode()) {
      throw Encoding_Error("Refusing to encode empty IssuingDistributionPoint");
   }

   const size_t scope_set = static_cast<size_t>(m_only_contains_user_certs) +
                            static_cast<size_t>(m_only_contains_ca_certs) +
                            static_cast<size_t>(m_only_contains_attribute_certs);
   if(scope_set > 1) {
      throw Encoding_Error(
         "At most one of onlyContainsUserCerts, onlyContainsCACerts, onlyContainsAttributeCerts may be TRUE");
   }

   auto emit_optional_boolean_implicit = [](DER_Encoder& der, uint32_t tag, bool value) {
      // All of the values encoded here are DEFAULT FALSE so skip encoding if false
      if(value == true) {
         // Encode a BOOLEAN TRUE (0xFF) as [tag] IMPLICIT BOOLEAN
         const uint8_t val = 0xFF;
         der.add_object(ASN1_Type(tag), ASN1_Class::ContextSpecific, &val, 1);
      }
   };

   std::vector<uint8_t> output;
   DER_Encoder der(output);
   der.start_sequence();

   if(m_dp_name.has_value()) {
      der.start_explicit_context_specific(0).encode(*m_dp_name).end_cons();
   }

   emit_optional_boolean_implicit(der, 1, m_only_contains_user_certs);
   emit_optional_boolean_implicit(der, 2, m_only_contains_ca_certs);

   if(m_only_some_reasons) {
      emit_reason_flags_implicit(der, 3, *m_only_some_reasons);
   }

   emit_optional_boolean_implicit(der, 4, m_indirect_crl);
   emit_optional_boolean_implicit(der, 5, m_only_contains_attribute_certs);

   der.end_cons();
   return output;
}

void CRL_Issuing_Distribution_Point::decode_inner(const std::vector<uint8_t>& buf) {
   /*
   * RFC 5280 Section 5.2.5
   *
   * IssuingDistributionPoint ::= SEQUENCE {
   *      distributionPoint          [0] DistributionPointName OPTIONAL,
   *      onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
   *      onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
   *      onlySomeReasons            [3] ReasonFlags OPTIONAL,
   *      indirectCRL                [4] BOOLEAN DEFAULT FALSE,
   *      onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
   */
   BER_Decoder outer(buf, BER_Decoder::Limits::DER());
   BER_Decoder seq = outer.start_sequence();

   m_dp_name.reset();
   m_only_contains_user_certs = false;
   m_only_contains_ca_certs = false;
   m_only_some_reasons = {};
   m_indirect_crl = false;
   m_only_contains_attribute_certs = false;

   auto decode_implicit_bool = [&](BER_Decoder& dec, uint32_t tag) -> bool {
      bool value = false;
      dec.decode(value, ASN1_Type(tag), ASN1_Class::ContextSpecific);
      return value;
   };

   // DER: these optional fields appear at most once and in increasing tag
   // order. Decoding them in tag order and then rejecting anything left over
   // (see end_cons below) catches out-of-order, duplicate, and unknown fields.
   seq.decode_optional_field(0,
                             ASN1_Class::ContextSpecific | ASN1_Class::Constructed,
                             [&](BER_Decoder& d) {
                                DistributionPointName name;
                                d.start_context_specific(0).decode(name).verify_end();
                                m_dp_name = std::move(name);
                             })
      .decode_optional_field(1,
                             ASN1_Class::ContextSpecific,
                             [&](BER_Decoder& d) { m_only_contains_user_certs = decode_implicit_bool(d, 1); })
      .decode_optional_field(
         2, ASN1_Class::ContextSpecific, [&](BER_Decoder& d) { m_only_contains_ca_certs = decode_implicit_bool(d, 2); })
      .decode_optional_field(3,
                             ASN1_Class::ContextSpecific,
                             [&](BER_Decoder& d) { m_only_some_reasons = decode_reason_flags_implicit(d, 3); })
      .decode_optional_field(
         4, ASN1_Class::ContextSpecific, [&](BER_Decoder& d) { m_indirect_crl = decode_implicit_bool(d, 4); })
      .decode_optional_field(5, ASN1_Class::ContextSpecific, [&](BER_Decoder& d) {
         m_only_contains_attribute_certs = decode_implicit_bool(d, 5);
      });

   seq.end_cons();
   outer.verify_end();

   /* RFC 5280 5.2.5: "Conforming CRLs issuers MUST NOT issue CRLs where the
   * DER encoding of the issuing distribution point extension is an empty
   * sequence." Empty here means none of the fields above were present. */
   if(!m_dp_name.has_value() && !m_only_contains_user_certs && !m_only_contains_ca_certs &&
      !m_only_some_reasons.has_value() && !m_indirect_crl && !m_only_contains_attribute_certs) {
      throw Decoding_Error("IssuingDistributionPoint must contain at least one field");
   }

   /* RFC 5280 5.2.5: "at most one of onlyContainsUserCerts,
   * onlyContainsCACerts, and onlyContainsAttributeCerts may be set to TRUE." */
   const size_t scope_set = static_cast<size_t>(m_only_contains_user_certs) +
                            static_cast<size_t>(m_only_contains_ca_certs) +
                            static_cast<size_t>(m_only_contains_attribute_certs);
   if(scope_set > 1) {
      throw Decoding_Error(
         "IssuingDistributionPoint sets more than one of onlyContainsUserCerts/CACerts/AttributeCerts");
   }
}

void TNAuthList::Entry::encode_into(DER_Encoder& /*to*/) const {
   throw Not_Implemented("TNAuthList extension entry serialization is not supported");
}

void TNAuthList::Entry::decode_from(class BER_Decoder& ber) {
   const BER_Object obj = ber.get_next_object();

   if(obj.get_class() != (ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      throw Decoding_Error(fmt("Unexpected TNEntry class tag {}", static_cast<uint32_t>(obj.get_class())));
   }

   const uint32_t type_tag = static_cast<uint32_t>(obj.type_tag());

   if(type_tag == ServiceProviderCode) {
      m_type = ServiceProviderCode;
      ASN1_String spc_string;
      BER_Decoder(obj, ber.limits()).decode(spc_string).verify_end();
      m_data = std::move(spc_string);
   } else if(type_tag == TelephoneNumberRange) {
      m_type = TelephoneNumberRange;
      m_data = RangeContainer();
      auto& range_items = std::get<RangeContainer>(m_data);
      BER_Decoder outer(obj, ber.limits());
      BER_Decoder list = outer.start_sequence();
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
      outer.verify_end();

      if(range_items.empty()) {
         throw Decoding_Error("TelephoneNumberRange is empty");
      }
   } else if(type_tag == TelephoneNumber) {
      m_type = TelephoneNumber;
      ASN1_String one_string;
      BER_Decoder(obj, ber.limits()).decode(one_string).verify_end();
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
   /* RFC 8226 Section 9 - TNAuthorizationList ::= SEQUENCE SIZE (1..MAX) OF TNEntry */
   BER_Decoder(in, BER_Decoder::Limits::DER()).decode_list(m_tn_entries).verify_end();
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
   /* RFC 3779 Section 2.2.3.1 - IPAddrBlocks ::= SEQUENCE OF IPAddressFamily */
   BER_Decoder(in, BER_Decoder::Limits::DER()).decode_list(m_ip_addr_blocks).verify_end();
   sort_and_merge();
}

void IPAddressBlocks::IPAddressFamily::encode_into(Botan::DER_Encoder& into) const {
   into.start_sequence();

   std::vector<uint8_t> afam = {get_byte<0>(m_afi), get_byte<1>(m_afi)};

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
   const ASN1_Type next_tag = from.peek_next_object().type_tag();
   if(next_tag != ASN1_Type::Sequence) {
      throw Decoding_Error(fmt("Unexpected type for IPAddressFamily {}", static_cast<uint32_t>(next_tag)));
   }

   BER_Decoder seq_dec = from.start_sequence();

   std::vector<uint8_t> addr_family;
   seq_dec.decode(addr_family, ASN1_Type::OctetString);
   const size_t addr_family_length = addr_family.size();

   if(addr_family_length != 2 && addr_family_length != 3) {
      throw Decoding_Error("(S)AFI can only contain 2 or 3 bytes");
   }

   m_afi = (addr_family[0] << 8) | addr_family[1];

   if(addr_family_length == 3) {
      m_safi = addr_family[2];
   }

   if(m_afi == 1) {
      IPAddressChoice<Version::IPv4> addr_choice;
      seq_dec.decode(addr_choice);
      m_ip_addr_choice = addr_choice;
   } else if(m_afi == 2) {
      IPAddressChoice<Version::IPv6> addr_choice;
      seq_dec.decode(addr_choice);
      m_ip_addr_choice = addr_choice;
   } else {
      throw Decoding_Error("Only AFI IPv4 and IPv6 are supported.");
   }

   seq_dec.end_cons();
}

void IPAddressBlocks::sort_and_merge() {
   // Sort IPAddressFamilies by afi/safi values
   //
   // see: https://www.rfc-editor.org/rfc/rfc3779.html#section-2.2.3.3
   //
   // v4 families are ordered before v6 families (i.e. they are sorted by afis, primarily),
   // families with no safis are ordered before families with safis
   //
   // families with the same afi/safi combination are then merged

   // std::map is ordered, so using a pair (afi, optional(safi)) here works - std::nullopt is sorted before any actual values
   std::map<std::pair<uint16_t, std::optional<uint8_t>>, std::vector<IPAddressFamily>> afam_map;
   for(const IPAddressFamily& block : m_ip_addr_blocks) {
      auto key = std::make_pair(block.afi(), block.safi());
      std::vector<IPAddressFamily>& fams = afam_map[key];
      fams.push_back(block);
   }

   std::vector<IPAddressFamily> merged_blocks;
   for(auto& it : afam_map) {
      // fams consists of families with the same afi/safi combination
      std::vector<IPAddressFamily>& fams = it.second;
      // since at least 1 block has to belong to a afi/safi combination for it to appear in the map,
      // fams cannot be empty
      BOTAN_ASSERT_NOMSG(!fams.empty());

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
   // Merge IPAddressFamilies that have the same afi/safi combination
   //
   // see: https://www.rfc-editor.org/rfc/rfc3779.html#section-2.2.3.3

   BOTAN_ASSERT(!blocks.empty(), "Cannot merge an empty set of IP address blocks into a single family");

   // nothing to merge
   if(blocks.size() == 1) {
      return blocks[0];
   }

   bool all_inherit = true;
   bool none_inherit = true;
   for(const IPAddressFamily& block : blocks) {
      const IPAddressChoice<V> choice = std::get<IPAddressChoice<V>>(block.addr_choice());
      all_inherit = !choice.ranges().has_value() && all_inherit;  // all the blocks have the 'inherit' value
      none_inherit = choice.ranges().has_value() && none_inherit;
   }

   // they are all 'inherit', short-circuit using default constructor for nullopt
   if(all_inherit) {
      return IPAddressFamily(IPAddressChoice<V>(), blocks[0].safi());
   }

   // some are inherit, and some have values - no sensible way to merge them
   if(!all_inherit && !none_inherit) {
      throw Decoding_Error("Invalid IPAddressBlocks: Only one of 'inherit' or 'do not inherit' is allowed per family");
   }

   std::vector<IPAddressOrRange<V>> merged_ranges;
   for(const IPAddressFamily& block : blocks) {
      const IPAddressChoice<V> choice = std::get<IPAddressChoice<V>>(block.addr_choice());
      const std::vector<IPAddressOrRange<V>> ranges = choice.ranges().value();
      for(const IPAddressOrRange<V>& r : ranges) {
         merged_ranges.push_back(r);
      }
   }

   // we have extracted all the ranges, and now rely on the constructor of IPAddressChoice to merge them
   IPAddressChoice<V> choice(merged_ranges);
   IPAddressFamily fam(choice, blocks[0].safi());
   return fam;
}

namespace {

constexpr auto IPv4 = IPAddressBlocks::Version::IPv4;
constexpr auto IPv6 = IPAddressBlocks::Version::IPv6;

template <IPAddressBlocks::Version V>
using IPRangeVec = std::vector<IPAddressBlocks::IPAddressOrRange<V>>;

// (S)AFI -> (needs_check, ptr to IPRangeVec)
// the pointer can be null, in which case the boolean will be false, as such the pointer's value will never be looked at
template <IPAddressBlocks::Version V>
using IPValidationMap = std::map<uint32_t, std::pair<bool, const IPRangeVec<V>*>>;

template <typename T>
std::optional<std::vector<T>> sort_and_merge_ranges(std::optional<std::span<const T>> ranges) {
   // Sort and merge overlapping/adjacent IPAddressOrRange or ASIdOrRange objects.
   // cf. https://www.rfc-editor.org/rfc/rfc3779.html#section-2.2.3.6 and https://www.rfc-editor.org/rfc/rfc3779.html#section-3.2.3.4
   // This implementation uses only min-max ranges internally, so sorting by the prefix length is not necessary / impossible here.

   if(!ranges.has_value()) {
      return std::nullopt;
   }

   std::vector<T> sorted(ranges.value().begin(), ranges.value().end());

   if(sorted.empty()) {
      return sorted;
   }

   // sort by the min value
   std::sort(sorted.begin(), sorted.end(), [](T& a, T& b) { return a.min() < b.min(); });

   // Single-pass merge: extend the last merged range or start a new one
   std::vector<T> merged;
   merged.reserve(sorted.size());
   merged.push_back(sorted[0]);

   for(size_t i = 1; i < sorted.size(); ++i) {
      auto& back = merged.back();
      // they either overlap or are adjacent
      if(sorted[i].min() <= back.max() || sorted[i].min() == (back.max() + 1)) {
         back = T(back.min(), std::max(back.max(), sorted[i].max()));
      } else {
         merged.push_back(sorted[i]);
      }
   }

   return merged;
}

template <typename T>
bool validate_subject_in_issuer(std::span<const T> subject, std::span<const T> issuer) {
   // ensures that the subject ranges are enclosed by the issuer ranges
   // both vectors are already sorted, so we can do this in O(n+m)

   // the issuer has 0 ranges to validate against, so this can only work if the subject also has none
   if(issuer.empty()) {
      return subject.empty();
   }
   for(auto subj = subject.begin(), issu = issuer.begin(); subj != subject.end();) {
      // the issuer range is smaller than the subject range, step to the next issuer range to check next round
      if(subj->min() > issu->max()) {
         issu++;
         // we have run out of issuer ranges, but still have subject ranges left to validate
         if(issu == issuer.end() && subj != subject.end()) {
            return false;
         }
      } else {
         // the subject is outside of the closest issuer range on the left (min) side
         if(subj->min() < issu->min()) {
            return false;
         }
         // the subject is outside of the closest issuer range on the right (max) side
         if(subj->max() > issu->max()) {
            return false;
         }
         // this range is contained within the issuer, advance to the next subject range
         subj++;
      }
   }
   return true;
}

template <IPAddressBlocks::Version V>
void populate_validation_map(uint32_t afam,
                             const IPAddressBlocks::IPAddressFamily::AddrChoice& choice,
                             IPValidationMap<V>& map) {
   const std::optional<IPRangeVec<V>>& ranges = std::get<IPAddressBlocks::IPAddressChoice<V>>(choice).ranges();
   const bool has_value = ranges.has_value();
   const IPRangeVec<V>* value = has_value ? &ranges.value() : nullptr;
   map.emplace(afam, std::make_pair(has_value, std::move(value)));
}

std::pair<IPValidationMap<IPv4>, IPValidationMap<IPv6>> create_validation_map(
   const std::vector<IPAddressBlocks::IPAddressFamily>& addr_blocks) {
   IPValidationMap<IPv4> v4_map;
   IPValidationMap<IPv6> v6_map;

   for(const IPAddressBlocks::IPAddressFamily& block : addr_blocks) {
      uint32_t afam = block.afi();
      if(block.safi().has_value()) {
         afam = static_cast<uint32_t>(afam << 8) | block.safi().value();
      }

      const IPAddressBlocks::IPAddressFamily::AddrChoice& a_choice = block.addr_choice();
      if(std::holds_alternative<IPAddressBlocks::IPAddressChoice<IPv4>>(a_choice)) {
         populate_validation_map(afam, a_choice, v4_map);
      } else {
         populate_validation_map(afam, a_choice, v6_map);
      }
   }

   return std::make_pair(v4_map, v6_map);
}

}  // namespace

template <IPAddressBlocks::Version V>
IPAddressBlocks::IPAddressChoice<V>::IPAddressChoice(
   std::optional<std::span<const IPAddressBlocks::IPAddressOrRange<V>>> ranges) {
   // NOLINTNEXTLINE(*-prefer-member-initializer)
   m_ip_addr_ranges = sort_and_merge_ranges<IPAddressOrRange<V>>(ranges);
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
   const ASN1_Type next_tag = from.peek_next_object().type_tag();

   if(next_tag == ASN1_Type::Null) {
      from.decode_null();
      m_ip_addr_ranges = std::nullopt;
   } else if(next_tag == ASN1_Type::Sequence) {
      std::vector<IPAddressOrRange<V>> ip_ranges;
      from.decode_list(ip_ranges);
      m_ip_addr_ranges = sort_and_merge_ranges<IPAddressOrRange<V>>(ip_ranges);
   } else {
      throw Decoding_Error(fmt("Unexpected type for IPAddressChoice {}", static_cast<uint32_t>(next_tag)));
   }
}

template <IPAddressBlocks::Version V>
void IPAddressBlocks::IPAddressOrRange<V>::encode_into(Botan::DER_Encoder& into) const {
   // Compress IPAddressOrRange as much as possible
   // cf. https://www.rfc-editor.org/rfc/rfc3779.html#section-2.2.3.7 - https://www.rfc-editor.org/rfc/rfc3779.html#section-2.2.3.9
   //
   // If possible encode as a prefix x.x.x.x/x, else encode as a range of min-max.
   // Single addresses are encoded as is (technically a /32 or /128 prefix).
   //
   // A range can be encoded as a prefix if the lowest n bits of the min address are 0
   // and the highest n bits of the max address are 1, or in other words, contiguous sequences of 0s and 1s are omitted.
   // To make reconstruction possible, an 'unused' octet is included at the start, since in the case of e.g. /25 only
   // the highest bit of the last octet is actually meaningful.
   //
   // If encoding requires a range, the individual elements can still be compressed using the above method,
   // but the number of used bits varies between them.

   const size_t version_octets = static_cast<size_t>(V);

   std::array<uint8_t, version_octets> min = m_min.value();
   std::array<uint8_t, version_octets> max = m_max.value();

   uint8_t zeros = 0;
   uint8_t ones = 0;

   bool zeros_done = false;
   bool ones_done = false;

   // count contiguous 0s/1s from the right of the min/max addresses
   for(size_t i = version_octets; i > 0; i--) {
      if(!zeros_done) {
         const uint8_t local_zeros = static_cast<uint8_t>(std::countr_zero(min[i - 1]));
         zeros += local_zeros;
         zeros_done = (local_zeros != 8);
      }

      if(!ones_done) {
         const uint8_t local_ones = static_cast<uint8_t>(std::countr_one(max[i - 1]));
         ones += local_ones;
         ones_done = (local_ones != 8);
      }

      if(zeros_done && ones_done) {
         break;
      }
   }

   // the part we want to compress
   const uint8_t host = std::min(zeros, ones);

   // these we can outright drop
   const uint8_t discarded_octets = host / 8;
   // in a partially used octet
   const uint8_t unused_bits = host % 8;

   bool octets_match = true;
   bool used_bits_match = true;

   // we have octets to check
   if(discarded_octets < version_octets) {
      // check all but the last octet
      for(size_t i = 0; i < static_cast<uint8_t>(version_octets - discarded_octets - 1); i++) {
         if(min[i] != max[i]) {
            octets_match = false;
            break;
         }
      }
      // check the last significant octet if we have matched so far
      if(octets_match) {
         const uint8_t shifted_min = (min[version_octets - 1 - discarded_octets] >> unused_bits);
         const uint8_t shifted_max = (max[version_octets - 1 - discarded_octets] >> unused_bits);
         used_bits_match = (shifted_min == shifted_max);
      }
   }

   // both the full octets and the partially used one match
   if(octets_match && used_bits_match) {
      // at this point the range can be encoded as a prefix
      into.encode_bitstring(std::span{min}.first(version_octets - discarded_octets), unused_bits);
   } else {
      const uint8_t discarded_octets_min = zeros / 8;
      const uint8_t unused_bits_min = zeros % 8;

      const uint8_t discarded_octets_max = ones / 8;
      const uint8_t unused_bits_max = ones % 8;

      // compress the max address by setting unused bits to 0, for the min address these are already 0
      if(unused_bits_max != 0) {
         BOTAN_ASSERT_NOMSG(discarded_octets_max < version_octets);
         max[version_octets - 1 - discarded_octets_max] >>= unused_bits_max;
         max[version_octets - 1 - discarded_octets_max] <<= unused_bits_max;
      }

      into.start_sequence()
         .encode_bitstring(std::span{min}.first(version_octets - discarded_octets_min), unused_bits_min)
         .encode_bitstring(std::span{max}.first(version_octets - discarded_octets_max), unused_bits_max)
         .end_cons();
   }
}

template <IPAddressBlocks::Version V>
void IPAddressBlocks::IPAddressOrRange<V>::decode_from(Botan::BER_Decoder& from) {
   const ASN1_Type next_tag = from.peek_next_object().type_tag();

   // this can either be a prefix or a single address
   if(next_tag == ASN1_Type::BitString) {
      // construct a min and a max address from the prefix

      ASN1_BitString prefix;
      from.decode_bitstring(prefix);

      // min address gets filled with 0's
      m_min = decode_single_address(prefix, true);
      // max address with 1's
      m_max = decode_single_address(prefix, false);
   } else if(next_tag == ASN1_Type::Sequence) {
      // this is a range

      ASN1_BitString addr_min;
      ASN1_BitString addr_max;

      from.start_sequence().decode_bitstring(addr_min).decode_bitstring(addr_max).end_cons();

      m_min = decode_single_address(addr_min, true);
      m_max = decode_single_address(addr_max, false);

      if(m_min > m_max) {
         throw Decoding_Error("IP address ranges must be sorted.");
      }
   } else {
      throw Decoding_Error(fmt("Unexpected type for IPAddressOrRange {}", static_cast<uint32_t>(next_tag)));
   }
}

template <IPAddressBlocks::Version V>
IPAddressBlocks::IPAddress<V> IPAddressBlocks::IPAddressOrRange<V>::decode_single_address(const ASN1_BitString& decoded,
                                                                                          bool min) {
   const size_t version_octets = static_cast<size_t>(V);

   // decode a single address according to https://datatracker.ietf.org/doc/html/rfc3779#section-2.1.1 and following

   if(decoded.bytes().size() > version_octets) {
      throw Decoding_Error(fmt("IP address range entries must have a length between 0 and {} bytes.", version_octets));
   }

   const uint8_t unused = static_cast<uint8_t>(decoded.unused_bits());
   const uint8_t discarded_octets = version_octets - static_cast<uint8_t>(decoded.bytes().size());

   std::vector<uint8_t> address(decoded.bytes().begin(), decoded.bytes().end());

   if(address.empty() && unused != 0) {
      throw Decoding_Error("IP address range entry specified unused bits, but did not provide any octets.");
   }

   // pad to version length with 0's for min addresses, 255's (0xff) for max addresses
   const uint8_t fill_discarded = min ? 0 : 0xff;
   for(size_t i = 0; i < discarded_octets; i++) {
      address.push_back(fill_discarded);
   }

   // for min addresses they should already be 0, but we set them to zero regardless
   // for max addresses this turns the unused bits to 1
   for(size_t i = 0; i < unused; i++) {
      if(min) {
         address[version_octets - 1 - discarded_octets] &= ~(1 << i);
      } else {
         address[version_octets - 1 - discarded_octets] |= (1 << i);
      }
   }

   return IPAddressBlocks::IPAddress<V>(address);
}

template <IPAddressBlocks::Version V>
IPAddressBlocks::IPAddress<V>::IPAddress(std::span<const uint8_t> v) {
   if(v.size() != Length) {
      throw Decoding_Error("number of bytes does not match IP version used");
   }

   for(size_t i = 0; i < Length; i++) {
      m_value[i] = v[i];
   }
}

void IPAddressBlocks::validate(const X509_Certificate& /* unused */,
                               const std::optional<X509_Certificate>& /* unused */,
                               const std::vector<X509_Certificate>& cert_path,
                               std::vector<std::set<Certificate_Status_Code>>& cert_status,
                               size_t pos) const {
   // maps in the form of (s)afi -> (needs_checking, ranges)
   auto [v4_needs_check, v6_needs_check] = create_validation_map(m_ip_addr_blocks);

   if(pos == cert_path.size() - 1) {
      // checks if any range / family has 'inherit' as a value somewhere, not allowed for the root cert
      auto validate_root_cert_ext = [&](const auto& map) {
         // check if any range has a value of 'false', indicating 'inherit'
         return std::any_of(map.begin(), map.end(), [&](const auto& it) {
            const auto& [_1, validation_info] = it;
            const auto& [needs_checking, _2] = validation_info;
            return !needs_checking;
         });
      };
      if(validate_root_cert_ext(v4_needs_check) || validate_root_cert_ext(v6_needs_check)) {
         cert_status.at(pos).insert(Certificate_Status_Code::IPADDR_BLOCKS_ERROR);
      }
      return;
   }

   // traverse the chain until we find a cert with concrete values for the extension (so not 'inherit')
   for(auto cert_path_it = cert_path.begin() + pos + 1; cert_path_it != cert_path.end(); cert_path_it++) {
      const IPAddressBlocks* const parent_ip = cert_path_it->v3_extensions().get_extension_object_as<IPAddressBlocks>();
      // extension not present for parent
      if(parent_ip == nullptr) {
         cert_status.at(pos).insert(Certificate_Status_Code::IPADDR_BLOCKS_ERROR);
         return;
      }
      auto [issuer_v4, issuer_v6] = create_validation_map(parent_ip->addr_blocks());

      auto validate_against_issuer = [&](auto& subject_map, const auto& issuer_map) {
         for(auto map_it = subject_map.begin(); map_it != subject_map.end(); map_it++) {
            auto& [afam, validation_info] = *map_it;

            // the issuer does not have this combination of afi/safi
            if(issuer_map.count(afam) == 0) {
               cert_status.at(pos).insert(Certificate_Status_Code::IPADDR_BLOCKS_ERROR);
               return false;
            }

            auto& [needs_check, subject_value] = validation_info;
            const auto& [issuer_has_value, issuer_value] = issuer_map.at(afam);
            BOTAN_ASSERT_NOMSG(!needs_check || subject_value != nullptr);
            BOTAN_ASSERT_NOMSG(!issuer_has_value || issuer_value != nullptr);

            // we still need to check this range and the issuer has an actual value for it (so not 'inherit')
            if(needs_check && issuer_has_value) {
               if(!validate_subject_in_issuer(std::span(*subject_value), std::span(*issuer_value))) {
                  cert_status.at(pos).insert(Certificate_Status_Code::IPADDR_BLOCKS_ERROR);
                  return false;
               }
               needs_check = false;
            }
         }
         return true;
      };

      if(!validate_against_issuer(v4_needs_check, issuer_v4) || !validate_against_issuer(v6_needs_check, issuer_v6)) {
         return;
      }

      auto validate_no_checks_left = [&](const auto& map) {
         // check if all ranges have been checked, either by comparing their ranges if they have any,
         // or if they are inherit, their parent(s) will be validated later
         return std::all_of(map.begin(), map.end(), [&](const auto& it) {
            const auto& [_1, validation_info] = it;
            const auto& [needs_checking, _2] = validation_info;
            return !needs_checking;
         });
      };

      if(validate_no_checks_left(v4_needs_check) && validate_no_checks_left(v6_needs_check)) {
         // we've validated what we need to and can stop traversing the cert chain
         return;
      }
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
   /* RFC 3779 Section 3.2.3.1 - ASIdentifiers ::= SEQUENCE { ... } */
   BER_Decoder(in, BER_Decoder::Limits::DER()).decode(m_as_identifiers).verify_end();
}

ASBlocks::ASIdentifierChoice ASBlocks::add_new(const std::optional<ASIdentifierChoice>& old, asnum_t min, asnum_t max) {
   std::vector<ASIdOrRange> range;
   if(!old.has_value() || !old.value().ranges().has_value()) {
      range = {ASIdOrRange(min, max)};
   } else {
      range = old.value().ranges().value();
      range.push_back(ASIdOrRange(min, max));
   }
   return ASIdentifierChoice(range);
}

void ASBlocks::ASIdentifiers::encode_into(Botan::DER_Encoder& into) const {
   into.start_sequence();

   if(!m_asnum.has_value() && !m_rdi.has_value()) {
      throw Encoding_Error("One of asnum, rdi must be present");
   }

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
   const ASN1_Type next_tag = from.peek_next_object().type_tag();
   if(next_tag != ASN1_Type::Sequence) {
      throw Decoding_Error(fmt("Unexpected type for ASIdentifiers {}", static_cast<uint32_t>(next_tag)));
   }

   BER_Decoder seq_dec = from.start_sequence();

   const BER_Object elem_obj = seq_dec.get_next_object();
   const uint32_t elem_type_tag = static_cast<uint32_t>(elem_obj.type_tag());

   // asnum, potentially followed by an rdi
   if(elem_type_tag == 0) {
      BER_Decoder as_obj_ber = BER_Decoder(elem_obj, seq_dec.limits());
      ASIdentifierChoice asnum;
      as_obj_ber.decode(asnum).verify_end();
      m_asnum = asnum;

      const BER_Object rdi_obj = seq_dec.get_next_object();
      const ASN1_Type rdi_type_tag = rdi_obj.type_tag();
      if(static_cast<uint32_t>(rdi_type_tag) == 1) {
         BER_Decoder rdi_obj_ber = BER_Decoder(rdi_obj, seq_dec.limits());
         ASIdentifierChoice rdi;
         rdi_obj_ber.decode(rdi).verify_end();
         m_rdi = rdi;
      } else if(rdi_type_tag != ASN1_Type::NoObject) {
         throw Decoding_Error(fmt("Unexpected type for ASIdentifiers rdi: {}", static_cast<uint32_t>(rdi_type_tag)));
      }
   }

   // just an rdi
   if(elem_type_tag == 1) {
      BER_Decoder rdi_obj_ber = BER_Decoder(elem_obj, seq_dec.limits());
      ASIdentifierChoice rdi;
      rdi_obj_ber.decode(rdi).verify_end();
      m_rdi = rdi;
      const BER_Object end = seq_dec.get_next_object();
      const ASN1_Type end_type_tag = end.type_tag();
      if(end_type_tag != ASN1_Type::NoObject) {
         throw Decoding_Error(
            fmt("Unexpected element with type {} in ASIdentifiers", static_cast<uint32_t>(end_type_tag)));
      }
   }

   seq_dec.end_cons();

   if(!m_asnum.has_value() && !m_rdi.has_value()) {
      throw Decoding_Error("Invalid encoding for ASIdentifiers");
   }
}

void ASBlocks::ASIdentifierChoice::encode_into(Botan::DER_Encoder& into) const {
   if(m_as_ranges.has_value()) {
      into.start_sequence().encode_list(m_as_ranges.value()).end_cons();
   } else {
      into.encode_null();
   }
}

ASBlocks::ASIdentifierChoice::ASIdentifierChoice(const std::optional<std::vector<ASIdOrRange>>& ranges) {
   m_as_ranges = sort_and_merge_ranges<ASIdOrRange>(ranges);
}

void ASBlocks::ASIdentifierChoice::decode_from(Botan::BER_Decoder& from) {
   const ASN1_Type next_tag = from.peek_next_object().type_tag();

   if(next_tag == ASN1_Type::Null) {
      from.decode_null();
      m_as_ranges = std::nullopt;
   } else if(next_tag == ASN1_Type::Sequence) {
      std::vector<ASIdOrRange> as_ranges;
      from.decode_list(as_ranges);

      m_as_ranges = sort_and_merge_ranges<ASIdOrRange>(as_ranges);
   } else {
      throw Decoding_Error(fmt("Unexpected type for ASIdentifierChoice {}", static_cast<uint32_t>(next_tag)));
   }
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
   const ASN1_Type next_tag = from.peek_next_object().type_tag();

   size_t min = 0;
   size_t max = 0;

   if(next_tag == ASN1_Type::Integer) {
      from.decode(min);
      m_min = checked_cast_to<asnum_t>(min);
      m_max = m_min;
   } else if(next_tag == ASN1_Type::Sequence) {
      from.start_sequence().decode(min).decode(max).end_cons();
      m_min = checked_cast_to<asnum_t>(min);
      m_max = checked_cast_to<asnum_t>(max);
      if(m_min >= m_max) {
         throw Decoding_Error("ASIdOrRange has min greater than max");
      }
   } else {
      throw Decoding_Error(fmt("Unexpected type for ASIdOrRange {}", static_cast<uint32_t>(next_tag)));
   }
}

void ASBlocks::validate(const X509_Certificate& /* unused */,
                        const std::optional<X509_Certificate>& /* unused */,
                        const std::vector<X509_Certificate>& cert_path,
                        std::vector<std::set<Certificate_Status_Code>>& cert_status,
                        size_t pos) const {
   // the extension may not contain asnums or rdis, but one of them is always present
   const bool asnum_present = m_as_identifiers.asnum().has_value();
   const bool rdi_present = m_as_identifiers.rdi().has_value();

   if(!asnum_present && !rdi_present) {
      // Invalid, should have been caught during decoding
      cert_status.at(pos).insert(Certificate_Status_Code::AS_BLOCKS_ERROR);
      return;
   }

   bool asnum_needs_check = asnum_present ? m_as_identifiers.asnum().value().ranges().has_value() : false;
   bool rdi_needs_check = rdi_present ? m_as_identifiers.rdi().value().ranges().has_value() : false;

   // we are at the (trusted) root cert, there is no parent to verify against
   if(pos == cert_path.size() - 1) {
      // asnum / rdi is present, but has 'inherit' value, but there is nothing to inherit from
      if((asnum_present && !asnum_needs_check) || (rdi_present && !rdi_needs_check)) {
         cert_status.at(pos).insert(Certificate_Status_Code::AS_BLOCKS_ERROR);
      }
      return;
   }

   // traverse the chain until we find a cert with concrete values for the extension (so not 'inherit')
   for(auto it = cert_path.begin() + pos + 1; it != cert_path.end(); it++) {
      const ASBlocks* const parent_as = it->v3_extensions().get_extension_object_as<ASBlocks>();
      // no extension at all or no asnums or no rdis (if needed)
      if(parent_as == nullptr || (asnum_present && !parent_as->as_identifiers().asnum().has_value()) ||
         (rdi_present && !parent_as->as_identifiers().rdi().has_value())) {
         cert_status.at(pos).insert(Certificate_Status_Code::AS_BLOCKS_ERROR);
         return;
      }
      const auto as_identifiers = parent_as->as_identifiers();

      // only something to validate if the subject does not have 'inherit' as a value
      if(asnum_needs_check && as_identifiers.asnum().value().ranges().has_value()) {
         const std::vector<ASBlocks::ASIdOrRange>& subject_asnums = m_as_identifiers.asnum()->ranges().value();
         const std::vector<ASBlocks::ASIdOrRange>& issuer_asnums = as_identifiers.asnum()->ranges().value();

         if(!validate_subject_in_issuer<ASBlocks::ASIdOrRange>(subject_asnums, issuer_asnums)) {
            cert_status.at(pos).insert(Certificate_Status_Code::AS_BLOCKS_ERROR);
            return;
         }
         // successfully validated the asnums, but we may need to step further for rdis
         asnum_needs_check = false;
      }

      if(rdi_needs_check && as_identifiers.rdi().value().ranges().has_value()) {
         const std::vector<ASBlocks::ASIdOrRange>& subject_rdis = m_as_identifiers.rdi()->ranges().value();
         const std::vector<ASBlocks::ASIdOrRange>& issuer_rdis = as_identifiers.rdi()->ranges().value();

         if(!validate_subject_in_issuer<ASBlocks::ASIdOrRange>(subject_rdis, issuer_rdis)) {
            cert_status.at(pos).insert(Certificate_Status_Code::AS_BLOCKS_ERROR);
            return;
         }
         // successfully validated the rdis, but we may need to step further for asnums
         rdi_needs_check = false;
      }

      if(!asnum_needs_check && !rdi_needs_check) {
         // we've validated what we need to and can stop traversing the cert chain
         return;
      }
   }
}

void OCSP_NoCheck::validate(const X509_Certificate& subject,
                            const std::optional<X509_Certificate>& /*issuer*/,
                            const std::vector<X509_Certificate>& /*cert_path*/,
                            std::vector<std::set<Certificate_Status_Code>>& cert_status,
                            size_t pos) const {
   /*
   * RFC 6960 is not particularly explicit about when id-pkix-ocsp-nocheck can
   * or cannot be included in a certificate, but reasonably we should require
   * that id-pkix-ocsp-nocheck is only included for certificates that are marked
   * as OCSP responders. This checks for compatible key usage and also the OCSP
   * signer extended key usage.
   */
   if(!subject.allowed_usage(Usage_Type::OCSP_RESPONDER)) {
      cert_status.at(pos).insert(Certificate_Status_Code::INVALID_OCSP_NOCHECK);
   }
}

std::vector<uint8_t> OCSP_NoCheck::encode_inner() const {
   return {0x05, 0x00};  // NULL
}

void OCSP_NoCheck::decode_inner(const std::vector<uint8_t>& buf) {
   /* RFC 6960 Section 4.2.2.2.1 - id-pkix-ocsp-nocheck (value SHALL be NULL) */
   BER_Decoder(buf, BER_Decoder::Limits::DER()).decode_null().verify_end();
}

std::vector<uint8_t> NoRevocationAvailable::encode_inner() const {
   return {0x05, 0x00};  // NULL
}

void NoRevocationAvailable::decode_inner(const std::vector<uint8_t>& buf) {
   // RFC 9608 Section 2, it's just a NULL
   BER_Decoder(buf, BER_Decoder::Limits::DER()).decode_null().verify_end();
}

void NoRevocationAvailable::validate(const X509_Certificate& subject,
                                     const std::optional<X509_Certificate>& /*issuer*/,
                                     const std::vector<X509_Certificate>& /*cert_path*/,
                                     std::vector<std::set<Certificate_Status_Code>>& cert_status,
                                     size_t pos) const {
   // RFC 9608 Section 2:
   //    This extension MUST NOT be present in CA public key certificates.
   //
   // RFC 9608 Section 3:
   //    Certificates that include the noRevAvail extension MUST NOT include
   //    certificate extensions that point to CRL repositories or provide
   //    locations of OCSP responders.
   //
   // Additionally (and unusually) the requirements of RFC 9608 Section 3
   // are not just on issuing parties but also on verifiers:
   //
   //   If any of the above are violated in a certificate, then the relying
   //   party MUST consider the certificate invalid.

   const Extensions& exts = subject.v3_extensions();

   if(const auto* bc = exts.get_extension_object_as<Basic_Constraints>(); bc != nullptr && bc->is_ca()) {
      // RFC 9608 Section 3:
      //    The certificate MUST NOT also include the basic constraints
      //    certificate extension with the cA BOOLEAN set to TRUE
      cert_status.at(pos).insert(Certificate_Status_Code::NO_REV_AVAIL_INVALID_USE);
   }

   // RFC 9608 Section 3:
   //    The certificate MUST NOT also include the CRL Distribution Points
   //    certificate extension
   if(exts.extension_set(CRL_Distribution_Points::static_oid())) {
      cert_status.at(pos).insert(Certificate_Status_Code::NO_REV_AVAIL_INVALID_USE);
   }

   // RFC 9608 Section 3:
   //    The certificate MUST NOT also include the Freshest CRL certificate
   //    extension
   if(exts.extension_set(OID({2, 5, 29, 46}))) {
      cert_status.at(pos).insert(Certificate_Status_Code::NO_REV_AVAIL_INVALID_USE);
   }

   // RFC 9608 Section 3:
   //    The Authority Information Access certificate extension, if
   //    present, MUST NOT include an id-ad-ocsp accessMethod
   //
   // Walk the raw AccessDescription list rather than the URI-only typed
   // accessor so a non-URI OCSP accessLocation also triggers the rejection.
   if(const auto* aia = exts.get_extension_object_as<Authority_Information_Access>(); aia != nullptr) {
      const OID id_ad_ocsp = OID::from_string("PKIX.OCSP");
      const bool has_ocsp = !aia->ocsp_responder_uris().empty() ||
                            std::ranges::any_of(aia->access_descriptions(),
                                                [&](const auto& ad) { return ad.access_method() == id_ad_ocsp; });
      if(has_ocsp) {
         cert_status.at(pos).insert(Certificate_Status_Code::NO_REV_AVAIL_INVALID_USE);
      }
   }
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
