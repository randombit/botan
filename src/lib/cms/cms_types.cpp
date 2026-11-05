/*
* CMS common types
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cms.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/x509cert.h>
#include <botan/internal/cms_helpers.h>
#include <botan/internal/stl_util.h>

namespace Botan::CMS {

IssuerAndSerialNumber::IssuerAndSerialNumber(const X509_Certificate& cert) :
      m_issuer(cert.issuer_dn()), m_serial(cert.serial()) {}

void IssuerAndSerialNumber::encode_into(DER_Encoder& to) const {
   to.start_sequence().encode(m_issuer).encode(m_serial).end_cons();
}

void IssuerAndSerialNumber::decode_from(BER_Decoder& from) {
   from.start_sequence().decode(m_issuer).decode(m_serial).end_cons();
}

bool IssuerAndSerialNumber::matches(const X509_Certificate& cert) const {
   return cert.serial() == m_serial && cert.issuer_dn() == m_issuer;
}

SignerIdentifier::SignerIdentifier(const X509_Certificate& cert) : m_id(IssuerAndSerialNumber(cert)) {}

const IssuerAndSerialNumber& SignerIdentifier::issuer_and_serial() const {
   const auto* iasn = std::get_if<IssuerAndSerialNumber>(&m_id);
   BOTAN_STATE_CHECK(iasn != nullptr);
   return *iasn;
}

const std::vector<uint8_t>& SignerIdentifier::subject_key_id() const {
   const auto* skid = std::get_if<std::vector<uint8_t>>(&m_id);
   BOTAN_STATE_CHECK(skid != nullptr);
   return *skid;
}

void SignerIdentifier::encode_into(DER_Encoder& to) const {
   std::visit(overloaded{[&](const IssuerAndSerialNumber& iasn) { to.encode(iasn); },
                         [&](const std::vector<uint8_t>& skid) {
                            to.add_object(ASN1_Type(0), ASN1_Class::ContextSpecific, skid);
                         }},
              m_id);
}

void SignerIdentifier::decode_from(BER_Decoder& from) {
   BER_Object obj = from.get_next_object();

   if(obj.is_a(ASN1_Type::Sequence, ASN1_Class::Constructed)) {
      from.push_back(std::move(obj));
      IssuerAndSerialNumber iasn;
      from.decode(iasn);
      m_id = std::move(iasn);
   } else if(obj.is_a(ASN1_Type(0), ASN1_Class::ContextSpecific)) {
      m_id = std::vector<uint8_t>(obj.bits(), obj.bits() + obj.length());
   } else {
      throw Decoding_Error("Unexpected tag for CMS SignerIdentifier");
   }
}

bool SignerIdentifier::matches(const X509_Certificate& cert) const {
   return std::visit(
      overloaded{[&](const IssuerAndSerialNumber& iasn) { return iasn.matches(cert); },
                 [&](const std::vector<uint8_t>& skid) { return !skid.empty() && cert.subject_key_id() == skid; }},
      m_id);
}

std::vector<uint8_t> make_content_info(const OID& content_type, std::span<const uint8_t> content) {
   std::vector<uint8_t> out;
   DER_Encoder(out)
      .start_sequence()
      .encode(content_type)
      .start_explicit_context_specific(0)
      .raw_bytes(content)
      .end_cons()
      .end_cons();
   return out;
}

std::vector<uint8_t> attrs_as_set_encoding(const BER_Object& obj) {
   std::vector<uint8_t> out;
   DER_Encoder(out).add_object(ASN1_Type::Set, ASN1_Class::Universal | ASN1_Class::Constructed, obj.data());

   std::vector<Attribute> attrs;
   BER_Decoder(out, BER_Decoder::Limits::DER()).decode_list(attrs, ASN1_Type::Set, ASN1_Class::Universal).verify_end();
   if(attrs.empty()) {
      throw Decoding_Error("CMS attributes set is empty");
   }
   return out;
}

std::pair<OID, BER_Object> open_content_info(std::span<const uint8_t> content_info) {
   // BER (including the indefinite-length streaming form produced eg by
   // openssl cms) is accepted for received messages
   BER_Decoder dec(content_info, BER_Decoder::Limits::BER());

   BER_Decoder ci = dec.start_sequence();
   OID content_type;
   ci.decode(content_type);
   BER_Decoder content = ci.start_explicit_context_specific(0);
   BER_Object inner = content.get_next_object();
   if(!inner.is_set()) {
      throw Decoding_Error("CMS ContentInfo content is empty");
   }
   content.end_cons();
   ci.end_cons();
   dec.verify_end("Trailing data after CMS ContentInfo");

   return {content_type, std::move(inner)};
}

}  // namespace Botan::CMS
