/*
* X.509 Certificate Extensions
* (C) 1999-2010,2012 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_ext.h>
#include <botan/x509cert.h>
#include <botan/sha160.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <botan/charset.h>
#include <botan/internal/bit_ops.h>
#include <algorithm>
#include <sstream>

namespace Botan {

/*
* List of X.509 Certificate Extensions
*/
Certificate_Extension* Extensions::get_extension(const OID& oid, bool critical)
   {
#define X509_EXTENSION(NAME, TYPE) \
   if(OIDS::name_of(oid, NAME))    \
      return new Cert_Extension::TYPE();

   X509_EXTENSION("X509v3.KeyUsage", Key_Usage);
   X509_EXTENSION("X509v3.BasicConstraints", Basic_Constraints);
   X509_EXTENSION("X509v3.SubjectKeyIdentifier", Subject_Key_ID);
   X509_EXTENSION("X509v3.AuthorityKeyIdentifier", Authority_Key_ID);
   X509_EXTENSION("X509v3.ExtendedKeyUsage", Extended_Key_Usage);
   X509_EXTENSION("X509v3.IssuerAlternativeName", Issuer_Alternative_Name);
   X509_EXTENSION("X509v3.SubjectAlternativeName", Subject_Alternative_Name);
   X509_EXTENSION("X509v3.NameConstraints", Name_Constraints);
   X509_EXTENSION("X509v3.CertificatePolicies", Certificate_Policies);
   X509_EXTENSION("X509v3.CRLDistributionPoints", CRL_Distribution_Points);
   X509_EXTENSION("PKIX.AuthorityInformationAccess", Authority_Information_Access);
   X509_EXTENSION("X509v3.CRLNumber", CRL_Number);
   X509_EXTENSION("X509v3.ReasonCode", CRL_ReasonCode);

   return critical ? new Cert_Extension::Unknown_Critical_Extension(oid) : nullptr;
   }

/*
* Extensions Copy Constructor
*/
Extensions::Extensions(const Extensions& extensions) : ASN1_Object()
   {
   *this = extensions;
   }

/*
* Extensions Assignment Operator
*/
Extensions& Extensions::operator=(const Extensions& other)
   {
   m_extensions.clear();

   for(size_t i = 0; i != other.m_extensions.size(); ++i)
      m_extensions.push_back(
         std::make_pair(std::unique_ptr<Certificate_Extension>(other.m_extensions[i].first->copy()),
                        other.m_extensions[i].second));

   m_extensions_raw = other.m_extensions_raw;
   m_throw_on_unknown_critical = other.m_throw_on_unknown_critical;

   return (*this);
   }

/*
* Return the OID of this extension
*/
OID Certificate_Extension::oid_of() const
   {
   return OIDS::lookup(oid_name());
   }

/*
* Validate the extension (the default implementation is a NOP)
*/
void Certificate_Extension::validate(const X509_Certificate&, const X509_Certificate&,
      const std::vector<std::shared_ptr<const X509_Certificate>>&,
      std::vector<std::set<Certificate_Status_Code>>&,
      size_t)
   {
   }

void Extensions::add(Certificate_Extension* extn, bool critical)
   {
   m_extensions.push_back(std::make_pair(std::unique_ptr<Certificate_Extension>(extn), critical));
   m_extensions_raw.emplace(extn->oid_of(), std::make_pair(extn->encode_inner(), critical));
   }

std::vector<std::pair<std::unique_ptr<Certificate_Extension>, bool>> Extensions::extensions() const
   {
   std::vector<std::pair<std::unique_ptr<Certificate_Extension>, bool>> exts;
   for(auto& ext : m_extensions)
      {
      exts.push_back(std::make_pair(std::unique_ptr<Certificate_Extension>(ext.first->copy()), ext.second));
      }
   return exts;
   }

std::map<OID, std::pair<std::vector<byte>, bool>> Extensions::extensions_raw() const
   {
   return m_extensions_raw;
   }

/*
* Encode an Extensions list
*/
void Extensions::encode_into(DER_Encoder& to_object) const
   {
   for(size_t i = 0; i != m_extensions.size(); ++i)
      {
      const Certificate_Extension* ext = m_extensions[i].first.get();
      const bool is_critical = m_extensions[i].second;

      const bool should_encode = ext->should_encode();

      if(should_encode)
         {
         to_object.start_cons(SEQUENCE)
               .encode(ext->oid_of())
               .encode_optional(is_critical, false)
               .encode(ext->encode_inner(), OCTET_STRING)
            .end_cons();
         }
      }
   }

/*
* Decode a list of Extensions
*/
void Extensions::decode_from(BER_Decoder& from_source)
   {
   m_extensions.clear();
   m_extensions_raw.clear();

   BER_Decoder sequence = from_source.start_cons(SEQUENCE);

   while(sequence.more_items())
      {
      OID oid;
      std::vector<byte> value;
      bool critical;

      sequence.start_cons(SEQUENCE)
            .decode(oid)
            .decode_optional(critical, BOOLEAN, UNIVERSAL, false)
            .decode(value, OCTET_STRING)
            .verify_end()
         .end_cons();

      m_extensions_raw.emplace(oid, std::make_pair(value, critical));

      std::unique_ptr<Certificate_Extension> ext(get_extension(oid, critical));

      if(!ext && critical && m_throw_on_unknown_critical)
         throw Decoding_Error("Encountered unknown X.509 extension marked "
                              "as critical; OID = " + oid.as_string());

      if(ext)
         {
         try
            {
            ext->decode_inner(value);
            }
         catch(std::exception& e)
            {
            throw Decoding_Error("Exception while decoding extension " +
                                 oid.as_string() + ": " + e.what());
            }

         m_extensions.push_back(std::make_pair(std::move(ext), critical));
         }
      }

   sequence.verify_end();
   }

/*
* Write the extensions to an info store
*/
void Extensions::contents_to(Data_Store& subject_info,
                             Data_Store& issuer_info) const
   {
   for(size_t i = 0; i != m_extensions.size(); ++i)
      {
      m_extensions[i].first->contents_to(subject_info, issuer_info);
      subject_info.add(m_extensions[i].first->oid_name() + ".is_critical", (m_extensions[i].second ? 1 : 0));
      }
   }


namespace Cert_Extension {

/*
* Checked accessor for the path_limit member
*/
size_t Basic_Constraints::get_path_limit() const
   {
   if(!m_is_ca)
      throw Invalid_State("Basic_Constraints::get_path_limit: Not a CA");
   return m_path_limit;
   }

/*
* Encode the extension
*/
std::vector<byte> Basic_Constraints::encode_inner() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
      .encode_if(m_is_ca,
                 DER_Encoder()
                    .encode(m_is_ca)
                    .encode_optional(m_path_limit, NO_CERT_PATH_LIMIT)
         )
      .end_cons()
   .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Basic_Constraints::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder(in)
      .start_cons(SEQUENCE)
         .decode_optional(m_is_ca, BOOLEAN, UNIVERSAL, false)
         .decode_optional(m_path_limit, INTEGER, UNIVERSAL, NO_CERT_PATH_LIMIT)
         .verify_end()
      .end_cons();

   if(m_is_ca == false)
      m_path_limit = 0;
   }

/*
* Return a textual representation
*/
void Basic_Constraints::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.BasicConstraints.is_ca", (m_is_ca ? 1 : 0));
   subject.add("X509v3.BasicConstraints.path_constraint", static_cast<u32bit>(m_path_limit));
   }

/*
* Encode the extension
*/
std::vector<byte> Key_Usage::encode_inner() const
   {
   if(m_constraints == NO_CONSTRAINTS)
      throw Encoding_Error("Cannot encode zero usage constraints");

   const size_t unused_bits = low_bit(m_constraints) - 1;

   std::vector<byte> der;
   der.push_back(BIT_STRING);
   der.push_back(2 + ((unused_bits < 8) ? 1 : 0));
   der.push_back(unused_bits % 8);
   der.push_back((m_constraints >> 8) & 0xFF);
   if(m_constraints & 0xFF)
      der.push_back(m_constraints & 0xFF);

   return der;
   }

/*
* Decode the extension
*/
void Key_Usage::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder ber(in);

   BER_Object obj = ber.get_next_object();

   if(obj.type_tag != BIT_STRING || obj.class_tag != UNIVERSAL)
      throw BER_Bad_Tag("Bad tag for usage constraint",
                        obj.type_tag, obj.class_tag);

   if(obj.value.size() != 2 && obj.value.size() != 3)
      throw BER_Decoding_Error("Bad size for BITSTRING in usage constraint");

   if(obj.value[0] >= 8)
      throw BER_Decoding_Error("Invalid unused bits in usage constraint");

   obj.value[obj.value.size()-1] &= (0xFF << obj.value[0]);

   u16bit usage = 0;
   for(size_t i = 1; i != obj.value.size(); ++i)
      {
      usage = (obj.value[i] << 8*(sizeof(usage)-i)) | usage;
      }

   m_constraints = Key_Constraints(usage);
   }

/*
* Return a textual representation
*/
void Key_Usage::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.KeyUsage", m_constraints);
   }

/*
* Encode the extension
*/
std::vector<byte> Subject_Key_ID::encode_inner() const
   {
   return DER_Encoder().encode(m_key_id, OCTET_STRING).get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Subject_Key_ID::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder(in).decode(m_key_id, OCTET_STRING).verify_end();
   }

/*
* Return a textual representation
*/
void Subject_Key_ID::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.SubjectKeyIdentifier", m_key_id);
   }

/*
* Subject_Key_ID Constructor
*/
Subject_Key_ID::Subject_Key_ID(const std::vector<byte>& pub_key) : m_key_id(unlock(SHA_160().process(pub_key)))
   {}

/*
* Encode the extension
*/
std::vector<byte> Authority_Key_ID::encode_inner() const
   {
   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(m_key_id, OCTET_STRING, ASN1_Tag(0), CONTEXT_SPECIFIC)
         .end_cons()
      .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Authority_Key_ID::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder(in)
      .start_cons(SEQUENCE)
      .decode_optional_string(m_key_id, OCTET_STRING, 0);
   }

/*
* Return a textual representation
*/
void Authority_Key_ID::contents_to(Data_Store&, Data_Store& issuer) const
   {
   if(m_key_id.size())
      issuer.add("X509v3.AuthorityKeyIdentifier", m_key_id);
   }

/*
* Encode the extension
*/
std::vector<byte> Alternative_Name::encode_inner() const
   {
   return DER_Encoder().encode(m_alt_name).get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Alternative_Name::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder(in).decode(m_alt_name);
   }

/*
* Return a textual representation
*/
void Alternative_Name::contents_to(Data_Store& subject_info,
                                   Data_Store& issuer_info) const
   {
   std::multimap<std::string, std::string> contents =
      get_alt_name().contents();

   if(m_oid_name_str == "X509v3.SubjectAlternativeName")
      subject_info.add(contents);
   else if(m_oid_name_str == "X509v3.IssuerAlternativeName")
      issuer_info.add(contents);
   else
      throw Internal_Error("In Alternative_Name, unknown type " +
                           m_oid_name_str);
   }

/*
* Alternative_Name Constructor
*/
Alternative_Name::Alternative_Name(const AlternativeName& alt_name,
                                   const std::string& oid_name_str) :
   m_oid_name_str(oid_name_str),
   m_alt_name(alt_name)
   {}

/*
* Subject_Alternative_Name Constructor
*/
Subject_Alternative_Name::Subject_Alternative_Name(
  const AlternativeName& name) :
   Alternative_Name(name, "X509v3.SubjectAlternativeName")
   {
   }

/*
* Issuer_Alternative_Name Constructor
*/
Issuer_Alternative_Name::Issuer_Alternative_Name(const AlternativeName& name) :
   Alternative_Name(name, "X509v3.IssuerAlternativeName")
   {
   }

/*
* Encode the extension
*/
std::vector<byte> Extended_Key_Usage::encode_inner() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode_list(m_oids)
      .end_cons()
   .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Extended_Key_Usage::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder(in).decode_list(m_oids);
   }

/*
* Return a textual representation
*/
void Extended_Key_Usage::contents_to(Data_Store& subject, Data_Store&) const
   {
   for(size_t i = 0; i != m_oids.size(); ++i)
      subject.add("X509v3.ExtendedKeyUsage", m_oids[i].as_string());
   }

/*
* Encode the extension
*/
std::vector<byte> Name_Constraints::encode_inner() const
   {
   throw Not_Implemented("Name_Constraints encoding");
   }


/*
* Decode the extension
*/
void Name_Constraints::decode_inner(const std::vector<byte>& in)
   {
   std::vector<GeneralSubtree> permit, exclude;
   BER_Decoder ber(in);
   BER_Decoder ext = ber.start_cons(SEQUENCE);
   BER_Object per = ext.get_next_object();

   ext.push_back(per);
   if(per.type_tag == 0 && per.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      ext.decode_list(permit,ASN1_Tag(0),ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));
      if(permit.empty())
         throw Encoding_Error("Empty Name Contraint list");
      }

   BER_Object exc = ext.get_next_object();
   ext.push_back(exc);
   if(per.type_tag == 1 && per.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      ext.decode_list(exclude,ASN1_Tag(1),ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));
      if(exclude.empty())
         throw Encoding_Error("Empty Name Contraint list");
      }

   ext.end_cons();

   if(permit.empty() && exclude.empty())
      throw Encoding_Error("Empty Name Contraint extension");

   m_name_constraints = NameConstraints(std::move(permit),std::move(exclude));
   }

/*
* Return a textual representation
*/
void Name_Constraints::contents_to(Data_Store& subject, Data_Store&) const
   {
   std::stringstream ss;

   for(const GeneralSubtree& gs: m_name_constraints.permitted())
      {
      ss << gs;
      subject.add("X509v3.NameConstraints.permitted", ss.str());
      ss.str(std::string());
      }
   for(const GeneralSubtree& gs: m_name_constraints.excluded())
      {
      ss << gs;
      subject.add("X509v3.NameConstraints.excluded", ss.str());
      ss.str(std::string());
      }
   }

void Name_Constraints::validate(const X509_Certificate& subject, const X509_Certificate& issuer,
      const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
      std::vector<std::set<Certificate_Status_Code>>& cert_status,
      size_t pos)
   {
   if(!m_name_constraints.permitted().empty() || !m_name_constraints.excluded().empty())
      {
      if(!subject.is_CA_cert() || !subject.is_critical("X509v3.NameConstraints"))
         cert_status.at(pos).insert(Certificate_Status_Code::NAME_CONSTRAINT_ERROR);

      const bool at_self_signed_root = (pos == cert_path.size() - 1);

      // Check that all subordinate certs pass the name constraint
      for(size_t j = 0; j <= pos; ++j)
         {
         if(pos == j && at_self_signed_root)
            continue;

         bool permitted = m_name_constraints.permitted().empty();
         bool failed = false;

         for(auto c: m_name_constraints.permitted())
            {
            switch(c.base().matches(*cert_path.at(j)))
               {
            case GeneralName::MatchResult::NotFound:
            case GeneralName::MatchResult::All:
               permitted = true;
               break;
            case GeneralName::MatchResult::UnknownType:
               failed = issuer.is_critical("X509v3.NameConstraints");
               permitted = true;
               break;
            default:
               break;
               }
            }

         for(auto c: m_name_constraints.excluded())
            {
            switch(c.base().matches(*cert_path.at(j)))
               {
            case GeneralName::MatchResult::All:
            case GeneralName::MatchResult::Some:
               failed = true;
               break;
            case GeneralName::MatchResult::UnknownType:
               failed = issuer.is_critical("X509v3.NameConstraints");
               break;
            default:
               break;
               }
            }

         if(failed || !permitted)
            {
            cert_status.at(j).insert(Certificate_Status_Code::NAME_CONSTRAINT_ERROR);
            }
         }
      }
   }

namespace {

/*
* A policy specifier
*/
class Policy_Information : public ASN1_Object
   {
   public:
      Policy_Information() {}
      explicit Policy_Information(const OID& oid) : m_oid(oid) {}

      const OID& oid() const { return m_oid; }

      void encode_into(DER_Encoder& codec) const override
         {
         codec.start_cons(SEQUENCE)
            .encode(m_oid)
            .end_cons();
         }

      void decode_from(BER_Decoder& codec) override
         {
         codec.start_cons(SEQUENCE)
            .decode(m_oid)
            .discard_remaining()
            .end_cons();
         }

   private:
      OID m_oid;
   };

}

/*
* Encode the extension
*/
std::vector<byte> Certificate_Policies::encode_inner() const
   {
   std::vector<Policy_Information> policies;

   for(size_t i = 0; i != m_oids.size(); ++i)
      policies.push_back(Policy_Information(m_oids[i]));

   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode_list(policies)
      .end_cons()
   .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Certificate_Policies::decode_inner(const std::vector<byte>& in)
   {
   std::vector<Policy_Information> policies;

   BER_Decoder(in).decode_list(policies);

   m_oids.clear();
   for(size_t i = 0; i != policies.size(); ++i)
      m_oids.push_back(policies[i].oid());
   }

/*
* Return a textual representation
*/
void Certificate_Policies::contents_to(Data_Store& info, Data_Store&) const
   {
   for(size_t i = 0; i != m_oids.size(); ++i)
      info.add("X509v3.CertificatePolicies", m_oids[i].as_string());
   }

std::vector<byte> Authority_Information_Access::encode_inner() const
   {
   ASN1_String url(m_ocsp_responder, IA5_STRING);

   return DER_Encoder()
      .start_cons(SEQUENCE)
      .start_cons(SEQUENCE)
      .encode(OIDS::lookup("PKIX.OCSP"))
      .add_object(ASN1_Tag(6), CONTEXT_SPECIFIC, url.iso_8859())
      .end_cons()
      .end_cons().get_contents_unlocked();
   }

void Authority_Information_Access::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder ber = BER_Decoder(in).start_cons(SEQUENCE);

   while(ber.more_items())
      {
      OID oid;

      BER_Decoder info = ber.start_cons(SEQUENCE);

      info.decode(oid);

      if(oid == OIDS::lookup("PKIX.OCSP"))
         {
         BER_Object name = info.get_next_object();

         if(name.type_tag == 6 && name.class_tag == CONTEXT_SPECIFIC)
            {
            m_ocsp_responder = Charset::transcode(ASN1::to_string(name),
                                                  LATIN1_CHARSET,
                                                  LOCAL_CHARSET);
            }

         }
      }
   }

void Authority_Information_Access::contents_to(Data_Store& subject, Data_Store&) const
   {
   if(!m_ocsp_responder.empty())
      subject.add("OCSP.responder", m_ocsp_responder);
   }

/*
* Checked accessor for the crl_number member
*/
size_t CRL_Number::get_crl_number() const
   {
   if(!m_has_value)
      throw Invalid_State("CRL_Number::get_crl_number: Not set");
   return m_crl_number;
   }

/*
* Copy a CRL_Number extension
*/
CRL_Number* CRL_Number::copy() const
   {
   if(!m_has_value)
      throw Invalid_State("CRL_Number::copy: Not set");
   return new CRL_Number(m_crl_number);
   }

/*
* Encode the extension
*/
std::vector<byte> CRL_Number::encode_inner() const
   {
   return DER_Encoder().encode(m_crl_number).get_contents_unlocked();
   }

/*
* Decode the extension
*/
void CRL_Number::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder(in).decode(m_crl_number);
   }

/*
* Return a textual representation
*/
void CRL_Number::contents_to(Data_Store& info, Data_Store&) const
   {
   info.add("X509v3.CRLNumber", static_cast<u32bit>(m_crl_number));
   }

/*
* Encode the extension
*/
std::vector<byte> CRL_ReasonCode::encode_inner() const
   {
   return DER_Encoder()
      .encode(static_cast<size_t>(m_reason), ENUMERATED, UNIVERSAL)
   .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void CRL_ReasonCode::decode_inner(const std::vector<byte>& in)
   {
   size_t reason_code = 0;
   BER_Decoder(in).decode(reason_code, ENUMERATED, UNIVERSAL);
   m_reason = static_cast<CRL_Code>(reason_code);
   }

/*
* Return a textual representation
*/
void CRL_ReasonCode::contents_to(Data_Store& info, Data_Store&) const
   {
   info.add("X509v3.CRLReasonCode", m_reason);
   }

std::vector<byte> CRL_Distribution_Points::encode_inner() const
   {
   throw Not_Implemented("CRL_Distribution_Points encoding");
   }

void CRL_Distribution_Points::decode_inner(const std::vector<byte>& buf)
   {
   BER_Decoder(buf).decode_list(m_distribution_points).verify_end();
   }

void CRL_Distribution_Points::contents_to(Data_Store& info, Data_Store&) const
   {
   for(size_t i = 0; i != m_distribution_points.size(); ++i)
      {
      auto point = m_distribution_points[i].point().contents();

      auto uris = point.equal_range("URI");

      for(auto uri = uris.first; uri != uris.second; ++uri)
         info.add("CRL.DistributionPoint", uri->second);
      }
   }

void CRL_Distribution_Points::Distribution_Point::encode_into(class DER_Encoder&) const
   {
   throw Not_Implemented("CRL_Distribution_Points encoding");
   }

void CRL_Distribution_Points::Distribution_Point::decode_from(class BER_Decoder& ber)
   {
   ber.start_cons(SEQUENCE)
      .start_cons(ASN1_Tag(0), CONTEXT_SPECIFIC)
        .decode_optional_implicit(m_point, ASN1_Tag(0),
                                  ASN1_Tag(CONTEXT_SPECIFIC | CONSTRUCTED),
                                  SEQUENCE, CONSTRUCTED)
      .end_cons().end_cons();
   }

std::vector<byte> Unknown_Critical_Extension::encode_inner() const
   {
   throw Not_Implemented("Unknown_Critical_Extension encoding");
   }

void Unknown_Critical_Extension::decode_inner(const std::vector<byte>&)
   {
   }

void Unknown_Critical_Extension::contents_to(Data_Store&, Data_Store&) const
   {
   }

}

}
