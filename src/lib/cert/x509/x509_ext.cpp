/*
* X.509 Certificate Extensions
* (C) 1999-2010,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_ext.h>
#include <botan/sha160.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <botan/charset.h>
#include <botan/internal/bit_ops.h>
#include <algorithm>

namespace Botan {

/*
* List of X.509 Certificate Extensions
*/
Certificate_Extension* Extensions::get_extension(const OID& oid)
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
   X509_EXTENSION("X509v3.CertificatePolicies", Certificate_Policies);
   X509_EXTENSION("X509v3.CRLDistributionPoints", CRL_Distribution_Points);
   X509_EXTENSION("PKIX.AuthorityInformationAccess", Authority_Information_Access);
   X509_EXTENSION("X509v3.CRLNumber", CRL_Number);
   X509_EXTENSION("X509v3.ReasonCode", CRL_ReasonCode);

   return nullptr;
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
   for(size_t i = 0; i != extensions.size(); ++i)
      delete extensions[i].first;
   extensions.clear();

   for(size_t i = 0; i != other.extensions.size(); ++i)
      extensions.push_back(
         std::make_pair(other.extensions[i].first->copy(),
                        other.extensions[i].second));

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

void Extensions::add(Certificate_Extension* extn, bool critical)
   {
   extensions.push_back(std::make_pair(extn, critical));
   }

/*
* Encode an Extensions list
*/
void Extensions::encode_into(DER_Encoder& to_object) const
   {
   for(size_t i = 0; i != extensions.size(); ++i)
      {
      const Certificate_Extension* ext = extensions[i].first;
      const bool is_critical = extensions[i].second;

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
   for(size_t i = 0; i != extensions.size(); ++i)
      delete extensions[i].first;
   extensions.clear();

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

      Certificate_Extension* ext = get_extension(oid);

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

         extensions.push_back(std::make_pair(ext, critical));
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
   for(size_t i = 0; i != extensions.size(); ++i)
      extensions[i].first->contents_to(subject_info, issuer_info);
   }

/*
* Delete an Extensions list
*/
Extensions::~Extensions()
   {
   for(size_t i = 0; i != extensions.size(); ++i)
      delete extensions[i].first;
   }

namespace Cert_Extension {

/*
* Checked accessor for the path_limit member
*/
size_t Basic_Constraints::get_path_limit() const
   {
   if(!is_ca)
      throw Invalid_State("Basic_Constraints::get_path_limit: Not a CA");
   return path_limit;
   }

/*
* Encode the extension
*/
std::vector<byte> Basic_Constraints::encode_inner() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
      .encode_if(is_ca,
                 DER_Encoder()
                    .encode(is_ca)
                    .encode_optional(path_limit, NO_CERT_PATH_LIMIT)
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
         .decode_optional(is_ca, BOOLEAN, UNIVERSAL, false)
         .decode_optional(path_limit, INTEGER, UNIVERSAL, NO_CERT_PATH_LIMIT)
         .verify_end()
      .end_cons();

   if(is_ca == false)
      path_limit = 0;
   }

/*
* Return a textual representation
*/
void Basic_Constraints::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.BasicConstraints.is_ca", (is_ca ? 1 : 0));
   subject.add("X509v3.BasicConstraints.path_constraint", path_limit);
   }

/*
* Encode the extension
*/
std::vector<byte> Key_Usage::encode_inner() const
   {
   if(constraints == NO_CONSTRAINTS)
      throw Encoding_Error("Cannot encode zero usage constraints");

   const size_t unused_bits = low_bit(constraints) - 1;

   std::vector<byte> der;
   der.push_back(BIT_STRING);
   der.push_back(2 + ((unused_bits < 8) ? 1 : 0));
   der.push_back(unused_bits % 8);
   der.push_back((constraints >> 8) & 0xFF);
   if(constraints & 0xFF)
      der.push_back(constraints & 0xFF);

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
      usage = (obj.value[i] << 8) | usage;

   constraints = Key_Constraints(usage);
   }

/*
* Return a textual representation
*/
void Key_Usage::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.KeyUsage", constraints);
   }

/*
* Encode the extension
*/
std::vector<byte> Subject_Key_ID::encode_inner() const
   {
   return DER_Encoder().encode(key_id, OCTET_STRING).get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Subject_Key_ID::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder(in).decode(key_id, OCTET_STRING).verify_end();
   }

/*
* Return a textual representation
*/
void Subject_Key_ID::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.SubjectKeyIdentifier", key_id);
   }

/*
* Subject_Key_ID Constructor
*/
Subject_Key_ID::Subject_Key_ID(const std::vector<byte>& pub_key)
   {
   SHA_160 hash;
   key_id = unlock(hash.process(pub_key));
   }

/*
* Encode the extension
*/
std::vector<byte> Authority_Key_ID::encode_inner() const
   {
   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(key_id, OCTET_STRING, ASN1_Tag(0), CONTEXT_SPECIFIC)
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
      .decode_optional_string(key_id, OCTET_STRING, 0);
   }

/*
* Return a textual representation
*/
void Authority_Key_ID::contents_to(Data_Store&, Data_Store& issuer) const
   {
   if(key_id.size())
      issuer.add("X509v3.AuthorityKeyIdentifier", key_id);
   }

/*
* Encode the extension
*/
std::vector<byte> Alternative_Name::encode_inner() const
   {
   return DER_Encoder().encode(alt_name).get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Alternative_Name::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder(in).decode(alt_name);
   }

/*
* Return a textual representation
*/
void Alternative_Name::contents_to(Data_Store& subject_info,
                                   Data_Store& issuer_info) const
   {
   std::multimap<std::string, std::string> contents =
      get_alt_name().contents();

   if(oid_name_str == "X509v3.SubjectAlternativeName")
      subject_info.add(contents);
   else if(oid_name_str == "X509v3.IssuerAlternativeName")
      issuer_info.add(contents);
   else
      throw Internal_Error("In Alternative_Name, unknown type " +
                           oid_name_str);
   }

/*
* Alternative_Name Constructor
*/
Alternative_Name::Alternative_Name(const AlternativeName& alt_name,
                                   const std::string& oid_name_str)
   {
   this->alt_name = alt_name;
   this->oid_name_str = oid_name_str;
   }

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
         .encode_list(oids)
      .end_cons()
   .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Extended_Key_Usage::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder(in).decode_list(oids);
   }

/*
* Return a textual representation
*/
void Extended_Key_Usage::contents_to(Data_Store& subject, Data_Store&) const
   {
   for(size_t i = 0; i != oids.size(); ++i)
      subject.add("X509v3.ExtendedKeyUsage", oids[i].as_string());
   }

namespace {

/*
* A policy specifier
*/
class Policy_Information : public ASN1_Object
   {
   public:
      OID oid;

      Policy_Information() {}
      Policy_Information(const OID& oid) : oid(oid) {}

      void encode_into(DER_Encoder& codec) const override
         {
         codec.start_cons(SEQUENCE)
            .encode(oid)
            .end_cons();
         }

      void decode_from(BER_Decoder& codec) override
         {
         codec.start_cons(SEQUENCE)
            .decode(oid)
            .discard_remaining()
            .end_cons();
         }
   };

}

/*
* Encode the extension
*/
std::vector<byte> Certificate_Policies::encode_inner() const
   {
   std::vector<Policy_Information> policies;

   for(size_t i = 0; i != oids.size(); ++i)
      policies.push_back(oids[i]);

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

   oids.clear();
   for(size_t i = 0; i != policies.size(); ++i)
      oids.push_back(policies[i].oid);
   }

/*
* Return a textual representation
*/
void Certificate_Policies::contents_to(Data_Store& info, Data_Store&) const
   {
   for(size_t i = 0; i != oids.size(); ++i)
      info.add("X509v3.CertificatePolicies", oids[i].as_string());
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
   if(m_ocsp_responder != "")
      subject.add("OCSP.responder", m_ocsp_responder);
   }

/*
* Checked accessor for the crl_number member
*/
size_t CRL_Number::get_crl_number() const
   {
   if(!has_value)
      throw Invalid_State("CRL_Number::get_crl_number: Not set");
   return crl_number;
   }

/*
* Copy a CRL_Number extension
*/
CRL_Number* CRL_Number::copy() const
   {
   if(!has_value)
      throw Invalid_State("CRL_Number::copy: Not set");
   return new CRL_Number(crl_number);
   }

/*
* Encode the extension
*/
std::vector<byte> CRL_Number::encode_inner() const
   {
   return DER_Encoder().encode(crl_number).get_contents_unlocked();
   }

/*
* Decode the extension
*/
void CRL_Number::decode_inner(const std::vector<byte>& in)
   {
   BER_Decoder(in).decode(crl_number);
   }

/*
* Return a textual representation
*/
void CRL_Number::contents_to(Data_Store& info, Data_Store&) const
   {
   info.add("X509v3.CRLNumber", crl_number);
   }

/*
* Encode the extension
*/
std::vector<byte> CRL_ReasonCode::encode_inner() const
   {
   return DER_Encoder()
      .encode(static_cast<size_t>(reason), ENUMERATED, UNIVERSAL)
   .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void CRL_ReasonCode::decode_inner(const std::vector<byte>& in)
   {
   size_t reason_code = 0;
   BER_Decoder(in).decode(reason_code, ENUMERATED, UNIVERSAL);
   reason = static_cast<CRL_Code>(reason_code);
   }

/*
* Return a textual representation
*/
void CRL_ReasonCode::contents_to(Data_Store& info, Data_Store&) const
   {
   info.add("X509v3.CRLReasonCode", reason);
   }

std::vector<byte> CRL_Distribution_Points::encode_inner() const
   {
   throw Exception("CRL_Distribution_Points encoding not implemented");
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
   throw Exception("CRL_Distribution_Points encoding not implemented");
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

}

}
