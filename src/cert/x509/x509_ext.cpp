/*
* X.509 Certificate Extensions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509_ext.h>
#include <botan/sha160.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <botan/libstate.h>
#include <botan/bit_ops.h>
#include <algorithm>
#include <memory>

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
   X509_EXTENSION("X509v3.CRLNumber", CRL_Number);
   X509_EXTENSION("X509v3.CertificatePolicies", Certificate_Policies);

   return 0;
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
   for(u32bit j = 0; j != extensions.size(); ++j)
      delete extensions[j];
   extensions.clear();

   for(u32bit j = 0; j != other.extensions.size(); ++j)
      extensions.push_back(other.extensions[j]->copy());

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
* Encode an Extensions list
*/
void Extensions::encode_into(DER_Encoder& to_object) const
   {
   for(u32bit j = 0; j != extensions.size(); ++j)
      {
      const Certificate_Extension* ext = extensions[j];

      std::string setting;

      if(ext->config_id() != "")
         setting = global_state().option("x509/exts/" + ext->config_id());

      if(setting == "")
         setting = "yes";

      if(setting != "yes" && setting != "no" && setting != "critical")
         throw Invalid_Argument("X509_CA:: Invalid value for option "
                                "x509/exts/" + ext->config_id() + " of " +
                                setting);

      bool is_critical = (setting == "critical");
      bool should_encode = ext->should_encode() && (setting != "no");

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
   for(u32bit j = 0; j != extensions.size(); ++j)
      delete extensions[j];
   extensions.clear();

   BER_Decoder sequence = from_source.start_cons(SEQUENCE);
   while(sequence.more_items())
      {
      OID oid;
      MemoryVector<byte> value;
      bool critical;

      sequence.start_cons(SEQUENCE)
            .decode(oid)
            .decode_optional(critical, BOOLEAN, UNIVERSAL, false)
            .decode(value, OCTET_STRING)
            .verify_end()
         .end_cons();

      Certificate_Extension* ext = get_extension(oid);

      if(!ext)
         {
         if(!critical || !should_throw)
            continue;

         throw Decoding_Error("Encountered unknown X.509 extension marked "
                              "as critical; OID = " + oid.as_string());
         }

      ext->decode_inner(value);

      extensions.push_back(ext);
      }
   sequence.verify_end();
   }

/*
* Write the extensions to an info store
*/
void Extensions::contents_to(Data_Store& subject_info,
                             Data_Store& issuer_info) const
   {
   for(u32bit j = 0; j != extensions.size(); ++j)
      extensions[j]->contents_to(subject_info, issuer_info);
   }

/*
* Delete an Extensions list
*/
Extensions::~Extensions()
   {
   for(u32bit j = 0; j != extensions.size(); ++j)
      delete extensions[j];
   }

namespace Cert_Extension {

/*
* Checked accessor for the path_limit member
*/
u32bit Basic_Constraints::get_path_limit() const
   {
   if(!is_ca)
      throw Invalid_State("Basic_Constraints::get_path_limit: Not a CA");
   return path_limit;
   }

/*
* Encode the extension
*/
MemoryVector<byte> Basic_Constraints::encode_inner() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
      .encode_if(is_ca,
                 DER_Encoder()
                    .encode(is_ca)
                    .encode_optional(path_limit, NO_CERT_PATH_LIMIT)
         )
      .end_cons()
   .get_contents();
   }

/*
* Decode the extension
*/
void Basic_Constraints::decode_inner(const MemoryRegion<byte>& in)
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
MemoryVector<byte> Key_Usage::encode_inner() const
   {
   if(constraints == NO_CONSTRAINTS)
      throw Encoding_Error("Cannot encode zero usage constraints");

   const u32bit unused_bits = low_bit(constraints) - 1;

   SecureVector<byte> der;
   der.append(BIT_STRING);
   der.append(2 + ((unused_bits < 8) ? 1 : 0));
   der.append(unused_bits % 8);
   der.append((constraints >> 8) & 0xFF);
   if(constraints & 0xFF)
      der.append(constraints & 0xFF);

   return der;
   }

/*
* Decode the extension
*/
void Key_Usage::decode_inner(const MemoryRegion<byte>& in)
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
   for(u32bit j = 1; j != obj.value.size(); ++j)
      usage = (obj.value[j] << 8) | usage;

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
MemoryVector<byte> Subject_Key_ID::encode_inner() const
   {
   return DER_Encoder().encode(key_id, OCTET_STRING).get_contents();
   }

/*
* Decode the extension
*/
void Subject_Key_ID::decode_inner(const MemoryRegion<byte>& in)
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
Subject_Key_ID::Subject_Key_ID(const MemoryRegion<byte>& pub_key)
   {
   SHA_160 hash;
   key_id = hash.process(pub_key);
   }

/*
* Encode the extension
*/
MemoryVector<byte> Authority_Key_ID::encode_inner() const
   {
   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(key_id, OCTET_STRING, ASN1_Tag(0), CONTEXT_SPECIFIC)
         .end_cons()
      .get_contents();
   }

/*
* Decode the extension
*/
void Authority_Key_ID::decode_inner(const MemoryRegion<byte>& in)
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
MemoryVector<byte> Alternative_Name::encode_inner() const
   {
   return DER_Encoder().encode(alt_name).get_contents();
   }

/*
* Decode the extension
*/
void Alternative_Name::decode_inner(const MemoryRegion<byte>& in)
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
                                   const std::string& oid_name_str,
                                   const std::string& config_name_str)
   {
   this->alt_name = alt_name;
   this->oid_name_str = oid_name_str;
   this->config_name_str = config_name_str;
   }

/*
* Subject_Alternative_Name Constructor
*/
Subject_Alternative_Name::Subject_Alternative_Name(
   const AlternativeName& name) :

   Alternative_Name(name, "X509v3.SubjectAlternativeName",
                    "subject_alternative_name")
   {
   }

/*
* Issuer_Alternative_Name Constructor
*/
Issuer_Alternative_Name::Issuer_Alternative_Name(const AlternativeName& name) :
   Alternative_Name(name, "X509v3.IssuerAlternativeName",
                    "issuer_alternative_name")
   {
   }

/*
* Encode the extension
*/
MemoryVector<byte> Extended_Key_Usage::encode_inner() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode_list(oids)
      .end_cons()
   .get_contents();
   }

/*
* Decode the extension
*/
void Extended_Key_Usage::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder(in)
      .start_cons(SEQUENCE)
         .decode_list(oids)
      .end_cons();
   }

/*
* Return a textual representation
*/
void Extended_Key_Usage::contents_to(Data_Store& subject, Data_Store&) const
   {
   for(u32bit j = 0; j != oids.size(); ++j)
      subject.add("X509v3.ExtendedKeyUsage", oids[j].as_string());
   }

namespace {

/*
* A policy specifier
*/
class Policy_Information : public ASN1_Object
   {
   public:
      OID oid;

      void encode_into(DER_Encoder& codec) const
         {
         codec.start_cons(SEQUENCE)
            .encode(oid)
            .end_cons();
         }

      void decode_from(BER_Decoder& codec)
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
MemoryVector<byte> Certificate_Policies::encode_inner() const
   {
   throw Exception("Certificate_Policies::encode_inner: Bugged");

   std::vector<Policy_Information> policies;

   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode_list(policies)
      .end_cons()
   .get_contents();
   }

/*
* Decode the extension
*/
void Certificate_Policies::decode_inner(const MemoryRegion<byte>& in)
   {
   std::vector<Policy_Information> policies;

   BER_Decoder(in)
      .start_cons(SEQUENCE)
         .decode_list(policies)
      .end_cons();
   }

/*
* Return a textual representation
*/
void Certificate_Policies::contents_to(Data_Store& info, Data_Store&) const
   {
   for(u32bit j = 0; j != oids.size(); ++j)
      info.add("X509v3.ExtendedKeyUsage", oids[j].as_string());
   }

/*
* Checked accessor for the crl_number member
*/
u32bit CRL_Number::get_crl_number() const
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
MemoryVector<byte> CRL_Number::encode_inner() const
   {
   return DER_Encoder().encode(crl_number).get_contents();
   }

/*
* Decode the extension
*/
void CRL_Number::decode_inner(const MemoryRegion<byte>& in)
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
MemoryVector<byte> CRL_ReasonCode::encode_inner() const
   {
   return DER_Encoder()
      .encode(static_cast<u32bit>(reason), ENUMERATED, UNIVERSAL)
   .get_contents();
   }

/*
* Decode the extension
*/
void CRL_ReasonCode::decode_inner(const MemoryRegion<byte>& in)
   {
   u32bit reason_code = 0;
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

}

}
