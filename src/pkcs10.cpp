/*************************************************
* PKCS #10 Source File                           *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/pkcs10.h>
#include <botan/asn1_int.h>
#include <botan/parsing.h>
#include <botan/x509stor.h>
#include <botan/oids.h>

namespace Botan {

/*************************************************
* PKCS10_Request Constructor                     *
*************************************************/
PKCS10_Request::PKCS10_Request(DataSource& in) :
   X509_Object(in, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST")
   {
   is_ca = false;
   max_path_len = 0;
   constraints_value = NO_CONSTRAINTS;

   do_decode();
   }

/*************************************************
* PKCS10_Request Constructor                     *
*************************************************/
PKCS10_Request::PKCS10_Request(const std::string& in) :
   X509_Object(in, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST")
   {
   is_ca = false;
   max_path_len = 0;

   do_decode();
   }

/*************************************************
* Deocde the CertificateRequestInfo              *
*************************************************/
void PKCS10_Request::force_decode()
   {
   BER_Decoder cert_req_info(tbs_bits);

   u32bit version;
   cert_req_info.decode(version);
   if(version != 0)
      throw Decoding_Error("Unknown version code in PKCS #10 request: " +
                           to_string(version));

   BER::decode(cert_req_info, dn);

   BER_Object public_key = cert_req_info.get_next_object();
   if(public_key.type_tag != SEQUENCE || public_key.class_tag != CONSTRUCTED)
      throw BER_Bad_Tag("PKCS10_Request: Unexpected tag for public key",
                        public_key.type_tag, public_key.class_tag);
   pub_key = ASN1::put_in_sequence(public_key.value);

   BER_Object attr_bits = cert_req_info.get_next_object();

   if(attr_bits.type_tag == 0 &&
      attr_bits.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      BER_Decoder attributes(attr_bits.value);
      while(attributes.more_items())
         {
         Attribute attr;
         BER::decode(attributes, attr);
         handle_attribute(attr);
         }
      attributes.verify_end();
      }
   else if(attr_bits.type_tag != NO_OBJECT)
      throw BER_Bad_Tag("PKCS10_Request: Unexpected tag for attributes",
                        attr_bits.type_tag, attr_bits.class_tag);

   cert_req_info.verify_end();

   std::vector<std::string> emails = dn.get_attribute("PKCS9.EmailAddress");
   for(u32bit j = 0; j != emails.size(); ++j)
      subject_alt.add_attribute("RFC822", emails[j]);

   X509_Code sig_check = X509_Store::check_sig(*this, subject_public_key());
   if(sig_check != VERIFIED)
      throw Decoding_Error("PKCS #10 request: Bad signature detected");
   }

/*************************************************
* Handle attributes in a PKCS #10 request        *
*************************************************/
void PKCS10_Request::handle_attribute(const Attribute& attr)
   {
   BER_Decoder value(attr.parameters);

   if(attr.oid == OIDS::lookup("PKCS9.EmailAddress"))
      {
      ASN1_String email;
      BER::decode(value, email);
      subject_alt.add_attribute("RFC822", email.value());
      }
   else if(attr.oid == OIDS::lookup("PKCS9.ChallengePassword"))
      {
      ASN1_String challenge_password;
      BER::decode(value, challenge_password);
      challenge = challenge_password.value();
      }
   else if(attr.oid == OIDS::lookup("PKCS9.ExtensionRequest"))
      {
      BER_Decoder sequence = BER::get_subsequence(value);

      while(sequence.more_items())
         {
         Extension extn;
         BER::decode(sequence, extn);
         handle_v3_extension(extn);
         }
      sequence.verify_end();
      }
   }

/*************************************************
* Decode a requested X.509v3 extension           *
*************************************************/
void PKCS10_Request::handle_v3_extension(const Extension& extn)
   {
   BER_Decoder value(extn.value);

   if(extn.oid == OIDS::lookup("X509v3.KeyUsage"))
      BER::decode(value, constraints_value);
   else if(extn.oid == OIDS::lookup("X509v3.ExtendedKeyUsage"))
      {
      BER_Decoder key_usage = BER::get_subsequence(value);
      while(key_usage.more_items())
         {
         OID usage_oid;
         BER::decode(key_usage, usage_oid);
         ex_constraints_list.push_back(usage_oid);
         }
      }
   else if(extn.oid == OIDS::lookup("X509v3.BasicConstraints"))
      {
      BER_Decoder constraints = BER::get_subsequence(value);
      BER::decode_optional(constraints, is_ca, BOOLEAN, UNIVERSAL, false);
      BER::decode_optional(constraints, max_path_len,
                           INTEGER, UNIVERSAL, NO_CERT_PATH_LIMIT);
      }
   else if(extn.oid == OIDS::lookup("X509v3.SubjectAlternativeName"))
      BER::decode(value, subject_alt);
   else
      return;

   value.verify_end();
   }

/*************************************************
* Return the public key of the requestor         *
*************************************************/
MemoryVector<byte> PKCS10_Request::raw_public_key() const
   {
   return pub_key;
   }

/*************************************************
* Return the public key of the requestor         *
*************************************************/
X509_PublicKey* PKCS10_Request::subject_public_key() const
   {
   return X509::load_key(pub_key);
   }

/*************************************************
* Return the name of the requestor               *
*************************************************/
X509_DN PKCS10_Request::subject_dn() const
   {
   return dn;
   }

/*************************************************
* Return the alternative names of the requestor  *
*************************************************/
AlternativeName PKCS10_Request::subject_alt_name() const
   {
   return subject_alt;
   }

/*************************************************
* Return the challenge password (if any)         *
*************************************************/
std::string PKCS10_Request::challenge_password() const
   {
   return challenge;
   }

/*************************************************
* Return the key constraints (if any)            *
*************************************************/
Key_Constraints PKCS10_Request::constraints() const
   {
   return constraints_value;
   }

/*************************************************
* Return the extendend key constraints (if any)  *
*************************************************/
std::vector<OID> PKCS10_Request::ex_constraints() const
   {
   return ex_constraints_list;
   }

/*************************************************
* Return is a CA certificate is requested        *
*************************************************/
bool PKCS10_Request::is_CA() const
   {
   return is_ca;
   }

/*************************************************
* Return the desired path limit (if any)         *
*************************************************/
u32bit PKCS10_Request::path_limit() const
   {
   return max_path_len;
   }

}
