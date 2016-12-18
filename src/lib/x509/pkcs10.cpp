/*
* PKCS #10
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkcs10.h>
#include <botan/x509_ext.h>
#include <botan/x509cert.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/parsing.h>
#include <botan/oids.h>
#include <botan/pem.h>

namespace Botan {

/*
* PKCS10_Request Constructor
*/
PKCS10_Request::PKCS10_Request(DataSource& in) :
   X509_Object(in, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST")
   {
   do_decode();
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
/*
* PKCS10_Request Constructor
*/
PKCS10_Request::PKCS10_Request(const std::string& fsname) :
   X509_Object(fsname, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST")
   {
   do_decode();
   }
#endif

/*
* PKCS10_Request Constructor
*/
PKCS10_Request::PKCS10_Request(const std::vector<uint8_t>& in) :
   X509_Object(in, "CERTIFICATE REQUEST/NEW CERTIFICATE REQUEST")
   {
   do_decode();
   }

/*
* Decode the CertificateRequestInfo
*/
void PKCS10_Request::force_decode()
   {
   BER_Decoder cert_req_info(m_tbs_bits);

   size_t version;
   cert_req_info.decode(version);
   if(version != 0)
      throw Decoding_Error("Unknown version code in PKCS #10 request: " +
                           std::to_string(version));

   X509_DN dn_subject;
   cert_req_info.decode(dn_subject);

   m_info.add(dn_subject.contents());

   BER_Object public_key = cert_req_info.get_next_object();
   if(public_key.type_tag != SEQUENCE || public_key.class_tag != CONSTRUCTED)
      throw BER_Bad_Tag("PKCS10_Request: Unexpected tag for public key",
                        public_key.type_tag, public_key.class_tag);

   m_info.add("X509.Certificate.public_key",
            PEM_Code::encode(
               ASN1::put_in_sequence(unlock(public_key.value)),
               "PUBLIC KEY"
               )
      );

   BER_Object attr_bits = cert_req_info.get_next_object();

   if(attr_bits.type_tag == 0 &&
      attr_bits.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      BER_Decoder attributes(attr_bits.value);
      while(attributes.more_items())
         {
         Attribute attr;
         attributes.decode(attr);
         handle_attribute(attr);
         }
      attributes.verify_end();
      }
   else if(attr_bits.type_tag != NO_OBJECT)
      throw BER_Bad_Tag("PKCS10_Request: Unexpected tag for attributes",
                        attr_bits.type_tag, attr_bits.class_tag);

   cert_req_info.verify_end();

   if(!this->check_signature(subject_public_key()))
      throw Decoding_Error("PKCS #10 request: Bad signature detected");
   }

/*
* Handle attributes in a PKCS #10 request
*/
void PKCS10_Request::handle_attribute(const Attribute& attr)
   {
   BER_Decoder value(attr.parameters);

   if(attr.oid == OIDS::lookup("PKCS9.EmailAddress"))
      {
      ASN1_String email;
      value.decode(email);
      m_info.add("RFC822", email.value());
      }
   else if(attr.oid == OIDS::lookup("PKCS9.ChallengePassword"))
      {
      ASN1_String challenge_password;
      value.decode(challenge_password);
      m_info.add("PKCS9.ChallengePassword", challenge_password.value());
      }
   else if(attr.oid == OIDS::lookup("PKCS9.ExtensionRequest"))
      {
      value.decode(m_extensions).verify_end();
      }
   }

/*
* Return the challenge password (if any)
*/
std::string PKCS10_Request::challenge_password() const
   {
   return m_info.get1("PKCS9.ChallengePassword");
   }

/*
* Return the name of the requestor
*/
X509_DN PKCS10_Request::subject_dn() const
   {
   return create_dn(m_info);
   }

/*
* Return the public key of the requestor
*/
std::vector<uint8_t> PKCS10_Request::raw_public_key() const
   {
   DataSource_Memory source(m_info.get1("X509.Certificate.public_key"));
   return unlock(PEM_Code::decode_check_label(source, "PUBLIC KEY"));
   }

/*
* Return the public key of the requestor
*/
Public_Key* PKCS10_Request::subject_public_key() const
   {
   DataSource_Memory source(m_info.get1("X509.Certificate.public_key"));
   return X509::load_key(source);
   }

/*
* Return the alternative names of the requestor
*/
AlternativeName PKCS10_Request::subject_alt_name() const
   {
   return create_alt_name(m_info);
   }

/*
* Return the key constraints (if any)
*/
Key_Constraints PKCS10_Request::constraints() const
   {
   if(auto ext = m_extensions.get(OIDS::lookup("X509v3.KeyUsage")))
      {
      return dynamic_cast<Cert_Extension::Key_Usage&>(*ext).get_constraints();
      }

   return NO_CONSTRAINTS;
   }

/*
* Return the extendend key constraints (if any)
*/
std::vector<OID> PKCS10_Request::ex_constraints() const
   {
   if(auto ext = m_extensions.get(OIDS::lookup("X509v3.ExtendedKeyUsage")))
      {
      return dynamic_cast<Cert_Extension::Extended_Key_Usage&>(*ext).get_oids();
      }

   return {};
   }

/*
* Return is a CA certificate is requested
*/
bool PKCS10_Request::is_CA() const
   {
   if(auto ext = m_extensions.get(OIDS::lookup("X509v3.BasicConstraints")))
      {
      return dynamic_cast<Cert_Extension::Basic_Constraints&>(*ext).get_is_ca();
      }

   return false;
   }

/*
* Return the desired path limit (if any)
*/
size_t PKCS10_Request::path_limit() const
   {
   if(auto ext = m_extensions.get(OIDS::lookup("X509v3.BasicConstraints")))
      {
      Cert_Extension::Basic_Constraints& basic_constraints = dynamic_cast<Cert_Extension::Basic_Constraints&>(*ext);
      if(basic_constraints.get_is_ca())
         {
         return basic_constraints.get_path_limit();
         }
      }

   return 0;
   }

/*
* Return the X509v3 extensions
*/
Extensions PKCS10_Request::extensions() const
   {
   return m_extensions;
   }

}
