/*************************************************
* X.509 Certificates Source File                 *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/x509cert.h>
#include <botan/x509_ext.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/stl_util.h>
#include <botan/parsing.h>
#include <botan/bigint.h>
#include <botan/oids.h>
#include <botan/pem.h>
#include <algorithm>

namespace Botan {

namespace {

/*************************************************
* Create and populate a X509_DN                  *
*************************************************/
X509_DN create_dn(const Data_Store& info)
   {
   class DN_Matcher : public Data_Store::Matcher
      {
      public:
         bool operator()(const std::string& key, const std::string&) const
            {
            if(key.find("X520.") != std::string::npos)
               return true;
            return false;
            }
      };

   std::multimap<std::string, std::string> names
      = info.search_with(DN_Matcher());

   typedef std::multimap<std::string, std::string>::const_iterator rdn_iter;

   X509_DN new_dn;
   for(rdn_iter j = names.begin(); j != names.end(); ++j)
      new_dn.add_attribute(j->first, j->second);
   return new_dn;
   }

}

/*************************************************
* X509_Certificate Constructor                   *
*************************************************/
X509_Certificate::X509_Certificate(DataSource& in) :
   X509_Object(in, "CERTIFICATE/X509 CERTIFICATE")
   {
   is_ca = self_signed = false;
   do_decode();
   }

/*************************************************
* X509_Certificate Constructor                   *
*************************************************/
X509_Certificate::X509_Certificate(const std::string& in) :
   X509_Object(in, "CERTIFICATE/X509 CERTIFICATE")
   {
   is_ca = self_signed = false;
   do_decode();
   }

/*************************************************
* Decode the TBSCertificate data                 *
*************************************************/
void X509_Certificate::force_decode()
   {
   u32bit version;
   BigInt serial_bn;
   AlgorithmIdentifier sig_algo_inner;
   X509_DN dn_issuer, dn_subject;
   X509_Time start, end;

   BER_Decoder tbs_cert(tbs_bits);
   tbs_cert.decode_optional(version, ASN1_Tag(0),
                            ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));
   tbs_cert.decode(serial_bn);
   tbs_cert.decode(sig_algo_inner);
   tbs_cert.decode(dn_issuer);
   tbs_cert.start_cons(SEQUENCE)
      .decode(start)
      .decode(end)
      .verify_end()
   .end_cons()
   .decode(dn_subject);

   if(version > 2)
      throw Decoding_Error("Unknown X.509 cert version " + to_string(version));
   if(sig_algo != sig_algo_inner)
      throw Decoding_Error("Algorithm identifier mismatch");

   self_signed = (dn_subject == dn_issuer);

   subject.add(dn_subject.contents());
   issuer.add(dn_issuer.contents());

   BER_Object public_key = tbs_cert.get_next_object();
   if(public_key.type_tag != SEQUENCE || public_key.class_tag != CONSTRUCTED)
      throw BER_Bad_Tag("X509_Certificate: Unexpected tag for public key",
                        public_key.type_tag, public_key.class_tag);

   MemoryVector<byte> v2_issuer_key_id, v2_subject_key_id;

   tbs_cert.decode_optional_string(v2_issuer_key_id, BIT_STRING, 1);
   tbs_cert.decode_optional_string(v2_subject_key_id, BIT_STRING, 2);

   BER_Object v3_exts_data = tbs_cert.get_next_object();
   if(v3_exts_data.type_tag == 3 &&
      v3_exts_data.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      BER_Decoder v3_exts_decoder(v3_exts_data.value);

#if 0
      Extensions extensions;
      v3_exts_decoder.decode(extensions);

      extensions.contents(subject, issuer);
#else
      BER_Decoder sequence = v3_exts_decoder.start_cons(SEQUENCE);

      while(sequence.more_items())
         {
         Extension extn;
         sequence.decode(extn);
         handle_v3_extension(extn);
         }
      sequence.verify_end();
#endif
      v3_exts_decoder.verify_end();
      }
   else if(v3_exts_data.type_tag != NO_OBJECT)
      throw BER_Bad_Tag("Unknown tag in X.509 cert",
                        v3_exts_data.type_tag, v3_exts_data.class_tag);

   if(tbs_cert.more_items())
      throw Decoding_Error("TBSCertificate has more items that expected");

   subject.add("X509.Certificate.version", version);
   subject.add("X509.Certificate.serial", BigInt::encode(serial_bn));
   subject.add("X509.Certificate.start", start.readable_string());
   subject.add("X509.Certificate.end", end.readable_string());

   issuer.add("X509.Certificate.v2.key_id", v2_issuer_key_id);
   subject.add("X509.Certificate.v2.key_id", v2_subject_key_id);

   subject.add("X509.Certificate.public_key",
               PEM_Code::encode(
                  ASN1::put_in_sequence(public_key.value),
                  "PUBLIC KEY"
                  )
      );

   if(!subject.has_value("X509v3.BasicConstraints.path_constraint"))
      {
      u32bit limit = (x509_version() < 3) ? NO_CERT_PATH_LIMIT : 0;
      subject.add("X509v3.BasicConstraints.path_constraint", limit);
      }
   }

/*************************************************
* Decode a particular v3 extension               *
*************************************************/
void X509_Certificate::handle_v3_extension(const Extension& extn)
   {
   BER_Decoder value(extn.value);

   if(extn.oid == OIDS::lookup("X509v3.KeyUsage"))
      {
      Key_Constraints constraints;
      BER::decode(value, constraints);

      if(constraints != NO_CONSTRAINTS)
         subject.add("X509v3.KeyUsage", constraints);
      }
   else if(extn.oid == OIDS::lookup("X509v3.ExtendedKeyUsage"))
      {
      BER_Decoder key_usage = value.start_cons(SEQUENCE);
      while(key_usage.more_items())
         {
         OID usage_oid;
         key_usage.decode(usage_oid);
         subject.add("X509v3.ExtendedKeyUsage", usage_oid.as_string());
         }
      }
   else if(extn.oid == OIDS::lookup("X509v3.BasicConstraints"))
      {
      u32bit max_path_len = 0;
      is_ca = false;

      value.start_cons(SEQUENCE)
            .decode_optional(is_ca, BOOLEAN, UNIVERSAL, false)
            .decode_optional(max_path_len, INTEGER, UNIVERSAL,
                             NO_CERT_PATH_LIMIT)
            .verify_end()
         .end_cons();

      subject.add("X509v3.BasicConstraints.path_constraint",
                  (is_ca ? max_path_len : 0));
      }
   else if(extn.oid == OIDS::lookup("X509v3.SubjectKeyIdentifier"))
      {
      MemoryVector<byte> v3_subject_key_id;
      value.decode(v3_subject_key_id, OCTET_STRING);
      subject.add("X509v3.SubjectKeyIdentifier", v3_subject_key_id);
      }
   else if(extn.oid == OIDS::lookup("X509v3.AuthorityKeyIdentifier"))
      {
      MemoryVector<byte> v3_issuer_key_id;
      BER_Decoder key_id = value.start_cons(SEQUENCE);
      key_id.decode_optional_string(v3_issuer_key_id, OCTET_STRING, 0);

      issuer.add("X509v3.AuthorityKeyIdentifier", v3_issuer_key_id);
      }
   else if(extn.oid == OIDS::lookup("X509v3.SubjectAlternativeName"))
      {
      AlternativeName alt_name;
      value.decode(alt_name);
      subject.add(alt_name.contents());
      }
   else if(extn.oid == OIDS::lookup("X509v3.IssuerAlternativeName"))
      {
      AlternativeName alt_name;
      value.decode(alt_name);
      issuer.add(alt_name.contents());
      }
   else if(extn.oid == OIDS::lookup("X509v3.CertificatePolicies"))
      {
      BER_Decoder ber_policies = value.start_cons(SEQUENCE);
      while(ber_policies.more_items())
         {
         OID oid;
         BER_Decoder policy = ber_policies.start_cons(SEQUENCE);
         policy.decode(oid);

         if(extn.critical && policy.more_items())
            throw Decoding_Error("X.509 v3 critical policy has qualifiers");

         subject.add("X509v3.CertificatePolicies", oid.as_string());
         }
      }
   else
      {
      if(extn.critical)
         throw Decoding_Error("Unknown critical X.509 v3 extension: " +
                              extn.oid.as_string());
      return;
      }

   value.verify_end();
   }

/*************************************************
* Return the X.509 version in use                *
*************************************************/
u32bit X509_Certificate::x509_version() const
   {
   return (subject.get1_u32bit("X509.Certificate.version") + 1);
   }

/*************************************************
* Return the time this cert becomes valid        *
*************************************************/
std::string X509_Certificate::start_time() const
   {
   return subject.get1("X509.Certificate.start");
   }

/*************************************************
* Return the time this cert becomes invalid      *
*************************************************/
std::string X509_Certificate::end_time() const
   {
   return subject.get1("X509.Certificate.end");
   }

/*************************************************
* Return information about the subject           *
*************************************************/
std::vector<std::string>
X509_Certificate::subject_info(const std::string& what) const
   {
   return subject.get(X509_DN::deref_info_field(what));
   }

/*************************************************
* Return information about the issuer            *
*************************************************/
std::vector<std::string>
X509_Certificate::issuer_info(const std::string& what) const
   {
   return issuer.get(X509_DN::deref_info_field(what));
   }

/*************************************************
* Return the public key in this certificate      *
*************************************************/
X509_PublicKey* X509_Certificate::subject_public_key() const
   {
   DataSource_Memory source(subject.get1("X509.Certificate.public_key"));
   return X509::load_key(source);
   }

/*************************************************
* Check if the certificate is for a CA           *
*************************************************/
bool X509_Certificate::is_CA_cert() const
   {
   if(!is_ca)
      return false;
   if((constraints() & KEY_CERT_SIGN) || (constraints() == NO_CONSTRAINTS))
      return true;
   return false;
   }

/*************************************************
* Return the path length constraint              *
*************************************************/
u32bit X509_Certificate::path_limit() const
   {
   return subject.get1_u32bit("X509v3.BasicConstraints.path_constraint");
   }

/*************************************************
* Return the key usage constraints               *
*************************************************/
Key_Constraints X509_Certificate::constraints() const
   {
   return Key_Constraints(subject.get1_u32bit("X509v3.KeyUsage"));
   }

/*************************************************
* Return the list of extended key usage OIDs     *
*************************************************/
std::vector<std::string> X509_Certificate::ex_constraints() const
   {
   return subject.get("X509v3.ExtendedKeyUsage");
   }

/*************************************************
* Return the list of certificate policies        *
*************************************************/
std::vector<std::string> X509_Certificate::policies() const
   {
   return subject.get("X509v3.CertificatePolicies");
   }

/*************************************************
* Return the authority key id                    *
*************************************************/
MemoryVector<byte> X509_Certificate::authority_key_id() const
   {
   return issuer.get1_memvec("X509v3.AuthorityKeyIdentifier");
   }

/*************************************************
* Return the subject key id                      *
*************************************************/
MemoryVector<byte> X509_Certificate::subject_key_id() const
   {
   return subject.get1_memvec("X509v3.SubjectKeyIdentifier");
   }

/*************************************************
* Return the certificate serial number           *
*************************************************/
MemoryVector<byte> X509_Certificate::serial_number() const
   {
   return subject.get1_memvec("X509.Certificate.serial");
   }

/*************************************************
* Return the distinguished name of the issuer    *
*************************************************/
X509_DN X509_Certificate::issuer_dn() const
   {
   return create_dn(issuer);
   }

/*************************************************
* Return the distinguished name of the subject   *
*************************************************/
X509_DN X509_Certificate::subject_dn() const
   {
   return create_dn(subject);
   }

/*************************************************
* Compare two certificates for equality          *
*************************************************/
bool X509_Certificate::operator==(const X509_Certificate& other) const
   {
   return (sig == other.sig && sig_algo == other.sig_algo &&
           issuer == other.issuer && subject == other.subject);
   }

/*************************************************
* X.509 Certificate Comparison                   *
*************************************************/
bool operator!=(const X509_Certificate& cert1, const X509_Certificate& cert2)
   {
   return !(cert1 == cert2);
   }

}
