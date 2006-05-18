/*************************************************
* X.509 Certificates Source File                 *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/x509cert.h>
#include <botan/asn1_int.h>
#include <botan/stl_util.h>
#include <botan/parsing.h>
#include <botan/bigint.h>
#include <botan/conf.h>
#include <botan/oids.h>
#include <botan/pem.h>
#include <algorithm>

#include <assert.h>

namespace Botan {

namespace {

/*************************************************
* Get information from the DistinguishedName     *
*************************************************/
void load_info(std::multimap<std::string, std::string>& names,
               const X509_DN& dn_info)
   {
   typedef std::multimap<OID, std::string>::const_iterator rdn_iter;
   std::multimap<OID, std::string> attr = dn_info.get_attributes();

   for(rdn_iter j = attr.begin(); j != attr.end(); ++j)
      {
      const std::string oid_name = OIDS::lookup(j->first);

      if(oid_name == "PKCS9.EmailAddress")
         multimap_insert(names, std::string("RFC822"), j->second);
      else
         multimap_insert(names, oid_name, j->second);
      }
   }

/*************************************************
* Get information from the alternative name      *
*************************************************/
void load_info(std::multimap<std::string, std::string>& names,
               const AlternativeName& alt_info)
   {
   typedef std::multimap<std::string, std::string>::const_iterator rdn_iter;
   std::multimap<std::string, std::string> attr = alt_info.get_attributes();

   for(rdn_iter j = attr.begin(); j != attr.end(); ++j)
      multimap_insert(names, j->first, j->second);

   typedef std::multimap<OID, ASN1_String>::const_iterator on_iter;
   std::multimap<OID, ASN1_String> othernames = alt_info.get_othernames();
   for(on_iter j = othernames.begin(); j != othernames.end(); ++j)
      multimap_insert(names, OIDS::lookup(j->first), j->second.value());
   }

/*************************************************
* Get some information from names                *
*************************************************/
std::string get_info(const std::multimap<std::string, std::string>& names,
                     const std::string& info)
   {
   typedef std::multimap<std::string, std::string>::const_iterator rdn_iter;

   const std::string what = X509_DN::deref_info_field(info);
   std::pair<rdn_iter, rdn_iter> range = names.equal_range(what);

   std::vector<std::string> results;
   for(rdn_iter j = range.first; j != range.second; ++j)
      {
      if(std::find(results.begin(), results.end(), j->second) == results.end())
         results.push_back(j->second);
      }

   std::string value;
   for(u32bit j = 0; j != results.size(); ++j)
      value += results[j] + '/';
   if(value.size())
      value.erase(value.size() - 1, 1);
   return value;
   }

/*************************************************
* Create and populate a X509_DN                  *
*************************************************/
X509_DN create_dn(const std::multimap<std::string, std::string>& names)
   {
   typedef std::multimap<std::string, std::string>::const_iterator rdn_iter;

   X509_DN new_dn;
   for(rdn_iter j = names.begin(); j != names.end(); ++j)
      {
      const std::string oid = j->first;
      const std::string value = j->second;
      if(!OIDS::have_oid(oid))
         continue;
      new_dn.add_attribute(oid, j->second);
      }
   return new_dn;
   }

}

/*************************************************
* X509_Certificate Constructor                   *
*************************************************/
X509_Certificate::X509_Certificate(DataSource& in) :
   X509_Object(in, "CERTIFICATE/X509 CERTIFICATE")
   {
   is_ca = false;
   do_decode();
   }

/*************************************************
* X509_Certificate Constructor                   *
*************************************************/
X509_Certificate::X509_Certificate(const std::string& in) :
   X509_Object(in, "CERTIFICATE/X509 CERTIFICATE")
   {
   is_ca = false;
   do_decode();
   }

/*************************************************
* Decode the TBSCertificate data                 *
*************************************************/
void X509_Certificate::force_decode()
   {
   BER_Decoder tbs_cert(tbs_bits);

   u32bit version;
   BER::decode_optional(tbs_cert, version, ASN1_Tag(0),
                        ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));
   if(version > 2)
      throw Decoding_Error("Unknown X.509 cert version " + to_string(version));
   if(version < 2)
      {
      is_ca = Config::get_bool("x509/v1_assume_ca");
      info.add("X509v3.BasicConstraints.path_constraint", NO_CERT_PATH_LIMIT);
      }

   BigInt serial_bn;
   tbs_cert.decode(serial_bn);

   AlgorithmIdentifier sig_algo_inner;
   BER::decode(tbs_cert, sig_algo_inner);

   if(sig_algo != sig_algo_inner)
      throw Decoding_Error("Algorithm identifier mismatch");

   X509_DN dn_issuer;
   BER::decode(tbs_cert, dn_issuer);
   load_info(issuer, dn_issuer);

   X509_Time start, end;

   BER_Decoder validity = BER::get_subsequence(tbs_cert);
   BER::decode(validity, start);
   BER::decode(validity, end);
   validity.verify_end();

   X509_DN dn_subject;
   BER::decode(tbs_cert, dn_subject);
   load_info(subject, dn_subject);

   BER_Object public_key = tbs_cert.get_next_object();
   if(public_key.type_tag != SEQUENCE || public_key.class_tag != CONSTRUCTED)
      throw BER_Bad_Tag("X509_Certificate: Unexpected tag for public key",
                        public_key.type_tag, public_key.class_tag);

   MemoryVector<byte> v2_issuer_key_id, v2_subject_key_id;

   BER::decode_optional_string(tbs_cert, v2_issuer_key_id, BIT_STRING,
                               ASN1_Tag(1), CONTEXT_SPECIFIC);
   BER::decode_optional_string(tbs_cert, v2_subject_key_id, BIT_STRING,
                               ASN1_Tag(2), CONTEXT_SPECIFIC);

   BER_Object v3_exts_data = tbs_cert.get_next_object();
   if(v3_exts_data.type_tag == 3 &&
      v3_exts_data.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      BER_Decoder v3_exts_decoder(v3_exts_data.value);
      BER_Decoder sequence = BER::get_subsequence(v3_exts_decoder);

      while(sequence.more_items())
         {
         Extension extn;
         BER::decode(sequence, extn);
         handle_v3_extension(extn);
         }
      sequence.verify_end();
      v3_exts_decoder.verify_end();
      }
   else if(v3_exts_data.type_tag != NO_OBJECT)
      throw BER_Bad_Tag("Unknown tag in X.509 cert",
                        v3_exts_data.type_tag, v3_exts_data.class_tag);

   if(tbs_cert.more_items())
      throw Decoding_Error("TBSCertificate has more items that expected");

   info.add("X509.Certificate.version", version);
   info.add("X509.Certificate.serial", BigInt::encode(serial_bn));
   info.add("X509.Certificate.start", start.readable_string());
   info.add("X509.Certificate.end", end.readable_string());

   info.add("X509.Certificate.v2.issuer_key_id", v2_issuer_key_id);
   info.add("X509.Certificate.v2.subject_key_id", v2_subject_key_id);

   info.add("X509.Certificate.public_key",
            PEM_Code::encode(
               ASN1::put_in_sequence(public_key.value),
               "PUBLIC KEY"
               )
      );
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
         info.add("X509v3.KeyUsage", constraints);
      }
   else if(extn.oid == OIDS::lookup("X509v3.ExtendedKeyUsage"))
      {
      BER_Decoder key_usage = BER::get_subsequence(value);
      while(key_usage.more_items())
         {
         OID usage_oid;
         BER::decode(key_usage, usage_oid);
         info.add("X509v3.ExtendedKeyUsage", usage_oid.as_string());
         }
      }
   else if(extn.oid == OIDS::lookup("X509v3.BasicConstraints"))
      {
      u32bit max_path_len = 0;
      BER_Decoder basic_constraints = BER::get_subsequence(value);
      BER::decode_optional(basic_constraints, is_ca,
                           BOOLEAN, UNIVERSAL, false);
      BER::decode_optional(basic_constraints, max_path_len,
                           INTEGER, UNIVERSAL, NO_CERT_PATH_LIMIT);

      info.add("X509v3.BasicConstraints.is_ca", is_ca);
      info.add("X509v3.BasicConstraints.path_constraint", max_path_len);
      }
   else if(extn.oid == OIDS::lookup("X509v3.SubjectKeyIdentifier"))
      {
      MemoryVector<byte> v3_subject_key_id;
      value.decode(v3_subject_key_id, OCTET_STRING);
      info.add("X509v3.SubjectKeyIdentifier", v3_subject_key_id);
      }
   else if(extn.oid == OIDS::lookup("X509v3.AuthorityKeyIdentifier"))
      {
      MemoryVector<byte> v3_issuer_key_id;
      BER_Decoder key_id = BER::get_subsequence(value);
      BER::decode_optional_string(key_id, v3_issuer_key_id, OCTET_STRING,
                                  ASN1_Tag(0), CONTEXT_SPECIFIC);

      info.add("X509v3.AuthorityKeyIdentifier", v3_issuer_key_id);
      }
   else if(extn.oid == OIDS::lookup("X509v3.SubjectAlternativeName"))
      {
      AlternativeName alt_name;
      BER::decode(value, alt_name);
      load_info(subject, alt_name);
      }
   else if(extn.oid == OIDS::lookup("X509v3.IssuerAlternativeName"))
      {
      AlternativeName alt_name;
      BER::decode(value, alt_name);
      load_info(issuer, alt_name);
      }
   else if(extn.oid == OIDS::lookup("X509v3.CertificatePolicies"))
      {
      BER_Decoder ber_policies = BER::get_subsequence(value);
      while(ber_policies.more_items())
         {
         OID oid;
         BER_Decoder policy = BER::get_subsequence(ber_policies);
         BER::decode(policy, oid);

         if(extn.critical && policy.more_items())
            throw Decoding_Error("X.509 v3 critical policy has qualifiers");

         info.add("X509v3.CertificatePolicies", oid.as_string());
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
   return (info.get1_u32bit("X509.Certificate.version") + 1);
   }

/*************************************************
* Return the time this cert becomes valid        *
*************************************************/
std::string X509_Certificate::start_time() const
   {
   return info.get1("X509.Certificate.start");
   }

/*************************************************
* Return the time this cert becomes invalid      *
*************************************************/
std::string X509_Certificate::end_time() const
   {
   return info.get1("X509.Certificate.end");
   }

/*************************************************
* Return information about the subject           *
*************************************************/
std::string X509_Certificate::subject_info(const std::string& info) const
   {
   return get_info(subject, info);
   }

/*************************************************
* Return information about the issuer            *
*************************************************/
std::string X509_Certificate::issuer_info(const std::string& info) const
   {
   return get_info(issuer, info);
   }

/*************************************************
* Return the public key in this certificate      *
*************************************************/
X509_PublicKey* X509_Certificate::subject_public_key() const
   {
   DataSource_Memory source(info.get1("X509.Certificate.public_key"));
   return X509::load_key(source);
   }

/*************************************************
* Check if the certificate is self-signed        *
*************************************************/
bool X509_Certificate::self_signed() const
   {
   return (create_dn(issuer) == create_dn(subject));
   }

/*************************************************
* Check if the certificate is for a CA           *
*************************************************/
bool X509_Certificate::is_CA_cert() const
   {
   if(!is_ca) return false;
   if((constraints() & KEY_CERT_SIGN) ||
      (constraints() == NO_CONSTRAINTS))
      return true;
   return false;
   }

/*************************************************
* Return the path length constraint              *
*************************************************/
u32bit X509_Certificate::path_limit() const
   {
   return info.get1_u32bit("X509v3.BasicConstraints.path_constraint");
   }

/*************************************************
* Return the key usage constraints               *
*************************************************/
Key_Constraints X509_Certificate::constraints() const
   {
   return Key_Constraints(info.get1_u32bit("X509v3.KeyUsage"));
   }

/*************************************************
* Return the list of extended key usage OIDs     *
*************************************************/
std::vector<std::string> X509_Certificate::ex_constraints() const
   {
   return info.get("X509v3.ExtendedKeyUsage");
   }

/*************************************************
* Return the list of certificate policies        *
*************************************************/
std::vector<std::string> X509_Certificate::policies() const
   {
   return info.get("X509v3.CertificatePolicies");
   }

/*************************************************
* Return the authority key id                    *
*************************************************/
MemoryVector<byte> X509_Certificate::authority_key_id() const
   {
   return info.get1_memvec("X509v3.AuthorityKeyIdentifier");
   }

/*************************************************
* Return the subject key id                      *
*************************************************/
MemoryVector<byte> X509_Certificate::subject_key_id() const
   {
   return info.get1_memvec("X509v3.SubjectKeyIdentifier");
   }

/*************************************************
* Return the certificate serial number           *
*************************************************/
MemoryVector<byte> X509_Certificate::serial_number() const
   {
   return info.get1_memvec("X509.Certificate.serial");
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
bool X509_Certificate::operator==(const X509_Certificate& cert) const
   {
   if(sig != cert.sig || sig_algo != cert.sig_algo)
      return false;
   if(issuer != cert.issuer || subject != cert.subject)
      return false;
   return (info == cert.info);
   }

/*************************************************
* X.509 Certificate Comparison                   *
*************************************************/
bool operator!=(const X509_Certificate& cert1, const X509_Certificate& cert2)
   {
   return !(cert1 == cert2);
   }

}
