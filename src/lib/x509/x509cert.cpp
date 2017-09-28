/*
* X.509 Certificates
* (C) 1999-2010,2015 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509cert.h>
#include <botan/pk_keys.h>
#include <botan/x509_ext.h>
#include <botan/ber_dec.h>
#include <botan/parsing.h>
#include <botan/bigint.h>
#include <botan/oids.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <algorithm>
#include <sstream>

namespace Botan {

namespace {

/*
* Lookup each OID in the vector
*/
std::vector<std::string> lookup_oids(const std::vector<std::string>& in)
   {
   std::vector<std::string> out;

   for(auto i = in.begin(); i != in.end(); ++i)
      out.push_back(OIDS::lookup(OID(*i)));
   return out;
   }

}

/*
* X509_Certificate Constructor
*/
X509_Certificate::X509_Certificate(DataSource& in) :
   X509_Object(in, "CERTIFICATE/X509 CERTIFICATE"),
   m_self_signed(false),
   m_v3_extensions(false)
   {
   do_decode();
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
/*
* X509_Certificate Constructor
*/
X509_Certificate::X509_Certificate(const std::string& fsname) :
   X509_Object(fsname, "CERTIFICATE/X509 CERTIFICATE"),
   m_self_signed(false),
   m_v3_extensions(false)
   {
   do_decode();
   }
#endif

/*
* X509_Certificate Constructor
*/
X509_Certificate::X509_Certificate(const std::vector<uint8_t>& in) :
   X509_Object(in, "CERTIFICATE/X509 CERTIFICATE"),
   m_self_signed(false),
   m_v3_extensions(false)
   {
   do_decode();
   }

/*
* Decode the TBSCertificate data
*/
void X509_Certificate::force_decode()
   {
   size_t version;
   BigInt serial_bn;
   AlgorithmIdentifier sig_algo_inner;
   X509_DN dn_issuer, dn_subject;
   X509_Time start, end;

   BER_Decoder tbs_cert(m_tbs_bits);

   tbs_cert.decode_optional(version, ASN1_Tag(0),
                            ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      .decode(serial_bn)
      .decode(sig_algo_inner)
      .decode(dn_issuer)
      .start_cons(SEQUENCE)
         .decode(start)
         .decode(end)
      .end_cons()
      .decode(dn_subject);

   if(version > 2)
      throw Decoding_Error("Unknown X.509 cert version " + std::to_string(version));
   if(m_sig_algo != sig_algo_inner)
      throw Decoding_Error("Algorithm identifier mismatch");


   m_subject.add(dn_subject.contents());
   m_issuer.add(dn_issuer.contents());

   m_subject.add("X509.Certificate.dn_bits", ASN1::put_in_sequence(dn_subject.get_bits()));
   m_issuer.add("X509.Certificate.dn_bits", ASN1::put_in_sequence(dn_issuer.get_bits()));

   BER_Object public_key = tbs_cert.get_next_object();
   if(public_key.type_tag != SEQUENCE || public_key.class_tag != CONSTRUCTED)
      throw BER_Bad_Tag("X509_Certificate: Unexpected tag for public key",
                        public_key.type_tag, public_key.class_tag);

   std::vector<uint8_t> v2_issuer_key_id, v2_subject_key_id;

   tbs_cert.decode_optional_string(v2_issuer_key_id, BIT_STRING, 1);
   tbs_cert.decode_optional_string(v2_subject_key_id, BIT_STRING, 2);

   BER_Object v3_exts_data = tbs_cert.get_next_object();
   if(v3_exts_data.type_tag == 3 &&
      v3_exts_data.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      BER_Decoder(v3_exts_data.value).decode(m_v3_extensions).verify_end();
      m_v3_extensions.contents_to(m_subject, m_issuer);
      }
   else if(v3_exts_data.type_tag != NO_OBJECT)
      throw BER_Bad_Tag("Unknown tag in X.509 cert",
                        v3_exts_data.type_tag, v3_exts_data.class_tag);

   if(tbs_cert.more_items())
      throw Decoding_Error("TBSCertificate has more items that expected");

   m_subject.add("X509.Certificate.version", static_cast<uint32_t>(version));
   m_subject.add("X509.Certificate.serial", BigInt::encode(serial_bn));
   m_subject.add("X509.Certificate.start", start.to_string());
   m_subject.add("X509.Certificate.end", end.to_string());

   m_issuer.add("X509.Certificate.v2.key_id", v2_issuer_key_id);
   m_subject.add("X509.Certificate.v2.key_id", v2_subject_key_id);

   m_subject.add("X509.Certificate.public_key", hex_encode(public_key.value));

   m_self_signed = false;
   if(dn_subject == dn_issuer)
      {
      std::unique_ptr<Public_Key> pub_key(subject_public_key());
      m_self_signed = check_signature(*pub_key);
      }

   if(m_self_signed && version == 0)
      {
      m_subject.add("X509v3.BasicConstraints.is_ca", 1);
      m_subject.add("X509v3.BasicConstraints.path_constraint", Cert_Extension::NO_CERT_PATH_LIMIT);
      }

   if(is_CA_cert() &&
      !m_subject.has_value("X509v3.BasicConstraints.path_constraint"))
      {
      const size_t limit = (x509_version() < 3) ?
        Cert_Extension::NO_CERT_PATH_LIMIT : 0;

      m_subject.add("X509v3.BasicConstraints.path_constraint", static_cast<uint32_t>(limit));
      }
   }

/*
* Return the X.509 version in use
*/
uint32_t X509_Certificate::x509_version() const
   {
   return (m_subject.get1_uint32("X509.Certificate.version") + 1);
   }

/*
* Return the time this cert becomes valid
*/
std::string X509_Certificate::start_time() const
   {
   return m_subject.get1("X509.Certificate.start");
   }

/*
* Return the time this cert becomes invalid
*/
std::string X509_Certificate::end_time() const
   {
   return m_subject.get1("X509.Certificate.end");
   }

/*
* Return information about the subject
*/
std::vector<std::string>
X509_Certificate::subject_info(const std::string& what) const
   {
   return m_subject.get(X509_DN::deref_info_field(what));
   }

/*
* Return information about the issuer
*/
std::vector<std::string>
X509_Certificate::issuer_info(const std::string& what) const
   {
   return m_issuer.get(X509_DN::deref_info_field(what));
   }

/*
* Return the public key in this certificate
*/
Public_Key* X509_Certificate::subject_public_key() const
   {
   return X509::load_key(
      ASN1::put_in_sequence(this->subject_public_key_bits()));
   }

std::vector<uint8_t> X509_Certificate::subject_public_key_bits() const
   {
   return hex_decode(m_subject.get1("X509.Certificate.public_key"));
   }

std::vector<uint8_t> X509_Certificate::subject_public_key_bitstring() const
   {
   // TODO: cache this
   const std::vector<uint8_t> key_bits = subject_public_key_bits();

   AlgorithmIdentifier public_key_algid;
   std::vector<uint8_t> public_key_bitstr;

   BER_Decoder(key_bits)
      .decode(public_key_algid)
      .decode(public_key_bitstr, BIT_STRING);

   return public_key_bitstr;
   }

std::vector<uint8_t> X509_Certificate::subject_public_key_bitstring_sha1() const
   {
   // TODO: cache this value
   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-1"));
   hash->update(this->subject_public_key_bitstring());
   return hash->final_stdvec();
   }

/*
* Check if the certificate is for a CA
*/
bool X509_Certificate::is_CA_cert() const
   {
   if(!m_subject.get1_uint32("X509v3.BasicConstraints.is_ca"))
      return false;

   return allowed_usage(Key_Constraints(KEY_CERT_SIGN));
   }

bool X509_Certificate::allowed_usage(Key_Constraints usage) const
   {
   if(constraints() == NO_CONSTRAINTS)
      return true;
   return ((constraints() & usage) == usage);
   }

bool X509_Certificate::allowed_extended_usage(const std::string& usage) const
   {
   const std::vector<std::string> ex = ex_constraints();

   if(ex.empty())
      return true;

   if(std::find(ex.begin(), ex.end(), usage) != ex.end())
      return true;

   return false;
   }

bool X509_Certificate::allowed_usage(Usage_Type usage) const
   {
   // These follow suggestions in RFC 5280 4.2.1.12

   switch(usage)
      {
      case Usage_Type::UNSPECIFIED:
         return true;

      case Usage_Type::TLS_SERVER_AUTH:
         return (allowed_usage(KEY_AGREEMENT) || allowed_usage(KEY_ENCIPHERMENT) || allowed_usage(DIGITAL_SIGNATURE)) && allowed_extended_usage("PKIX.ServerAuth");

      case Usage_Type::TLS_CLIENT_AUTH:
         return (allowed_usage(DIGITAL_SIGNATURE) || allowed_usage(KEY_AGREEMENT)) && allowed_extended_usage("PKIX.ClientAuth");

      case Usage_Type::OCSP_RESPONDER:
         return (allowed_usage(DIGITAL_SIGNATURE) || allowed_usage(NON_REPUDIATION)) && allowed_extended_usage("PKIX.OCSPSigning");

      case Usage_Type::CERTIFICATE_AUTHORITY:
         return is_CA_cert();
      }

   return false;
   }

bool X509_Certificate::has_constraints(Key_Constraints constraints) const
   {
   if(this->constraints() == NO_CONSTRAINTS)
      {
      return false;
      }

   return ((this->constraints() & constraints) != 0);
   }

bool X509_Certificate::has_ex_constraint(const std::string& ex_constraint) const
   {
   const std::vector<std::string> ex = ex_constraints();

   if(ex.empty())
      {
      return false;
      }

   if(std::find(ex.begin(), ex.end(), ex_constraint) != ex.end())
      {
      return true;
      }

   return false;
   }

/*
* Return the path length constraint
*/
uint32_t X509_Certificate::path_limit() const
   {
   return m_subject.get1_uint32("X509v3.BasicConstraints.path_constraint", Cert_Extension::NO_CERT_PATH_LIMIT);
   }

/*
* Return if a certificate extension is marked critical
*/
bool X509_Certificate::is_critical(const std::string& ex_name) const
   {
   return !!m_subject.get1_uint32(ex_name + ".is_critical",0);
   }

/*
* Return the key usage constraints
*/
Key_Constraints X509_Certificate::constraints() const
   {
   return Key_Constraints(m_subject.get1_uint32("X509v3.KeyUsage",
                                              NO_CONSTRAINTS));
   }

/*
* Return the list of extended key usage OIDs
*/
std::vector<std::string> X509_Certificate::ex_constraints() const
   {
   return lookup_oids(m_subject.get("X509v3.ExtendedKeyUsage"));
   }

/*
* Return the name constraints
*/
NameConstraints X509_Certificate::name_constraints() const
   {
   std::vector<GeneralSubtree> permit, exclude;

   for(const std::string& v: m_subject.get("X509v3.NameConstraints.permitted"))
      {
      permit.push_back(GeneralSubtree(v));
      }

   for(const std::string& v: m_subject.get("X509v3.NameConstraints.excluded"))
      {
      exclude.push_back(GeneralSubtree(v));
      }

   return NameConstraints(std::move(permit),std::move(exclude));
   }

/*
* Return the list of certificate policies
*/
std::vector<std::string> X509_Certificate::policies() const
   {
   return lookup_oids(m_subject.get("X509v3.CertificatePolicies"));
   }

Extensions X509_Certificate::v3_extensions() const
   {
   return m_v3_extensions;
   }

std::string X509_Certificate::ocsp_responder() const
   {
   return m_subject.get1("OCSP.responder", "");
   }

std::string X509_Certificate::crl_distribution_point() const
   {
   return m_subject.get1("CRL.DistributionPoint", "");
   }

/*
* Return the authority key id
*/
std::vector<uint8_t> X509_Certificate::authority_key_id() const
   {
   return m_issuer.get1_memvec("X509v3.AuthorityKeyIdentifier");
   }

/*
* Return the subject key id
*/
std::vector<uint8_t> X509_Certificate::subject_key_id() const
   {
   return m_subject.get1_memvec("X509v3.SubjectKeyIdentifier");
   }

/*
* Return the certificate serial number
*/
std::vector<uint8_t> X509_Certificate::serial_number() const
   {
   return m_subject.get1_memvec("X509.Certificate.serial");
   }

X509_DN X509_Certificate::issuer_dn() const
   {
   return create_dn(m_issuer);
   }

std::vector<uint8_t> X509_Certificate::raw_issuer_dn() const
   {
   return m_issuer.get1_memvec("X509.Certificate.dn_bits");
   }

std::vector<uint8_t> X509_Certificate::raw_issuer_dn_sha256() const
   {
   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
   hash->update(raw_issuer_dn());
   return hash->final_stdvec();
   }

X509_DN X509_Certificate::subject_dn() const
   {
   return create_dn(m_subject);
   }

std::vector<uint8_t> X509_Certificate::raw_subject_dn() const
   {
   return m_subject.get1_memvec("X509.Certificate.dn_bits");
   }

std::vector<uint8_t> X509_Certificate::raw_subject_dn_sha256() const
   {
   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
   hash->update(raw_subject_dn());
   return hash->final_stdvec();
   }

std::string X509_Certificate::fingerprint(const std::string& hash_name) const
   {
   std::unique_ptr<HashFunction> hash(HashFunction::create(hash_name));
   hash->update(this->BER_encode());
   const auto hex_print = hex_encode(hash->final());

   std::string formatted_print;

   for(size_t i = 0; i != hex_print.size(); i += 2)
      {
      formatted_print.push_back(hex_print[i]);
      formatted_print.push_back(hex_print[i+1]);

      if(i != hex_print.size() - 2)
         formatted_print.push_back(':');
      }

   return formatted_print;
   }

bool X509_Certificate::matches_dns_name(const std::string& name) const
   {
   if(name.empty())
      return false;

   std::vector<std::string> issued_names = subject_info("DNS");

   // Fall back to CN only if no DNS names are set (RFC 6125 sec 6.4.4)
   if(issued_names.empty())
      issued_names = subject_info("Name");

   for(size_t i = 0; i != issued_names.size(); ++i)
      {
      if(host_wildcard_match(issued_names[i], name))
         return true;
      }

   return false;
   }

/*
* Compare two certificates for equality
*/
bool X509_Certificate::operator==(const X509_Certificate& other) const
   {
   return (m_sig == other.m_sig &&
           m_sig_algo == other.m_sig_algo &&
           m_self_signed == other.m_self_signed &&
           m_issuer == other.m_issuer &&
           m_subject == other.m_subject);
   }

bool X509_Certificate::operator<(const X509_Certificate& other) const
   {
   /* If signature values are not equal, sort by lexicographic ordering of that */
   if(m_sig != other.m_sig)
      {
      if(m_sig < other.m_sig)
         return true;
      return false;
      }

   // Then compare the signed contents
   return m_tbs_bits < other.m_tbs_bits;
   }

/*
* X.509 Certificate Comparison
*/
bool operator!=(const X509_Certificate& cert1, const X509_Certificate& cert2)
   {
   return !(cert1 == cert2);
   }

std::string X509_Certificate::to_string() const
   {
   const std::vector<std::string> dn_fields{
      "Name",
      "Email",
      "Organization",
      "Organizational Unit",
      "Locality",
      "State",
      "Country",
      "IP",
      "DNS",
      "URI",
      "PKIX.XMPPAddr"
      };

   std::ostringstream out;

   for(auto&& field : dn_fields)
      {
      for(auto&& val : subject_info(field))
         {
         out << "Subject " << field << ": " << val << "\n";
         }
      }

   for(auto&& field : dn_fields)
      {
      for(auto&& val : issuer_info(field))
         {
         out << "Issuer " << field << ": " << val << "\n";
         }
      }

   out << "Version: " << this->x509_version() << "\n";

   out << "Not valid before: " << this->start_time() << "\n";
   out << "Not valid after: " << this->end_time() << "\n";

   out << "Constraints:\n";
   Key_Constraints constraints = this->constraints();
   if(constraints == NO_CONSTRAINTS)
      out << " None\n";
   else
      {
      if(constraints & DIGITAL_SIGNATURE)
         out << "   Digital Signature\n";
      if(constraints & NON_REPUDIATION)
         out << "   Non-Repudiation\n";
      if(constraints & KEY_ENCIPHERMENT)
         out << "   Key Encipherment\n";
      if(constraints & DATA_ENCIPHERMENT)
         out << "   Data Encipherment\n";
      if(constraints & KEY_AGREEMENT)
         out << "   Key Agreement\n";
      if(constraints & KEY_CERT_SIGN)
         out << "   Cert Sign\n";
      if(constraints & CRL_SIGN)
         out << "   CRL Sign\n";
      if(constraints & ENCIPHER_ONLY)
         out << "   Encipher Only\n";
      if(constraints & DECIPHER_ONLY)
         out << "   Decipher Only\n";
      }

   std::vector<std::string> policies = this->policies();
   if(!policies.empty())
      {
      out << "Policies: " << "\n";
      for(size_t i = 0; i != policies.size(); i++)
         out << "   " << policies[i] << "\n";
      }

   std::vector<std::string> ex_constraints = this->ex_constraints();
   if(!ex_constraints.empty())
      {
      out << "Extended Constraints:\n";
      for(size_t i = 0; i != ex_constraints.size(); i++)
         out << "   " << ex_constraints[i] << "\n";
      }

   NameConstraints name_constraints = this->name_constraints();
   if(!name_constraints.permitted().empty() ||
         !name_constraints.excluded().empty())
      {
      out << "Name Constraints:\n";

      if(!name_constraints.permitted().empty())
         {
         out << "   Permit";
         for(auto st: name_constraints.permitted())
            {
            out << " " << st.base();
            }
         out << "\n";
         }

      if(!name_constraints.excluded().empty())
         {
         out << "   Exclude";
         for(auto st: name_constraints.excluded())
            {
            out << " " << st.base();
            }
         out << "\n";
         }
      }

   if(!ocsp_responder().empty())
      out << "OCSP responder " << ocsp_responder() << "\n";
   if(!crl_distribution_point().empty())
      out << "CRL " << crl_distribution_point() << "\n";

   out << "Signature algorithm: " <<
      OIDS::lookup(this->signature_algorithm().oid) << "\n";

   out << "Serial number: " << hex_encode(this->serial_number()) << "\n";

   if(this->authority_key_id().size())
     out << "Authority keyid: " << hex_encode(this->authority_key_id()) << "\n";

   if(this->subject_key_id().size())
     out << "Subject keyid: " << hex_encode(this->subject_key_id()) << "\n";

   std::unique_ptr<Public_Key> pubkey(this->subject_public_key());
   out << "Public Key:\n" << X509::PEM_encode(*pubkey);

   return out.str();
   }

/*
* Create and populate a X509_DN
*/
X509_DN create_dn(const Data_Store& info)
   {
   auto names = info.search_for(
      [](const std::string& key, const std::string&)
      {
         return (key.find("X520.") != std::string::npos);
      });

   X509_DN dn;

   for(auto i = names.begin(); i != names.end(); ++i)
      dn.add_attribute(i->first, i->second);

   return dn;
   }

/*
* Create and populate an AlternativeName
*/
AlternativeName create_alt_name(const Data_Store& info)
   {
   auto names = info.search_for(
      [](const std::string& key, const std::string&)
      {
         return (key == "RFC822" ||
                 key == "DNS" ||
                 key == "URI" ||
                 key == "IP");
      });

   AlternativeName alt_name;

   for(auto i = names.begin(); i != names.end(); ++i)
      alt_name.add_attribute(i->first, i->second);

   return alt_name;
   }

}
