/*
* X.509 Certificates
* (C) 1999-2010,2015,2017 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509cert.h>
#include <botan/x509_key.h>
#include <botan/datastor.h>
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

struct X509_Certificate_Data
   {
   std::vector<uint8_t> m_serial;
   AlgorithmIdentifier m_sig_algo_inner;
   X509_DN m_issuer_dn;
   X509_DN m_subject_dn;
   std::vector<uint8_t> m_issuer_dn_bits;
   std::vector<uint8_t> m_subject_dn_bits;
   X509_Time m_not_before;
   X509_Time m_not_after;
   std::vector<uint8_t> m_subject_public_key_bits;
   std::vector<uint8_t> m_subject_public_key_bits_seq;
   std::vector<uint8_t> m_subject_public_key_bitstring;
   std::vector<uint8_t> m_subject_public_key_bitstring_sha1;
   AlgorithmIdentifier m_subject_public_key_algid;

   std::vector<uint8_t> m_v2_issuer_key_id;
   std::vector<uint8_t> m_v2_subject_key_id;
   Extensions m_v3_extensions;

   std::vector<OID> m_extended_key_usage;
   std::vector<uint8_t> m_authority_key_id;
   std::vector<uint8_t> m_subject_key_id;
   std::vector<OID> m_cert_policies;

   std::vector<std::string> m_crl_distribution_points;
   std::string m_ocsp_responder;
   std::vector<std::string> m_ca_issuers;

   std::vector<uint8_t> m_issuer_dn_bits_sha256;
   std::vector<uint8_t> m_subject_dn_bits_sha256;

   std::string m_fingerprint_sha1;
   std::string m_fingerprint_sha256;

   AlternativeName m_subject_alt_name;
   AlternativeName m_issuer_alt_name;
   NameConstraints m_name_constraints;

   Data_Store m_subject_ds;
   Data_Store m_issuer_ds;

   size_t m_version = 0;
   size_t m_path_len_constraint = 0;
   Key_Constraints m_key_constraints = NO_CONSTRAINTS;
   bool m_self_signed = false;
   bool m_is_ca_certificate = false;
   bool m_serial_negative = false;
   };

std::string X509_Certificate::PEM_label() const
   {
   return "CERTIFICATE";
   }

std::vector<std::string> X509_Certificate::alternate_PEM_labels() const
   {
   return { "X509 CERTIFICATE" };
   }

X509_Certificate::X509_Certificate(DataSource& src)
   {
   load_data(src);
   }

X509_Certificate::X509_Certificate(const std::vector<uint8_t>& vec)
   {
   DataSource_Memory src(vec.data(), vec.size());
   load_data(src);
   }

X509_Certificate::X509_Certificate(const uint8_t data[], size_t len)
   {
   DataSource_Memory src(data, len);
   load_data(src);
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
X509_Certificate::X509_Certificate(const std::string& fsname)
   {
   DataSource_Stream src(fsname, true);
   load_data(src);
   }
#endif

namespace {

std::unique_ptr<X509_Certificate_Data> parse_x509_cert_body(const X509_Object& obj)
   {
   std::unique_ptr<X509_Certificate_Data> data(new X509_Certificate_Data);

   BigInt serial_bn;
   BER_Object public_key;
   BER_Object v3_exts_data;

   BER_Decoder(obj.signed_body())
      .decode_optional(data->m_version, ASN1_Tag(0), ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      .decode(serial_bn)
      .decode(data->m_sig_algo_inner)
      .decode(data->m_issuer_dn)
      .start_cons(SEQUENCE)
         .decode(data->m_not_before)
         .decode(data->m_not_after)
      .end_cons()
      .decode(data->m_subject_dn)
      .get_next(public_key)
      .decode_optional_string(data->m_v2_issuer_key_id, BIT_STRING, 1)
      .decode_optional_string(data->m_v2_subject_key_id, BIT_STRING, 2)
      .get_next(v3_exts_data)
      .verify_end("TBSCertificate has extra data after extensions block");

   if(data->m_version > 2)
      throw Decoding_Error("Unknown X.509 cert version " + std::to_string(data->m_version));
   if(obj.signature_algorithm() != data->m_sig_algo_inner)
      throw Decoding_Error("X.509 Certificate had differing algorithm identifers in inner and outer ID fields");

   public_key.assert_is_a(SEQUENCE, CONSTRUCTED, "X.509 certificate public key");

   // crude method to save the serial's sign; will get lost during decoding, otherwise
   data->m_serial_negative = serial_bn.is_negative();

   // for general sanity convert wire version (0 based) to standards version (v1 .. v3)
   data->m_version += 1;

   data->m_serial = BigInt::encode(serial_bn);
   data->m_subject_dn_bits = ASN1::put_in_sequence(data->m_subject_dn.get_bits());
   data->m_issuer_dn_bits = ASN1::put_in_sequence(data->m_issuer_dn.get_bits());

   // validate_public_key_params(public_key.value);
   AlgorithmIdentifier public_key_alg_id;
   BER_Decoder(public_key).decode(public_key_alg_id).discard_remaining();

   const std::vector<std::string> public_key_info =
      split_on(OIDS::oid2str_or_empty(public_key_alg_id.get_oid()), '/');

   if(!public_key_info.empty() && public_key_info[0] == "RSA")
      {
      // RFC4055: If PublicKeyAlgo = PSS or OAEP: limit the use of the public key exclusively to either RSASSA - PSS or RSAES - OAEP
      if(public_key_info.size() >= 2)
         {
         if(public_key_info[1] == "EMSA4")
            {
            /*
            When the RSA private key owner wishes to limit the use of the public
            key exclusively to RSASSA-PSS, then the id-RSASSA-PSS object
            identifier MUST be used in the algorithm field within the subject
            public key information, and, if present, the parameters field MUST
            contain RSASSA-PSS-params.

            All parameters in the signature structure algorithm identifier MUST
            match the parameters in the key structure algorithm identifier
            except the saltLength field. The saltLength field in the signature parameters
            MUST be greater or equal to that in the key parameters field.

            ToDo: Allow salt length to be greater
            */
            if(public_key_alg_id != obj.signature_algorithm())
               {
               throw Decoding_Error("Algorithm identifier mismatch");
               }
            }
         }
      else
         {
         // oid = rsaEncryption -> parameters field MUST contain NULL
         if(public_key_alg_id != AlgorithmIdentifier(public_key_alg_id.get_oid(), AlgorithmIdentifier::USE_NULL_PARAM))
            {
            throw Decoding_Error("RSA algorithm parameters field MUST contain NULL");
            }
         }
      }

   data->m_subject_public_key_bits.assign(public_key.bits(), public_key.bits() + public_key.length());

   data->m_subject_public_key_bits_seq = ASN1::put_in_sequence(data->m_subject_public_key_bits);

   BER_Decoder(data->m_subject_public_key_bits)
      .decode(data->m_subject_public_key_algid)
      .decode(data->m_subject_public_key_bitstring, BIT_STRING);

   if(v3_exts_data.is_a(3, ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC)))
      {
      // Path validation will reject a v1/v2 cert with v3 extensions
      BER_Decoder(v3_exts_data).decode(data->m_v3_extensions).verify_end();
      }
   else if(v3_exts_data.is_set())
      {
      throw BER_Bad_Tag("Unknown tag in X.509 cert", v3_exts_data.tagging());
      }

   // Now cache some fields from the extensions
   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Key_Usage>())
      {
      data->m_key_constraints = ext->get_constraints();
      /*
      RFC 5280: When the keyUsage extension appears in a certificate,
      at least one of the bits MUST be set to 1.
      */
      if(data->m_key_constraints == NO_CONSTRAINTS)
         {
         throw Decoding_Error("Certificate has invalid encoding for KeyUsage");
         }
      }
   else
      {
      data->m_key_constraints = NO_CONSTRAINTS;
      }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Subject_Key_ID>())
      {
      data->m_subject_key_id = ext->get_key_id();
      }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Authority_Key_ID>())
      {
      data->m_authority_key_id = ext->get_key_id();
      }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Name_Constraints>())
      {
      data->m_name_constraints = ext->get_name_constraints();
      }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Basic_Constraints>())
      {
      if(ext->get_is_ca() == true)
         {
         /*
         * RFC 5280 section 4.2.1.3 requires that CAs include KeyUsage in all
         * intermediate CA certificates they issue. Currently we accept it being
         * missing, as do most other implementations. But it may be worth
         * removing this entirely, or alternately adding a warning level
         * validation failure for it.
         */
         if(data->m_key_constraints == NO_CONSTRAINTS ||
            (data->m_key_constraints & KEY_CERT_SIGN))
            {
            data->m_is_ca_certificate = true;
            data->m_path_len_constraint = ext->get_path_limit();
            }
         }
      }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Issuer_Alternative_Name>())
      {
      data->m_issuer_alt_name = ext->get_alt_name();
      }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Subject_Alternative_Name>())
      {
      data->m_subject_alt_name = ext->get_alt_name();
      }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Extended_Key_Usage>())
      {
      data->m_extended_key_usage = ext->get_oids();
      }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Certificate_Policies>())
      {
      data->m_cert_policies = ext->get_policy_oids();
      }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Authority_Information_Access>())
      {
      data->m_ocsp_responder = ext->ocsp_responder();
      data->m_ca_issuers = ext->ca_issuers();
      }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::CRL_Distribution_Points>())
      {
      data->m_crl_distribution_points = ext->crl_distribution_urls();
      }

   // Check for self-signed vs self-issued certificates
   if(data->m_subject_dn == data->m_issuer_dn)
      {
      if(data->m_subject_key_id.empty() == false && data->m_authority_key_id.empty() == false)
         {
         data->m_self_signed = (data->m_subject_key_id == data->m_authority_key_id);
         }
      else
         {
         /*
         If a parse error or unknown algorithm is encountered, default
         to assuming it is self signed. We have no way of being certain but
         that is usually the default case (self-issued is rare in practice).
         */
         data->m_self_signed = true;

         try
            {
            std::unique_ptr<Public_Key> pub_key(X509::load_key(data->m_subject_public_key_bits_seq));

            Certificate_Status_Code sig_status = obj.verify_signature(*pub_key);

            if(sig_status == Certificate_Status_Code::OK ||
               sig_status == Certificate_Status_Code::SIGNATURE_ALGO_UNKNOWN)
               {
               data->m_self_signed = true;
               }
            else
               {
               data->m_self_signed = false;
               }
            }
         catch(...)
            {
            // ignore errors here to allow parsing to continue
            }
         }
      }

   const std::vector<uint8_t> full_encoding = obj.BER_encode();

   std::unique_ptr<HashFunction> sha1(HashFunction::create("SHA-1"));
   if(sha1)
      {
      sha1->update(data->m_subject_public_key_bitstring);
      data->m_subject_public_key_bitstring_sha1 = sha1->final_stdvec();
      // otherwise left as empty, and we will throw if subject_public_key_bitstring_sha1 is called

      data->m_fingerprint_sha1 = create_hex_fingerprint(full_encoding, "SHA-1");
      }

   std::unique_ptr<HashFunction> sha256(HashFunction::create("SHA-256"));
   if(sha256)
      {
      sha256->update(data->m_issuer_dn_bits);
      data->m_issuer_dn_bits_sha256 = sha256->final_stdvec();

      sha256->update(data->m_subject_dn_bits);
      data->m_subject_dn_bits_sha256 = sha256->final_stdvec();

      data->m_fingerprint_sha256 = create_hex_fingerprint(full_encoding, "SHA-256");
      }

   data->m_subject_ds.add(data->m_subject_dn.contents());
   data->m_issuer_ds.add(data->m_issuer_dn.contents());
   data->m_v3_extensions.contents_to(data->m_subject_ds, data->m_issuer_ds);

   return data;
   }

}

/*
* Decode the TBSCertificate data
*/
void X509_Certificate::force_decode()
   {
   m_data.reset();

   std::unique_ptr<X509_Certificate_Data> data = parse_x509_cert_body(*this);

   m_data.reset(data.release());
   }

const X509_Certificate_Data& X509_Certificate::data() const
   {
   if(m_data == nullptr)
      {
      throw Invalid_State("X509_Certificate uninitialized");
      }
   return *m_data.get();
   }

uint32_t X509_Certificate::x509_version() const
   {
   return static_cast<uint32_t>(data().m_version);
   }

bool X509_Certificate::is_self_signed() const
   {
   return data().m_self_signed;
   }

const X509_Time& X509_Certificate::not_before() const
   {
   return data().m_not_before;
   }

const X509_Time& X509_Certificate::not_after() const
   {
   return data().m_not_after;
   }

const AlgorithmIdentifier& X509_Certificate::subject_public_key_algo() const
   {
   return data().m_subject_public_key_algid;
   }

const std::vector<uint8_t>& X509_Certificate::v2_issuer_key_id() const
   {
   return data().m_v2_issuer_key_id;
   }

const std::vector<uint8_t>& X509_Certificate::v2_subject_key_id() const
   {
   return data().m_v2_subject_key_id;
   }

const std::vector<uint8_t>& X509_Certificate::subject_public_key_bits() const
   {
   return data().m_subject_public_key_bits;
   }

const std::vector<uint8_t>& X509_Certificate::subject_public_key_info() const
   {
   return data().m_subject_public_key_bits_seq;
   }

const std::vector<uint8_t>& X509_Certificate::subject_public_key_bitstring() const
   {
   return data().m_subject_public_key_bitstring;
   }

const std::vector<uint8_t>& X509_Certificate::subject_public_key_bitstring_sha1() const
   {
   if(data().m_subject_public_key_bitstring_sha1.empty())
      throw Encoding_Error("X509_Certificate::subject_public_key_bitstring_sha1 called but SHA-1 disabled in build");

   return data().m_subject_public_key_bitstring_sha1;
   }

const std::vector<uint8_t>& X509_Certificate::authority_key_id() const
   {
   return data().m_authority_key_id;
   }

const std::vector<uint8_t>& X509_Certificate::subject_key_id() const
   {
   return data().m_subject_key_id;
   }

const std::vector<uint8_t>& X509_Certificate::serial_number() const
   {
   return data().m_serial;
   }

bool X509_Certificate::is_serial_negative() const
   {
   return data().m_serial_negative;
   }


const X509_DN& X509_Certificate::issuer_dn() const
   {
   return data().m_issuer_dn;
   }

const X509_DN& X509_Certificate::subject_dn() const
   {
   return data().m_subject_dn;
   }

const std::vector<uint8_t>& X509_Certificate::raw_issuer_dn() const
   {
   return data().m_issuer_dn_bits;
   }

const std::vector<uint8_t>& X509_Certificate::raw_subject_dn() const
   {
   return data().m_subject_dn_bits;
   }

bool X509_Certificate::is_CA_cert() const
   {
   if(data().m_version < 3 && data().m_self_signed)
      return true;

   return data().m_is_ca_certificate;
   }

uint32_t X509_Certificate::path_limit() const
   {
   if(data().m_version < 3 && data().m_self_signed)
      return 32; // in theory infinite, but this is more than enough

   return static_cast<uint32_t>(data().m_path_len_constraint);
   }

Key_Constraints X509_Certificate::constraints() const
   {
   return data().m_key_constraints;
   }

const std::vector<OID>& X509_Certificate::extended_key_usage() const
   {
   return data().m_extended_key_usage;
   }

const std::vector<OID>& X509_Certificate::certificate_policy_oids() const
   {
   return data().m_cert_policies;
   }

const NameConstraints& X509_Certificate::name_constraints() const
   {
   return data().m_name_constraints;
   }

const Extensions& X509_Certificate::v3_extensions() const
   {
   return data().m_v3_extensions;
   }

bool X509_Certificate::allowed_usage(Key_Constraints usage) const
   {
   if(constraints() == NO_CONSTRAINTS)
      return true;
   return ((constraints() & usage) == usage);
   }

bool X509_Certificate::allowed_extended_usage(const std::string& usage) const
   {
   return allowed_extended_usage(OID::from_string(usage));
   }

bool X509_Certificate::allowed_extended_usage(const OID& usage) const
   {
   const std::vector<OID>& ex = extended_key_usage();
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

      case Usage_Type::ENCRYPTION:
         return (allowed_usage(KEY_ENCIPHERMENT) || allowed_usage(DATA_ENCIPHERMENT));
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
   return has_ex_constraint(OID::from_string(ex_constraint));
   }

bool X509_Certificate::has_ex_constraint(const OID& usage) const
   {
   const std::vector<OID>& ex = extended_key_usage();
   return (std::find(ex.begin(), ex.end(), usage) != ex.end());
   }

/*
* Return if a certificate extension is marked critical
*/
bool X509_Certificate::is_critical(const std::string& ex_name) const
   {
   return v3_extensions().critical_extension_set(OID::from_string(ex_name));
   }

std::string X509_Certificate::ocsp_responder() const
   {
   return data().m_ocsp_responder;
   }

std::vector<std::string> X509_Certificate::ca_issuers() const
   {
   return data().m_ca_issuers;
   }

std::string X509_Certificate::crl_distribution_point() const
   {
   // just returns the first (arbitrarily)
   if(data().m_crl_distribution_points.size() > 0)
      return data().m_crl_distribution_points[0];
   return "";
   }

const AlternativeName& X509_Certificate::subject_alt_name() const
   {
   return data().m_subject_alt_name;
   }

const AlternativeName& X509_Certificate::issuer_alt_name() const
   {
   return data().m_issuer_alt_name;
   }

/*
* Return information about the subject
*/
std::vector<std::string>
X509_Certificate::subject_info(const std::string& req) const
   {
   if(req == "Email")
      return this->subject_info("RFC822");

   if(subject_dn().has_field(req))
      return subject_dn().get_attribute(req);

   if(subject_alt_name().has_field(req))
      return subject_alt_name().get_attribute(req);

   // These will be removed later:
   if(req == "X509.Certificate.v2.key_id")
      return {hex_encode(this->v2_subject_key_id())};
   if(req == "X509v3.SubjectKeyIdentifier")
      return {hex_encode(this->subject_key_id())};
   if(req == "X509.Certificate.dn_bits")
      return {hex_encode(this->raw_subject_dn())};
   if(req == "X509.Certificate.start")
      return {not_before().to_string()};
   if(req == "X509.Certificate.end")
      return {not_after().to_string()};

   if(req == "X509.Certificate.version")
      return {std::to_string(x509_version())};
   if(req == "X509.Certificate.serial")
      return {hex_encode(serial_number())};

   return data().m_subject_ds.get(req);
   }

/*
* Return information about the issuer
*/
std::vector<std::string>
X509_Certificate::issuer_info(const std::string& req) const
   {
   if(issuer_dn().has_field(req))
      return issuer_dn().get_attribute(req);

   if(issuer_alt_name().has_field(req))
      return issuer_alt_name().get_attribute(req);

   // These will be removed later:
   if(req == "X509.Certificate.v2.key_id")
      return {hex_encode(this->v2_issuer_key_id())};
   if(req == "X509v3.AuthorityKeyIdentifier")
      return {hex_encode(this->authority_key_id())};
   if(req == "X509.Certificate.dn_bits")
      return {hex_encode(this->raw_issuer_dn())};

   return data().m_issuer_ds.get(req);
   }

/*
* Return the public key in this certificate
*/
std::unique_ptr<Public_Key> X509_Certificate::load_subject_public_key() const
   {
   try
      {
      return std::unique_ptr<Public_Key>(X509::load_key(subject_public_key_info()));
      }
   catch(std::exception& e)
      {
      throw Decoding_Error("X509_Certificate::load_subject_public_key", e);
      }
   }

Public_Key* X509_Certificate::subject_public_key() const
   {
   return load_subject_public_key().release();
   }

std::vector<uint8_t> X509_Certificate::raw_issuer_dn_sha256() const
   {
   if(data().m_issuer_dn_bits_sha256.empty())
      throw Encoding_Error("X509_Certificate::raw_issuer_dn_sha256 called but SHA-256 disabled in build");
   return data().m_issuer_dn_bits_sha256;
   }

std::vector<uint8_t> X509_Certificate::raw_subject_dn_sha256() const
   {
   if(data().m_subject_dn_bits_sha256.empty())
      throw Encoding_Error("X509_Certificate::raw_subject_dn_sha256 called but SHA-256 disabled in build");
   return data().m_subject_dn_bits_sha256;
   }

namespace {

/*
* Lookup each OID in the vector
*/
std::vector<std::string> lookup_oids(const std::vector<OID>& oids)
   {
   std::vector<std::string> out;

   for(const OID& oid : oids)
      {
      out.push_back(oid.to_formatted_string());
      }
   return out;
   }

}

/*
* Return the list of extended key usage OIDs
*/
std::vector<std::string> X509_Certificate::ex_constraints() const
   {
   return lookup_oids(extended_key_usage());
   }

/*
* Return the list of certificate policies
*/
std::vector<std::string> X509_Certificate::policies() const
   {
   return lookup_oids(certificate_policy_oids());
   }

std::string X509_Certificate::fingerprint(const std::string& hash_name) const
   {
   /*
   * The SHA-1 and SHA-256 fingerprints are precomputed since these
   * are the most commonly used. Especially, SHA-256 fingerprints are
   * used for cycle detection during path construction.
   *
   * If SHA-1 or SHA-256 was missing at parsing time the vectors are
   * left empty in which case we fall back to create_hex_fingerprint
   * which will throw if the hash is unavailable.
   */
   if(hash_name == "SHA-256" && data().m_fingerprint_sha256.size() > 0)
      return data().m_fingerprint_sha256;
   else if(hash_name == "SHA-1" && data().m_fingerprint_sha1.size() > 0)
      return data().m_fingerprint_sha1;
   else
      return create_hex_fingerprint(this->BER_encode(), hash_name);
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
   return (this->signature() == other.signature() &&
           this->signature_algorithm() == other.signature_algorithm() &&
           this->signed_body() == other.signed_body());
   }

bool X509_Certificate::operator<(const X509_Certificate& other) const
   {
   /* If signature values are not equal, sort by lexicographic ordering of that */
   if(this->signature() != other.signature())
      {
      return (this->signature() < other.signature());
      }

   // Then compare the signed contents
   return this->signed_body() < other.signed_body();
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
   std::ostringstream out;

   out << "Version: " << this->x509_version() << "\n";
   out << "Subject: " << subject_dn() << "\n";
   out << "Issuer: " << issuer_dn() << "\n";
   out << "Issued: " << this->not_before().readable_string() << "\n";
   out << "Expires: " << this->not_after().readable_string() << "\n";

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

   const std::vector<OID>& policies = this->certificate_policy_oids();
   if(!policies.empty())
      {
      out << "Policies: " << "\n";
      for(auto oid : policies)
         out << "   " << oid.to_string() << "\n";
      }

   const std::vector<OID>& ex_constraints = this->extended_key_usage();
   if(!ex_constraints.empty())
      {
      out << "Extended Constraints:\n";
      for(auto&& oid : ex_constraints)
         {
         out << "   " << oid.to_formatted_string() << "\n";
         }
      }

   const NameConstraints& name_constraints = this->name_constraints();

   if(!name_constraints.permitted().empty() || !name_constraints.excluded().empty())
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

   const std::vector<std::string> ca_issuers = this->ca_issuers();
   if(!ca_issuers.empty())
      {
      out << "CA Issuers:\n";
      for(size_t i = 0; i != ca_issuers.size(); i++)
         out << "   URI: " << ca_issuers[i] << "\n";
      }

   if(!crl_distribution_point().empty())
      out << "CRL " << crl_distribution_point() << "\n";

   out << "Signature algorithm: " << this->signature_algorithm().get_oid().to_formatted_string() << "\n";

   out << "Serial number: " << hex_encode(this->serial_number()) << "\n";

   if(this->authority_key_id().size())
     out << "Authority keyid: " << hex_encode(this->authority_key_id()) << "\n";

   if(this->subject_key_id().size())
     out << "Subject keyid: " << hex_encode(this->subject_key_id()) << "\n";

   try
      {
      std::unique_ptr<Public_Key> pubkey(this->subject_public_key());
      out << "Public Key [" << pubkey->algo_name() << "-" << pubkey->key_length() << "]\n\n";
      out << X509::PEM_encode(*pubkey);
      }
   catch(Decoding_Error&)
      {
      const AlgorithmIdentifier& alg_id = this->subject_public_key_algo();
      out << "Failed to decode key with oid " << alg_id.get_oid().to_string() << "\n";
      }

   return out.str();
   }

}
