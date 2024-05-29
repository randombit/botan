/*
* X.509 Certificates
* (C) 1999-2010,2015,2017 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509cert.h>

#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/pk_keys.h>
#include <botan/x509_ext.h>
#include <botan/x509_key.h>
#include <botan/internal/parsing.h>
#include <algorithm>
#include <sstream>

namespace Botan {

struct X509_Certificate_Data {
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

      size_t m_version = 0;
      size_t m_path_len_constraint = 0;
      Key_Constraints m_key_constraints;
      bool m_self_signed = false;
      bool m_is_ca_certificate = false;
      bool m_serial_negative = false;
      bool m_subject_alt_name_exists = false;
};

std::string X509_Certificate::PEM_label() const {
   return "CERTIFICATE";
}

std::vector<std::string> X509_Certificate::alternate_PEM_labels() const {
   return {"X509 CERTIFICATE"};
}

X509_Certificate::X509_Certificate(DataSource& src) {
   load_data(src);
}

X509_Certificate::X509_Certificate(const std::vector<uint8_t>& vec) {
   DataSource_Memory src(vec.data(), vec.size());
   load_data(src);
}

X509_Certificate::X509_Certificate(const uint8_t data[], size_t len) {
   DataSource_Memory src(data, len);
   load_data(src);
}

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
X509_Certificate::X509_Certificate(std::string_view fsname) {
   DataSource_Stream src(fsname, true);
   load_data(src);
}
#endif

namespace {

std::unique_ptr<X509_Certificate_Data> parse_x509_cert_body(const X509_Object& obj) {
   auto data = std::make_unique<X509_Certificate_Data>();

   BigInt serial_bn;
   BER_Object public_key;
   BER_Object v3_exts_data;

   BER_Decoder(obj.signed_body())
      .decode_optional(data->m_version, ASN1_Type(0), ASN1_Class::Constructed | ASN1_Class::ContextSpecific)
      .decode(serial_bn)
      .decode(data->m_sig_algo_inner)
      .decode(data->m_issuer_dn)
      .start_sequence()
      .decode(data->m_not_before)
      .decode(data->m_not_after)
      .end_cons()
      .decode(data->m_subject_dn)
      .get_next(public_key)
      .decode_optional_string(data->m_v2_issuer_key_id, ASN1_Type::BitString, 1)
      .decode_optional_string(data->m_v2_subject_key_id, ASN1_Type::BitString, 2)
      .get_next(v3_exts_data)
      .verify_end("TBSCertificate has extra data after extensions block");

   if(data->m_version > 2) {
      throw Decoding_Error("Unknown X.509 cert version " + std::to_string(data->m_version));
   }
   if(obj.signature_algorithm() != data->m_sig_algo_inner) {
      throw Decoding_Error("X.509 Certificate had differing algorithm identifers in inner and outer ID fields");
   }

   public_key.assert_is_a(ASN1_Type::Sequence, ASN1_Class::Constructed, "X.509 certificate public key");

   // for general sanity convert wire version (0 based) to standards version (v1 .. v3)
   data->m_version += 1;

   data->m_serial = serial_bn.serialize();
   // crude method to save the serial's sign; will get lost during decoding, otherwise
   data->m_serial_negative = serial_bn.is_negative();
   data->m_subject_dn_bits = ASN1::put_in_sequence(data->m_subject_dn.get_bits());
   data->m_issuer_dn_bits = ASN1::put_in_sequence(data->m_issuer_dn.get_bits());

   data->m_subject_public_key_bits.assign(public_key.bits(), public_key.bits() + public_key.length());

   data->m_subject_public_key_bits_seq = ASN1::put_in_sequence(data->m_subject_public_key_bits);

   BER_Decoder(data->m_subject_public_key_bits)
      .decode(data->m_subject_public_key_algid)
      .decode(data->m_subject_public_key_bitstring, ASN1_Type::BitString);

   if(v3_exts_data.is_a(3, ASN1_Class::Constructed | ASN1_Class::ContextSpecific)) {
      // Path validation will reject a v1/v2 cert with v3 extensions
      BER_Decoder(v3_exts_data).decode(data->m_v3_extensions).verify_end();
   } else if(v3_exts_data.is_set()) {
      throw BER_Bad_Tag("Unknown tag in X.509 cert", v3_exts_data.tagging());
   }

   // Now cache some fields from the extensions
   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Key_Usage>()) {
      data->m_key_constraints = ext->get_constraints();
      /*
      RFC 5280: When the keyUsage extension appears in a certificate,
      at least one of the bits MUST be set to 1.
      */
      if(data->m_key_constraints.empty()) {
         throw Decoding_Error("Certificate has invalid encoding for KeyUsage");
      }
   }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Subject_Key_ID>()) {
      data->m_subject_key_id = ext->get_key_id();
   }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Authority_Key_ID>()) {
      data->m_authority_key_id = ext->get_key_id();
   }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Name_Constraints>()) {
      data->m_name_constraints = ext->get_name_constraints();
   }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Extended_Key_Usage>()) {
      data->m_extended_key_usage = ext->object_identifiers();
   }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Basic_Constraints>()) {
      if(ext->get_is_ca() == true) {
         /*
         * RFC 5280 section 4.2.1.3 requires that CAs include KeyUsage in all
         * intermediate CA certificates they issue. Currently we accept it being
         * missing, as do most other implementations. But it may be worth
         * removing this entirely, or alternately adding a warning level
         * validation failure for it.
         */
         const bool allowed_by_ku =
            data->m_key_constraints.includes(Key_Constraints::KeyCertSign) || data->m_key_constraints.empty();

         /*
         * If the extended key usages are set then we must restrict the
         * usage in accordance with it as well.
         *
         * RFC 5280 does not define any extended key usages compatible
         * with certificate signing, but some CAs seem to use serverAuth
         * or clientAuth here.
         */
         const bool allowed_by_ext_ku = [](const std::vector<OID>& ext_ku) -> bool {
            if(ext_ku.empty()) {
               return true;
            }

            const auto server_auth = OID::from_name("PKIX.ServerAuth");
            const auto client_auth = OID::from_name("PKIX.ClientAuth");
            const auto ocsp_sign = OID::from_name("PKIX.OCSPSigning");

            for(const auto& oid : ext_ku) {
               if(oid == server_auth || oid == client_auth || oid == ocsp_sign) {
                  return true;
               }
            }

            return false;
         }(data->m_extended_key_usage);

         if(allowed_by_ku && allowed_by_ext_ku) {
            data->m_is_ca_certificate = true;
            data->m_path_len_constraint = ext->get_path_limit();
         }
      }
   }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Issuer_Alternative_Name>()) {
      data->m_issuer_alt_name = ext->get_alt_name();
   }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Subject_Alternative_Name>()) {
      data->m_subject_alt_name = ext->get_alt_name();
   }

   // This will be set even if SAN parsing failed entirely eg due to a decoding error
   // or if the SAN is empty. This is used to guard against using the CN for domain
   // name checking.
   const auto san_oid = OID::from_string("X509v3.SubjectAlternativeName");
   data->m_subject_alt_name_exists = data->m_v3_extensions.extension_set(san_oid);

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Certificate_Policies>()) {
      data->m_cert_policies = ext->get_policy_oids();
   }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::Authority_Information_Access>()) {
      data->m_ocsp_responder = ext->ocsp_responder();
      data->m_ca_issuers = ext->ca_issuers();
   }

   if(auto ext = data->m_v3_extensions.get_extension_object_as<Cert_Extension::CRL_Distribution_Points>()) {
      data->m_crl_distribution_points = ext->crl_distribution_urls();
   }

   // Check for self-signed vs self-issued certificates
   if(data->m_subject_dn == data->m_issuer_dn) {
      if(data->m_subject_key_id.empty() == false && data->m_authority_key_id.empty() == false) {
         data->m_self_signed = (data->m_subject_key_id == data->m_authority_key_id);
      } else {
         /*
         If a parse error or unknown algorithm is encountered, default
         to assuming it is self signed. We have no way of being certain but
         that is usually the default case (self-issued is rare in practice).
         */
         data->m_self_signed = true;

         try {
            auto pub_key = X509::load_key(data->m_subject_public_key_bits_seq);

            const auto sig_status = obj.verify_signature(*pub_key);

            if(sig_status.first == Certificate_Status_Code::OK ||
               sig_status.first == Certificate_Status_Code::SIGNATURE_ALGO_UNKNOWN) {
               data->m_self_signed = true;
            } else {
               data->m_self_signed = false;
            }
         } catch(...) {
            // ignore errors here to allow parsing to continue
         }
      }
   }

   const std::vector<uint8_t> full_encoding = obj.BER_encode();

   if(auto sha1 = HashFunction::create("SHA-1")) {
      sha1->update(data->m_subject_public_key_bitstring);
      data->m_subject_public_key_bitstring_sha1 = sha1->final_stdvec();
      // otherwise left as empty, and we will throw if subject_public_key_bitstring_sha1 is called

      data->m_fingerprint_sha1 = create_hex_fingerprint(full_encoding, "SHA-1");
   }

   if(auto sha256 = HashFunction::create("SHA-256")) {
      sha256->update(data->m_issuer_dn_bits);
      data->m_issuer_dn_bits_sha256 = sha256->final_stdvec();

      sha256->update(data->m_subject_dn_bits);
      data->m_subject_dn_bits_sha256 = sha256->final_stdvec();

      data->m_fingerprint_sha256 = create_hex_fingerprint(full_encoding, "SHA-256");
   }

   return data;
}

}  // namespace

/*
* Decode the TBSCertificate data
*/
void X509_Certificate::force_decode() {
   m_data.reset();
   m_data = parse_x509_cert_body(*this);
}

const X509_Certificate_Data& X509_Certificate::data() const {
   if(m_data == nullptr) {
      throw Invalid_State("X509_Certificate uninitialized");
   }
   return *m_data;
}

uint32_t X509_Certificate::x509_version() const {
   return static_cast<uint32_t>(data().m_version);
}

bool X509_Certificate::is_self_signed() const {
   return data().m_self_signed;
}

const X509_Time& X509_Certificate::not_before() const {
   return data().m_not_before;
}

const X509_Time& X509_Certificate::not_after() const {
   return data().m_not_after;
}

const AlgorithmIdentifier& X509_Certificate::subject_public_key_algo() const {
   return data().m_subject_public_key_algid;
}

const std::vector<uint8_t>& X509_Certificate::v2_issuer_key_id() const {
   return data().m_v2_issuer_key_id;
}

const std::vector<uint8_t>& X509_Certificate::v2_subject_key_id() const {
   return data().m_v2_subject_key_id;
}

const std::vector<uint8_t>& X509_Certificate::subject_public_key_bits() const {
   return data().m_subject_public_key_bits;
}

const std::vector<uint8_t>& X509_Certificate::subject_public_key_info() const {
   return data().m_subject_public_key_bits_seq;
}

const std::vector<uint8_t>& X509_Certificate::subject_public_key_bitstring() const {
   return data().m_subject_public_key_bitstring;
}

const std::vector<uint8_t>& X509_Certificate::subject_public_key_bitstring_sha1() const {
   if(data().m_subject_public_key_bitstring_sha1.empty()) {
      throw Encoding_Error("X509_Certificate::subject_public_key_bitstring_sha1 called but SHA-1 disabled in build");
   }

   return data().m_subject_public_key_bitstring_sha1;
}

const std::vector<uint8_t>& X509_Certificate::authority_key_id() const {
   return data().m_authority_key_id;
}

const std::vector<uint8_t>& X509_Certificate::subject_key_id() const {
   return data().m_subject_key_id;
}

const std::vector<uint8_t>& X509_Certificate::serial_number() const {
   return data().m_serial;
}

bool X509_Certificate::is_serial_negative() const {
   return data().m_serial_negative;
}

const X509_DN& X509_Certificate::issuer_dn() const {
   return data().m_issuer_dn;
}

const X509_DN& X509_Certificate::subject_dn() const {
   return data().m_subject_dn;
}

const std::vector<uint8_t>& X509_Certificate::raw_issuer_dn() const {
   return data().m_issuer_dn_bits;
}

const std::vector<uint8_t>& X509_Certificate::raw_subject_dn() const {
   return data().m_subject_dn_bits;
}

bool X509_Certificate::is_CA_cert() const {
   if(data().m_version < 3 && data().m_self_signed) {
      return true;
   }

   return data().m_is_ca_certificate;
}

uint32_t X509_Certificate::path_limit() const {
   if(data().m_version < 3 && data().m_self_signed) {
      return 32;  // in theory infinite, but this is more than enough
   }

   return static_cast<uint32_t>(data().m_path_len_constraint);
}

Key_Constraints X509_Certificate::constraints() const {
   return data().m_key_constraints;
}

const std::vector<OID>& X509_Certificate::extended_key_usage() const {
   return data().m_extended_key_usage;
}

const std::vector<OID>& X509_Certificate::certificate_policy_oids() const {
   return data().m_cert_policies;
}

const NameConstraints& X509_Certificate::name_constraints() const {
   return data().m_name_constraints;
}

const Extensions& X509_Certificate::v3_extensions() const {
   return data().m_v3_extensions;
}

bool X509_Certificate::has_constraints(Key_Constraints usage) const {
   // Unlike allowed_usage, returns false if constraints was not set
   return constraints().includes(usage);
}

bool X509_Certificate::allowed_usage(Key_Constraints usage) const {
   if(constraints().empty()) {
      return true;
   }
   return constraints().includes(usage);
}

bool X509_Certificate::allowed_extended_usage(std::string_view usage) const {
   return allowed_extended_usage(OID::from_string(usage));
}

bool X509_Certificate::allowed_extended_usage(const OID& usage) const {
   const std::vector<OID>& ex = extended_key_usage();
   if(ex.empty()) {
      return true;
   }

   if(std::find(ex.begin(), ex.end(), usage) != ex.end()) {
      return true;
   }

   return false;
}

bool X509_Certificate::allowed_usage(Usage_Type usage) const {
   // These follow suggestions in RFC 5280 4.2.1.12

   switch(usage) {
      case Usage_Type::UNSPECIFIED:
         return true;

      case Usage_Type::TLS_SERVER_AUTH:
         return (allowed_usage(Key_Constraints::KeyAgreement) || allowed_usage(Key_Constraints::KeyEncipherment) ||
                 allowed_usage(Key_Constraints::DigitalSignature)) &&
                allowed_extended_usage("PKIX.ServerAuth");

      case Usage_Type::TLS_CLIENT_AUTH:
         return (allowed_usage(Key_Constraints::DigitalSignature) || allowed_usage(Key_Constraints::KeyAgreement)) &&
                allowed_extended_usage("PKIX.ClientAuth");

      case Usage_Type::OCSP_RESPONDER:
         return (allowed_usage(Key_Constraints::DigitalSignature) || allowed_usage(Key_Constraints::NonRepudiation)) &&
                has_ex_constraint("PKIX.OCSPSigning");

      case Usage_Type::CERTIFICATE_AUTHORITY:
         return is_CA_cert();

      case Usage_Type::ENCRYPTION:
         return (allowed_usage(Key_Constraints::KeyEncipherment) || allowed_usage(Key_Constraints::DataEncipherment));
   }

   return false;
}

bool X509_Certificate::has_ex_constraint(std::string_view ex_constraint) const {
   return has_ex_constraint(OID::from_string(ex_constraint));
}

bool X509_Certificate::has_ex_constraint(const OID& usage) const {
   const std::vector<OID>& ex = extended_key_usage();
   return (std::find(ex.begin(), ex.end(), usage) != ex.end());
}

/*
* Return if a certificate extension is marked critical
*/
bool X509_Certificate::is_critical(std::string_view ex_name) const {
   return v3_extensions().critical_extension_set(OID::from_string(ex_name));
}

std::string X509_Certificate::ocsp_responder() const {
   return data().m_ocsp_responder;
}

std::vector<std::string> X509_Certificate::ca_issuers() const {
   return data().m_ca_issuers;
}

std::vector<std::string> X509_Certificate::crl_distribution_points() const {
   return data().m_crl_distribution_points;
}

std::string X509_Certificate::crl_distribution_point() const {
   // just returns the first (arbitrarily)
   if(!data().m_crl_distribution_points.empty()) {
      return data().m_crl_distribution_points[0];
   }
   return "";
}

const AlternativeName& X509_Certificate::subject_alt_name() const {
   return data().m_subject_alt_name;
}

const AlternativeName& X509_Certificate::issuer_alt_name() const {
   return data().m_issuer_alt_name;
}

namespace {

std::vector<std::string> get_cert_user_info(std::string_view req, const X509_DN& dn, const AlternativeName& alt_name) {
   auto set_to_vector = [](const std::set<std::string>& s) -> std::vector<std::string> { return {s.begin(), s.end()}; };

   if(dn.has_field(req)) {
      return dn.get_attribute(req);
   } else if(req == "RFC822" || req == "Email") {
      return set_to_vector(alt_name.email());
   } else if(req == "DNS") {
      return set_to_vector(alt_name.dns());
   } else if(req == "URI") {
      return set_to_vector(alt_name.uris());
   } else if(req == "IP") {
      std::vector<std::string> ip_str;
      for(uint32_t ipv4 : alt_name.ipv4_address()) {
         ip_str.push_back(ipv4_to_string(ipv4));
      }
      return ip_str;
   } else {
      return {};
   }
}

}  // namespace

/*
* Return information about the subject
*/
std::vector<std::string> X509_Certificate::subject_info(std::string_view req) const {
   return get_cert_user_info(req, subject_dn(), subject_alt_name());
}

/*
* Return information about the issuer
*/
std::vector<std::string> X509_Certificate::issuer_info(std::string_view req) const {
   return get_cert_user_info(req, issuer_dn(), issuer_alt_name());
}

/*
* Return the public key in this certificate
*/
std::unique_ptr<Public_Key> X509_Certificate::subject_public_key() const {
   try {
      return std::unique_ptr<Public_Key>(X509::load_key(subject_public_key_info()));
   } catch(std::exception& e) {
      throw Decoding_Error("X509_Certificate::subject_public_key", e);
   }
}

std::unique_ptr<Public_Key> X509_Certificate::load_subject_public_key() const {
   return this->subject_public_key();
}

std::vector<uint8_t> X509_Certificate::raw_issuer_dn_sha256() const {
   if(data().m_issuer_dn_bits_sha256.empty()) {
      throw Encoding_Error("X509_Certificate::raw_issuer_dn_sha256 called but SHA-256 disabled in build");
   }
   return data().m_issuer_dn_bits_sha256;
}

std::vector<uint8_t> X509_Certificate::raw_subject_dn_sha256() const {
   if(data().m_subject_dn_bits_sha256.empty()) {
      throw Encoding_Error("X509_Certificate::raw_subject_dn_sha256 called but SHA-256 disabled in build");
   }
   return data().m_subject_dn_bits_sha256;
}

std::string X509_Certificate::fingerprint(std::string_view hash_name) const {
   /*
   * The SHA-1 and SHA-256 fingerprints are precomputed since these
   * are the most commonly used. Especially, SHA-256 fingerprints are
   * used for cycle detection during path construction.
   *
   * If SHA-1 or SHA-256 was missing at parsing time the vectors are
   * left empty in which case we fall back to create_hex_fingerprint
   * which will throw if the hash is unavailable.
   */
   if(hash_name == "SHA-256" && !data().m_fingerprint_sha256.empty()) {
      return data().m_fingerprint_sha256;
   } else if(hash_name == "SHA-1" && !data().m_fingerprint_sha1.empty()) {
      return data().m_fingerprint_sha1;
   } else {
      return create_hex_fingerprint(this->BER_encode(), hash_name);
   }
}

bool X509_Certificate::matches_dns_name(std::string_view name) const {
   if(name.empty()) {
      return false;
   }

   if(auto req_ipv4 = string_to_ipv4(name)) {
      const auto& ipv4_names = subject_alt_name().ipv4_address();
      return ipv4_names.contains(req_ipv4.value());
   } else {
      auto issued_names = subject_info("DNS");

      // Fall back to CN only if no SAN is included
      if(!data().m_subject_alt_name_exists) {
         issued_names = subject_info("Name");
      }

      for(const auto& issued_name : issued_names) {
         if(host_wildcard_match(issued_name, name)) {
            return true;
         }
      }
   }

   return false;
}

/*
* Compare two certificates for equality
*/
bool X509_Certificate::operator==(const X509_Certificate& other) const {
   return (this->signature() == other.signature() && this->signature_algorithm() == other.signature_algorithm() &&
           this->signed_body() == other.signed_body());
}

bool X509_Certificate::operator<(const X509_Certificate& other) const {
   /* If signature values are not equal, sort by lexicographic ordering of that */
   if(this->signature() != other.signature()) {
      return (this->signature() < other.signature());
   }

   // Then compare the signed contents
   return this->signed_body() < other.signed_body();
}

/*
* X.509 Certificate Comparison
*/
bool operator!=(const X509_Certificate& cert1, const X509_Certificate& cert2) {
   return !(cert1 == cert2);
}

std::string X509_Certificate::to_string() const {
   std::ostringstream out;

   out << "Version: " << this->x509_version() << "\n";
   out << "Subject: " << subject_dn() << "\n";
   out << "Issuer: " << issuer_dn() << "\n";
   out << "Issued: " << this->not_before().readable_string() << "\n";
   out << "Expires: " << this->not_after().readable_string() << "\n";

   out << "Constraints:\n";
   Key_Constraints constraints = this->constraints();
   if(constraints.empty()) {
      out << " None\n";
   } else {
      if(constraints.includes(Key_Constraints::DigitalSignature)) {
         out << "   Digital Signature\n";
      }
      if(constraints.includes(Key_Constraints::NonRepudiation)) {
         out << "   Non-Repudiation\n";
      }
      if(constraints.includes(Key_Constraints::KeyEncipherment)) {
         out << "   Key Encipherment\n";
      }
      if(constraints.includes(Key_Constraints::DataEncipherment)) {
         out << "   Data Encipherment\n";
      }
      if(constraints.includes(Key_Constraints::KeyAgreement)) {
         out << "   Key Agreement\n";
      }
      if(constraints.includes(Key_Constraints::KeyCertSign)) {
         out << "   Cert Sign\n";
      }
      if(constraints.includes(Key_Constraints::CrlSign)) {
         out << "   CRL Sign\n";
      }
      if(constraints.includes(Key_Constraints::EncipherOnly)) {
         out << "   Encipher Only\n";
      }
      if(constraints.includes(Key_Constraints::DecipherOnly)) {
         out << "   Decipher Only\n";
      }
   }

   const std::vector<OID>& policies = this->certificate_policy_oids();
   if(!policies.empty()) {
      out << "Policies: "
          << "\n";
      for(const auto& oid : policies) {
         out << "   " << oid.to_string() << "\n";
      }
   }

   const std::vector<OID>& ex_constraints = this->extended_key_usage();
   if(!ex_constraints.empty()) {
      out << "Extended Constraints:\n";
      for(auto&& oid : ex_constraints) {
         out << "   " << oid.to_formatted_string() << "\n";
      }
   }

   const NameConstraints& name_constraints = this->name_constraints();

   if(!name_constraints.permitted().empty() || !name_constraints.excluded().empty()) {
      out << "Name Constraints:\n";

      if(!name_constraints.permitted().empty()) {
         out << "   Permit";
         for(const auto& st : name_constraints.permitted()) {
            out << " " << st.base();
         }
         out << "\n";
      }

      if(!name_constraints.excluded().empty()) {
         out << "   Exclude";
         for(const auto& st : name_constraints.excluded()) {
            out << " " << st.base();
         }
         out << "\n";
      }
   }

   if(!ocsp_responder().empty()) {
      out << "OCSP responder " << ocsp_responder() << "\n";
   }

   const std::vector<std::string> ca_issuers = this->ca_issuers();
   if(!ca_issuers.empty()) {
      out << "CA Issuers:\n";
      for(const auto& ca_issuer : ca_issuers) {
         out << "   URI: " << ca_issuer << "\n";
      }
   }

   for(const auto& cdp : crl_distribution_points()) {
      out << "CRL " << cdp << "\n";
   }

   out << "Signature algorithm: " << this->signature_algorithm().oid().to_formatted_string() << "\n";

   out << "Serial number: " << hex_encode(this->serial_number()) << "\n";

   if(!this->authority_key_id().empty()) {
      out << "Authority keyid: " << hex_encode(this->authority_key_id()) << "\n";
   }

   if(!this->subject_key_id().empty()) {
      out << "Subject keyid: " << hex_encode(this->subject_key_id()) << "\n";
   }

   try {
      auto pubkey = this->subject_public_key();
      out << "Public Key [" << pubkey->algo_name() << "-" << pubkey->key_length() << "]\n\n";
      out << X509::PEM_encode(*pubkey);
   } catch(Decoding_Error&) {
      const AlgorithmIdentifier& alg_id = this->subject_public_key_algo();
      out << "Failed to decode key with oid " << alg_id.oid().to_string() << "\n";
   }

   return out.str();
}

}  // namespace Botan
