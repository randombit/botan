/*
* (C) 2009,2019 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/calendar.h>
   #include <botan/pkcs10.h>
   #include <botan/pkcs8.h>
   #include <botan/x509self.h>
   #include <botan/x509path.h>
   #include <botan/x509_ca.h>
   #include <botan/x509_ext.h>
   #include <botan/pk_algs.h>
   #include <botan/ber_dec.h>
   #include <botan/der_enc.h>
   #include <botan/oids.h>
   #include <botan/internal/padding.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES)

Botan::X509_Time from_date(const int y, const int m, const int d)
   {
   const size_t this_year = Botan::calendar_value(std::chrono::system_clock::now()).get_year();

   Botan::calendar_point t(static_cast<uint32_t>(this_year + y), m, d, 0, 0, 0);
   return Botan::X509_Time(t.to_std_timepoint());
   }

/* Return some option sets */
Botan::X509_Cert_Options ca_opts(const std::string& sig_padding = "")
   {
   Botan::X509_Cert_Options opts("Test CA/US/Botan Project/Testing");

   opts.uri = "https://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";
   opts.set_padding_scheme(sig_padding);

   opts.CA_key(1);

   return opts;
   }

Botan::X509_Cert_Options req_opts1(const std::string& algo, const std::string& sig_padding = "")
   {
   Botan::X509_Cert_Options opts("Test User 1/US/Botan Project/Testing");

   opts.uri = "https://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";
   opts.set_padding_scheme(sig_padding);

   opts.not_before("160101200000Z");
   opts.not_after("300101200000Z");

   opts.challenge = "zoom";

   if(algo == "RSA")
      {
      opts.constraints = Botan::Key_Constraints(Botan::KEY_ENCIPHERMENT);
      }
   else if(algo == "DSA" || algo == "ECDSA" || algo == "ECGDSA" || algo == "ECKCDSA")
      {
      opts.constraints = Botan::Key_Constraints(Botan::DIGITAL_SIGNATURE);
      }

   return opts;
   }

Botan::X509_Cert_Options req_opts2(const std::string& sig_padding = "")
   {
   Botan::X509_Cert_Options opts("Test User 2/US/Botan Project/Testing");

   opts.uri = "https://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";
   opts.set_padding_scheme(sig_padding);

   opts.add_ex_constraint("PKIX.EmailProtection");

   return opts;
   }

Botan::X509_Cert_Options req_opts3(const std::string& sig_padding = "")
   {
   Botan::X509_Cert_Options opts("Test User 2/US/Botan Project/Testing");

   opts.uri = "https://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";
   opts.set_padding_scheme(sig_padding);

   opts.more_org_units.push_back("IT");
   opts.more_org_units.push_back("Security");
   opts.more_dns.push_back("www.botan.randombit.net");

   return opts;
   }

std::unique_ptr<Botan::Private_Key> make_a_private_key(const std::string& algo)
   {
   const std::string params = [&]
      {
      // Here we override defaults as needed
      if(algo == "RSA")
         {
         return "1024";
         }
      if(algo == "GOST-34.10")
         {
         return "gost_256A";
         }
      if(algo == "ECKCDSA" || algo == "ECGDSA")
         {
         return "brainpool256r1";
         }
      return ""; // default "" means choose acceptable algo-specific params
      }();

   return Botan::create_private_key(algo, Test::rng(), params);
   }

Test::Result test_cert_status_strings()
   {
   Test::Result result("Certificate_Status_Code to_string");

   std::set<std::string> seen;

   result.test_eq("Same string",
                  Botan::to_string(Botan::Certificate_Status_Code::OK),
                  Botan::to_string(Botan::Certificate_Status_Code::VERIFIED));

   const Botan::Certificate_Status_Code codes[]
      {
      Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD,
      Botan::Certificate_Status_Code::OCSP_SIGNATURE_OK,
      Botan::Certificate_Status_Code::VALID_CRL_CHECKED,
      Botan::Certificate_Status_Code::OCSP_NO_HTTP,

      Botan::Certificate_Status_Code::CERT_SERIAL_NEGATIVE,
      Botan::Certificate_Status_Code::DN_TOO_LONG,

      Botan::Certificate_Status_Code::SIGNATURE_METHOD_TOO_WEAK,
      Botan::Certificate_Status_Code::NO_MATCHING_CRLDP,
      Botan::Certificate_Status_Code::UNTRUSTED_HASH,
      Botan::Certificate_Status_Code::NO_REVOCATION_DATA,
      Botan::Certificate_Status_Code::CERT_NOT_YET_VALID,
      Botan::Certificate_Status_Code::CERT_HAS_EXPIRED,
      Botan::Certificate_Status_Code::OCSP_NOT_YET_VALID,
      Botan::Certificate_Status_Code::OCSP_HAS_EXPIRED,
      Botan::Certificate_Status_Code::CRL_NOT_YET_VALID,
      Botan::Certificate_Status_Code::CRL_HAS_EXPIRED,
      Botan::Certificate_Status_Code::CERT_ISSUER_NOT_FOUND,
      Botan::Certificate_Status_Code::CANNOT_ESTABLISH_TRUST,
      Botan::Certificate_Status_Code::CERT_CHAIN_LOOP,
      Botan::Certificate_Status_Code::CHAIN_LACKS_TRUST_ROOT,
      Botan::Certificate_Status_Code::CHAIN_NAME_MISMATCH,
      Botan::Certificate_Status_Code::POLICY_ERROR,
      Botan::Certificate_Status_Code::DUPLICATE_CERT_POLICY,
      Botan::Certificate_Status_Code::INVALID_USAGE,
      Botan::Certificate_Status_Code::CERT_CHAIN_TOO_LONG,
      Botan::Certificate_Status_Code::CA_CERT_NOT_FOR_CERT_ISSUER,
      Botan::Certificate_Status_Code::NAME_CONSTRAINT_ERROR,
      Botan::Certificate_Status_Code::CA_CERT_NOT_FOR_CRL_ISSUER,
      Botan::Certificate_Status_Code::OCSP_CERT_NOT_LISTED,
      Botan::Certificate_Status_Code::OCSP_BAD_STATUS,
      Botan::Certificate_Status_Code::CERT_NAME_NOMATCH,
      Botan::Certificate_Status_Code::UNKNOWN_CRITICAL_EXTENSION,
      Botan::Certificate_Status_Code::DUPLICATE_CERT_EXTENSION,
      Botan::Certificate_Status_Code::EXT_IN_V1_V2_CERT,
      Botan::Certificate_Status_Code::OCSP_SIGNATURE_ERROR,
      Botan::Certificate_Status_Code::OCSP_ISSUER_NOT_FOUND,
      Botan::Certificate_Status_Code::OCSP_RESPONSE_MISSING_KEYUSAGE,
      Botan::Certificate_Status_Code::OCSP_RESPONSE_INVALID,
      Botan::Certificate_Status_Code::CERT_IS_REVOKED,
      Botan::Certificate_Status_Code::CRL_BAD_SIGNATURE,
      Botan::Certificate_Status_Code::SIGNATURE_ERROR,
      Botan::Certificate_Status_Code::CERT_PUBKEY_INVALID,
      Botan::Certificate_Status_Code::SIGNATURE_ALGO_UNKNOWN,
      Botan::Certificate_Status_Code::SIGNATURE_ALGO_BAD_PARAMS,
      };

   for(const auto code : codes)
      {
      const std::string s = Botan::to_string(code);
      result.confirm("String is long enough to be informative", s.size() > 12);
      result.test_eq("No duplicates", seen.count(s), 0);
      seen.insert(s);
      }

   return result;

   }

Test::Result test_x509_extension()
   {
   Test::Result result("X509 Extensions API");

   Botan::Extensions extn;

   const auto oid_bc = Botan::OID::from_string("X509v3.BasicConstraints");
   const auto oid_skid = Botan::OID::from_string("X509v3.SubjectKeyIdentifier");

   extn.add(new Botan::Cert_Extension::Basic_Constraints(true), true);

   result.confirm("Basic constraints is set", extn.extension_set(oid_bc));
   result.confirm("Basic constraints is critical", extn.critical_extension_set(oid_bc));
   result.confirm("SKID is not set", !extn.extension_set(oid_skid));
   result.confirm("SKID is not critical", !extn.critical_extension_set(oid_skid));

   result.test_eq("Extension::get_extension_bits",
                  extn.get_extension_bits(oid_bc), "30060101FF020100");

   result.test_throws("Extension::get_extension_bits throws if not set",
                      [&]() { extn.get_extension_bits(oid_skid); });

   result.test_throws("Extension::add throws on second add",
                      [&]() { extn.add(new Botan::Cert_Extension::Basic_Constraints(false), false); });

   result.test_eq("Extension::get_extension_bits",
                  extn.get_extension_bits(oid_bc), "30060101FF020100");

   result.confirm("Returns false since extension already existed",
                  !extn.add_new(new Botan::Cert_Extension::Basic_Constraints(false), false));

   result.confirm("Basic constraints is still critical", extn.critical_extension_set(oid_bc));

   extn.replace(new Botan::Cert_Extension::Basic_Constraints(false), false);
   result.confirm("Replaced basic constraints is not critical", !extn.critical_extension_set(oid_bc));
   result.test_eq("Extension::get_extension_bits", extn.get_extension_bits(oid_bc), "3000");

   result.confirm("Delete returns false if extn not set", !extn.remove(oid_skid));
   result.confirm("Delete returns true if extn was set", extn.remove(oid_bc));
   result.confirm("Basic constraints is not set", !extn.extension_set(oid_bc));
   result.confirm("Basic constraints is not critical", !extn.critical_extension_set(oid_bc));

   return result;
   }

Test::Result test_x509_dates()
   {
   Test::Result result("X509 Time");

   Botan::X509_Time time;
   result.confirm("unset time not set", !time.time_is_set());
   time = Botan::X509_Time("080201182200Z", Botan::ASN1_Tag::UTC_TIME);
   result.confirm("time set after construction", time.time_is_set());
   result.test_eq("time readable_string", time.readable_string(), "2008/02/01 18:22:00 UTC");

   time = Botan::X509_Time("200305100350Z", Botan::ASN1_Tag::UTC_TIME);
   result.test_eq("UTC_TIME readable_string", time.readable_string(), "2020/03/05 10:03:50 UTC");

   time = Botan::X509_Time("200305100350Z", Botan::ASN1_Tag::UTC_OR_GENERALIZED_TIME);
   result.test_eq("UTC_OR_GENERALIZED_TIME from UTC_TIME readable_string", time.readable_string(),
                  "2020/03/05 10:03:50 UTC");

   time = Botan::X509_Time("20200305100350Z", Botan::ASN1_Tag::UTC_OR_GENERALIZED_TIME);
   result.test_eq("UTC_OR_GENERALIZED_TIME from GENERALIZED_TIME readable_string", time.readable_string(),
                  "2020/03/05 10:03:50 UTC");

   time = Botan::X509_Time("20200305100350Z", Botan::ASN1_Tag::GENERALIZED_TIME);
   result.test_eq("GENERALIZED_TIME readable_string", time.readable_string(), "2020/03/05 10:03:50 UTC");

   // Dates that are valid per X.500 but rejected as unsupported
   const std::string valid_but_unsup[]
      {
      "0802010000-0000",
      "0802011724+0000",
      "0406142334-0500",
      "9906142334+0500",
      "0006142334-0530",
      "0006142334+0530",

      "080201000000-0000",
      "080201172412+0000",
      "040614233433-0500",
      "990614233444+0500",
      "000614233455-0530",
      "000614233455+0530",
      };

   // valid length 13
   const std::string valid_utc[]
      {
      "080201000000Z",
      "080201172412Z",
      "040614233433Z",
      "990614233444Z",
      "000614233455Z",
      };

   const std::string invalid_utc[]
      {
      "",
      " ",
      "2008`02-01",
      "9999-02-01",
      "2000-02-01 17",
      "999921",

      // No seconds
      "0802010000Z",
      "0802011724Z",
      "0406142334Z",
      "9906142334Z",
      "0006142334Z",

      // valid length 13 -> range check
      "080201000061Z", // seconds too big (61)
      "080201000060Z", // seconds too big (60, leap seconds not covered by the standard)
      "0802010000-1Z", // seconds too small (-1)
      "080201006000Z", // minutes too big (60)
      "080201240000Z", // hours too big (24:00)

      // valid length 13 -> invalid numbers
      "08020123112 Z",
      "08020123112!Z",
      "08020123112,Z",
      "08020123112\nZ",
      "080201232 33Z",
      "080201232!33Z",
      "080201232,33Z",
      "080201232\n33Z",
      "0802012 3344Z",
      "0802012!3344Z",
      "0802012,3344Z",
      "08022\n334455Z",
      "08022 334455Z",
      "08022!334455Z",
      "08022,334455Z",
      "08022\n334455Z",
      "082 33445511Z",
      "082!33445511Z",
      "082,33445511Z",
      "082\n33445511Z",
      "2 2211221122Z",
      "2!2211221122Z",
      "2,2211221122Z",
      "2\n2211221122Z",

      // wrong time zone
      "080201000000",
      "080201000000z",

      // Fractional seconds
      "170217180154.001Z",

      // Timezone offset
      "170217180154+0100",

      // Extra digits
      "17021718015400Z",

      // Non-digits
      "17021718015aZ",

      // Trailing garbage
      "170217180154Zlongtrailinggarbage",

      // Swapped type
      "20170217180154Z",
      };

   // valid length 15
   const std::string valid_generalized_time[]
      {
      "20000305100350Z",
      };

   const std::string invalid_generalized[]
      {
      // No trailing Z
      "20000305100350",

      // No seconds
      "200003051003Z",

      // Fractional seconds
      "20000305100350.001Z",

      // Timezone offset
      "20170217180154+0100",

      // Extra digits
      "2017021718015400Z",

      // Non-digits
      "2017021718015aZ",

      // Trailing garbage
      "20170217180154Zlongtrailinggarbage",

      // Swapped type
      "170217180154Z",
      };

   for(const auto& v : valid_but_unsup)
      {
      result.test_throws("valid but unsupported", [v]() { Botan::X509_Time t(v, Botan::ASN1_Tag::UTC_TIME); });
      }

   for(const auto& v : valid_utc)
      {
      Botan::X509_Time t(v, Botan::ASN1_Tag::UTC_TIME);
      }

   for(const auto& v : valid_generalized_time)
      {
      Botan::X509_Time t(v, Botan::ASN1_Tag::GENERALIZED_TIME);
      }

   for(const auto& v : invalid_utc)
      {
      result.test_throws("invalid", [v]() { Botan::X509_Time t(v, Botan::ASN1_Tag::UTC_TIME); });
      }

   for(const auto& v : invalid_generalized)
      {
      result.test_throws("invalid", [v]() { Botan::X509_Time t(v, Botan::ASN1_Tag::GENERALIZED_TIME); });
      }

   return result;
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

Test::Result test_crl_dn_name()
   {
   Test::Result result("CRL DN name");

   // See GH #1252

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EMSA_PKCS1)
   const Botan::OID dc_oid("0.9.2342.19200300.100.1.25");

   Botan::X509_Certificate cert(Test::data_file("x509/misc/opcuactt_ca.der"));

   Botan::DataSource_Stream key_input(Test::data_file("x509/misc/opcuactt_ca.pem"));
   std::unique_ptr<Botan::Private_Key> key = Botan::PKCS8::load_key(key_input);
   Botan::X509_CA ca(cert, *key, "SHA-256", Test::rng());

   Botan::X509_CRL crl = ca.new_crl(Test::rng());

   result.confirm("matches issuer cert", crl.issuer_dn() == cert.subject_dn());

   result.confirm("contains DC component",
                  crl.issuer_dn().get_attributes().count(dc_oid) == 1);
#endif

   return result;
   }

Test::Result test_rsa_oaep()
   {
   Test::Result result("RSA OAEP decoding");

#if defined(BOTAN_HAS_RSA)
   Botan::X509_Certificate cert(Test::data_file("x509/misc/rsa_oaep.pem"));

   auto public_key = cert.load_subject_public_key();
   result.test_not_null("Decoding RSA-OAEP worked", public_key.get());
   auto pk_info = cert.subject_public_key_algo();

   result.test_eq("RSA-OAEP OID", pk_info.get_oid().to_string(), Botan::OID::from_string("RSA/OAEP").to_string());
#endif

   return result;
   }

Test::Result test_x509_decode_list()
   {
   Test::Result result("X509_Certificate list decode");

   Botan::DataSource_Stream input(Test::data_file("x509/misc/cert_seq.der"), true);

   Botan::BER_Decoder dec(input);
   std::vector<Botan::X509_Certificate> certs;
   dec.decode_list(certs);

   result.test_eq("Expected number of certs in list", certs.size(), 2);

   result.test_eq("Expected cert 1 CN", certs[0].subject_dn().get_first_attribute("CN"), "CA1-PP.01.02");
   result.test_eq("Expected cert 2 CN", certs[1].subject_dn().get_first_attribute("CN"), "User1-PP.01.02");

   return result;
   }

Test::Result test_x509_utf8()
   {
   Test::Result result("X509 with UTF-8 encoded fields");

   try
      {
      Botan::X509_Certificate utf8_cert(Test::data_file("x509/misc/contains_utf8string.pem"));

      // UTF-8 encoded fields of test certificate (contains cyrillic letters)
      const std::string organization =
         "\xD0\x9C\xD0\xBE\xD1\x8F\x20\xD0\xBA\xD0\xBE\xD0"
         "\xBC\xD0\xBF\xD0\xB0\xD0\xBD\xD0\xB8\xD1\x8F";
      const std::string organization_unit =
         "\xD0\x9C\xD0\xBE\xD1\x91\x20\xD0\xBF\xD0\xBE\xD0\xB4\xD1\x80\xD0\xB0"
         "\xD0\xB7\xD0\xB4\xD0\xB5\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB5";
      const std::string common_name =
         "\xD0\x9E\xD0\xBF\xD0\xB8\xD1\x81\xD0\xB0\xD0\xBD\xD0\xB8"
         "\xD0\xB5\x20\xD1\x81\xD0\xB0\xD0\xB9\xD1\x82\xD0\xB0";
      const std::string location =
         "\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";

      const Botan::X509_DN& issuer_dn = utf8_cert.issuer_dn();

      result.test_eq("O",  issuer_dn.get_first_attribute("O"),  organization);
      result.test_eq("OU", issuer_dn.get_first_attribute("OU"), organization_unit);
      result.test_eq("CN", issuer_dn.get_first_attribute("CN"), common_name);
      result.test_eq("L",  issuer_dn.get_first_attribute("L"),  location);
      }
   catch (const Botan::Decoding_Error &ex)
      {
      result.test_failure(ex.what());
      }

   return result;
   }

Test::Result test_x509_bmpstring()
   {
   Test::Result result("X509 with UCS-2 (BMPString) encoded fields");

   try
      {
      Botan::X509_Certificate ucs2_cert(Test::data_file("x509/misc/contains_bmpstring.pem"));

      // UTF-8 encoded fields of test certificate (contains cyrillic and greek letters)
      const std::string organization =
         "\x6E\x65\xCF\x87\xCF\xB5\x6E\x69\xCF\x89";
      const std::string common_name =
         "\xC3\xA8\x6E\xC7\x9D\xD0\xAF\x20\xD0\x9C\xC7\x9D\xD0\xB9\xD0\xB7\xD1\x8D\xD0\xBB";

      // UTF-8 encoded fields of test certificate (contains only ASCII characters)
      const std::string location = "Berlin";

      const Botan::X509_DN& issuer_dn = ucs2_cert.issuer_dn();

      result.test_eq("O",  issuer_dn.get_first_attribute("O"),  organization);
      result.test_eq("CN", issuer_dn.get_first_attribute("CN"), common_name);
      result.test_eq("L",  issuer_dn.get_first_attribute("L"),  location);
      }
   catch (const Botan::Decoding_Error &ex)
      {
      result.test_failure(ex.what());
      }

   return result;
   }

Test::Result test_x509_authority_info_access_extension()
   {
   Test::Result result("X509 with PKIX.AuthorityInformationAccess extension");

   // contains no AIA extension
   Botan::X509_Certificate no_aia_cert(Test::data_file("x509/misc/contains_utf8string.pem"));

   result.test_eq("number of ca_issuers URLs", no_aia_cert.ca_issuers().size(), 0);
   result.test_eq("CA issuer URL matches", no_aia_cert.ocsp_responder(), "");

   // contains AIA extension with 1 CA issuer URL and 1 OCSP responder
   Botan::X509_Certificate aia_cert(Test::data_file("x509/misc/contains_authority_info_access.pem"));

   const auto ca_issuers = aia_cert.ca_issuers();

   result.test_eq("number of ca_issuers URLs", ca_issuers.size(), 1);
   if (result.tests_failed())
      return result;

   result.test_eq("CA issuer URL matches", ca_issuers[0], "http://gp.symcb.com/gp.crt");
   result.test_eq("OCSP responder URL matches", aia_cert.ocsp_responder(), "http://gp.symcd.com");

   // contains AIA extension with 2 CA issuer URL and 1 OCSP responder
   Botan::X509_Certificate aia_cert_2ca(Test::data_file("x509/misc/contains_authority_info_access_with_two_ca_issuers.pem"));

   const auto ca_issuers2 = aia_cert_2ca.ca_issuers();

   result.test_eq("number of ca_issuers URLs", ca_issuers2.size(), 2);
   if (result.tests_failed())
      return result;

   result.test_eq("CA issuer URL matches", ca_issuers2[0], "http://www.d-trust.net/cgi-bin/Bdrive_Test_CA_1-2_2017.crt");
   result.test_eq("CA issuer URL matches", ca_issuers2[1], "ldap://directory.d-trust.net/CN=Bdrive%20Test%20CA%201-2%202017,O=Bundesdruckerei%20GmbH,C=DE?cACertificate?base?");
   result.test_eq("OCSP responder URL matches", aia_cert_2ca.ocsp_responder(), "http://staging.ocsp.d-trust.net");

   return result;
   }

Test::Result test_verify_gost2012_cert()
   {
   Test::Result result("X509 GOST-2012 certificates");

#if defined(BOTAN_HAS_GOST_34_10_2012) && defined(BOTAN_HAS_STREEBOG) && defined(BOTAN_HAS_EMSA1)
   try
      {
      Botan::X509_Certificate root_cert(Test::data_file("x509/gost/gost_root.pem"));
      Botan::X509_Certificate root_int(Test::data_file("x509/gost/gost_int.pem"));

      Botan::Certificate_Store_In_Memory trusted;
      trusted.add_certificate(root_cert);

      const Botan::Path_Validation_Restrictions restrictions(false, 128, false, {"Streebog-256"});
      const Botan::Path_Validation_Result validation_result = Botan::x509_path_validate(root_int, restrictions, trusted);

      result.confirm("GOST certificate validates", validation_result.successful_validation());
      }
   catch(const Botan::Decoding_Error& e)
      {
      result.test_failure(e.what());
      }
#endif

   return result;
   }

/*
 * @brief checks the configurability of the EMSA4(RSA-PSS) signature scheme
 *
 * For the other algorithms than RSA, only one padding is supported right now.
 */
#if defined(BOTAN_HAS_EMSA_PKCS1) && defined(BOTAN_HAS_EMSA_PSSR) && defined(BOTAN_HAS_RSA)
 Test::Result test_padding_config() {
   // Throughout the test, some synonyms for EMSA4 are used, e.g. PSSR, EMSA-PSS
   Test::Result test_result("X509 Padding Config");

   std::unique_ptr<Botan::Private_Key> sk(Botan::PKCS8::load_key(
      Test::data_file("x509/misc/rsa_key.pem"), Test::rng()));

   // Create X509 CA certificate; EMSA3 is used for signing by default
   Botan::X509_Cert_Options opt("TESTCA");
   opt.CA_key();

   Botan::X509_Certificate ca_cert_def = Botan::X509::create_self_signed_cert(opt, (*sk), "SHA-512", Test::rng());
   test_result.test_eq("CA certificate signature algorithm (default)",
      Botan::OIDS::oid2str_or_throw(ca_cert_def.signature_algorithm().get_oid()),"RSA/EMSA3(SHA-512)");

   // Create X509 CA certificate; RSA-PSS is explicitly set
   opt.set_padding_scheme("PSSR");
   Botan::X509_Certificate ca_cert_exp = Botan::X509::create_self_signed_cert(opt, (*sk), "SHA-512", Test::rng());
   test_result.test_eq("CA certificate signature algorithm (explicit)",
      Botan::OIDS::oid2str_or_throw(ca_cert_exp.signature_algorithm().get_oid()),"RSA/EMSA4");

#if defined(BOTAN_HAS_EMSA1)

   // Try to set a padding scheme that is not supported for signing with the given key type
   opt.set_padding_scheme("EMSA1");
   try
      {
      Botan::X509_Certificate ca_cert_wrong = Botan::X509::create_self_signed_cert(opt, (*sk), "SHA-512", Test::rng());
      test_result.test_failure("Could build CA cert with invalid encoding scheme EMSA1 for key type " + sk->algo_name());
      }
   catch (const Botan::Invalid_Argument& e)
      {
      test_result.test_eq("Build CA certitiface with invalid encoding scheme EMSA1 for key type " +
         sk->algo_name(), e.what(),
         "Encoding scheme with canonical name EMSA1 not supported for signature algorithm RSA");
      }
#endif

   test_result.test_eq("CA certificate signature algorithm (explicit)",
      Botan::OIDS::oid2str_or_throw(ca_cert_exp.signature_algorithm().get_oid()),"RSA/EMSA4");

   const Botan::X509_Time not_before = from_date(-1, 1, 1);
   const Botan::X509_Time not_after = from_date(2, 1, 2);

   // Prepare a signing request for the end certificate
   Botan::X509_Cert_Options req_opt("endpoint");
   req_opt.set_padding_scheme("EMSA4(SHA-512,MGF1,64)");
   Botan::PKCS10_Request end_req = Botan::X509::create_cert_req(req_opt, (*sk), "SHA-512", Test::rng());
   test_result.test_eq("Certificate request signature algorithm", Botan::OIDS::oid2str_or_throw(end_req.signature_algorithm().get_oid()),"RSA/EMSA4");

   // Create X509 CA object: will fail as the chosen hash functions differ
   try
      {
      Botan::X509_CA ca_fail(ca_cert_exp, (*sk), {{"padding","EMSA4(SHA-256)"}},"SHA-512", Test::rng());
      test_result.test_failure("Configured conflicting hash functions for CA");
      }
   catch(const Botan::Invalid_Argument& e)
      {
      test_result.test_eq("Configured conflicting hash functions for CA",
            e.what(),
            "Hash function from opts and hash_fn argument need to be identical");
      }

   // Create X509 CA object: its signer will use the padding scheme from the CA certificate, i.e. EMSA3
   Botan::X509_CA ca_def(ca_cert_def, (*sk), "SHA-512", Test::rng());
   Botan::X509_Certificate end_cert_emsa3 = ca_def.sign_request(end_req, Test::rng(), not_before, not_after);
   test_result.test_eq("End certificate signature algorithm", Botan::OIDS::oid2str_or_throw(end_cert_emsa3.signature_algorithm().get_oid()), "RSA/EMSA3(SHA-512)");

   // Create X509 CA object: its signer will use the explicitly configured padding scheme, which is different from the CA certificate's scheme
   Botan::X509_CA ca_diff(ca_cert_def, (*sk), {{"padding","EMSA-PSS"}}, "SHA-512", Test::rng());
   Botan::X509_Certificate end_cert_diff_emsa4 = ca_diff.sign_request(end_req, Test::rng(), not_before, not_after);
   test_result.test_eq("End certificate signature algorithm", Botan::OIDS::oid2str_or_throw(end_cert_diff_emsa4.signature_algorithm().get_oid()), "RSA/EMSA4");

   // Create X509 CA object: its signer will use the explicitly configured padding scheme, which is identical to the CA certificate's scheme
   Botan::X509_CA ca_exp(ca_cert_exp, (*sk), {{"padding","EMSA4(SHA-512,MGF1,64)"}},"SHA-512", Test::rng());
   Botan::X509_Certificate end_cert_emsa4= ca_exp.sign_request(end_req, Test::rng(), not_before, not_after);
   test_result.test_eq("End certificate signature algorithm", Botan::OIDS::oid2str_or_throw(end_cert_emsa4.signature_algorithm().get_oid()), "RSA/EMSA4");

   // Check CRL signature algorithm
   Botan::X509_CRL crl = ca_exp.new_crl(Test::rng());
   test_result.test_eq("CRL signature algorithm", Botan::OIDS::oid2str_or_throw(crl.signature_algorithm().get_oid()), "RSA/EMSA4");

   // sanity check for verification, the heavy lifting is done in the other unit tests
   const Botan::Certificate_Store_In_Memory trusted(ca_exp.ca_certificate());
   const Botan::Path_Validation_Restrictions restrictions(false, 80);
   const Botan::Path_Validation_Result validation_result = Botan::x509_path_validate(
            end_cert_emsa4, restrictions, trusted);
   test_result.confirm("EMSA4-signed certificate validates", validation_result.successful_validation());

   return test_result;
}
#endif

#endif

Test::Result test_pkcs10_ext(const Botan::Private_Key& key,
                             const std::string& sig_padding,
                             const std::string& hash_fn = "SHA-256")
   {
   Test::Result result("PKCS10 extensions");

   Botan::X509_Cert_Options opts;

   opts.padding_scheme = sig_padding;

   Botan::AlternativeName alt_name;
   alt_name.add_attribute("DNS", "example.org");
   alt_name.add_attribute("DNS", "example.com");
   alt_name.add_attribute("DNS", "example.net");

   opts.extensions.add(new Botan::Cert_Extension::Subject_Alternative_Name(alt_name));

   Botan::PKCS10_Request req = Botan::X509::create_cert_req(opts, key, hash_fn, Test::rng());

   std::vector<std::string> alt_dns_names = req.subject_alt_name().get_attribute("DNS");

   result.test_eq("Expected number of DNS names", alt_dns_names.size(), 3);

   // The order is not guaranteed so sort before comparing
   std::sort(alt_dns_names.begin(), alt_dns_names.end());

   result.test_eq("Expected DNS name 1", alt_dns_names.at(0), "example.com");
   result.test_eq("Expected DNS name 2", alt_dns_names.at(1), "example.net");
   result.test_eq("Expected DNS name 3", alt_dns_names.at(2), "example.org");

   return result;
   }

Test::Result test_x509_cert(const Botan::Private_Key& ca_key,
                            const std::string& sig_algo,
                            const std::string& sig_padding = "",
                            const std::string& hash_fn = "SHA-256")
   {
   Test::Result result("X509 Unit");

   /* Create the self-signed cert */
   const auto ca_cert = Botan::X509::create_self_signed_cert(ca_opts(sig_padding), ca_key, hash_fn, Test::rng());

      {
      const auto constraints = Botan::Key_Constraints(Botan::KEY_CERT_SIGN | Botan::CRL_SIGN);
      result.test_eq("ca key usage", (ca_cert.constraints() & constraints) == constraints, true);
      }

   /* Create user #1's key and cert request */
   std::unique_ptr<Botan::Private_Key> user1_key(make_a_private_key(sig_algo));

   Botan::PKCS10_Request user1_req =
      Botan::X509::create_cert_req(req_opts1(sig_algo, sig_padding),
                                   *user1_key,
                                   hash_fn,
                                   Test::rng());

   result.test_eq("PKCS10 challenge password parsed",
                  user1_req.challenge_password(), "zoom");

   /* Create user #2's key and cert request */
   std::unique_ptr<Botan::Private_Key> user2_key(make_a_private_key(sig_algo));

   Botan::PKCS10_Request user2_req =
      Botan::X509::create_cert_req(req_opts2(sig_padding),
                                   *user2_key,
                                   hash_fn,
                                   Test::rng());

   // /* Create user #3's key and cert request */
   std::unique_ptr<Botan::Private_Key> user3_key(make_a_private_key(sig_algo));

   Botan::PKCS10_Request user3_req =
      Botan::X509::create_cert_req(req_opts3(sig_padding),
                                   *user3_key,
                                   hash_fn,
                                   Test::rng());

   /* Create the CA object */
   Botan::X509_CA ca(ca_cert, ca_key, {{"padding",sig_padding}}, hash_fn, Test::rng());

   const BigInt user1_serial = 99;

   /* Sign the requests to create the certs */
   Botan::X509_Certificate user1_cert =
      ca.sign_request(user1_req, Test::rng(), user1_serial,
                      from_date(-1, 01, 01),
                      from_date(2, 01, 01));

   result.test_eq("User1 serial size matches expected", user1_cert.serial_number().size(), 1);
   result.test_eq("User1 serial matches expected", user1_cert.serial_number().at(0), size_t(99));

   Botan::X509_Certificate user2_cert =
      ca.sign_request(user2_req, Test::rng(),
                      from_date(-1, 01, 01),
                      from_date(2, 01, 01));

   Botan::X509_Certificate user3_cert =
      ca.sign_request(user3_req, Test::rng(),
                      from_date(-1, 01, 01),
                      from_date(2, 01, 01));

   // user#1 creates a self-signed cert on the side
   const auto user1_ss_cert =
      Botan::X509::create_self_signed_cert(req_opts1(sig_algo, sig_padding), *user1_key, hash_fn, Test::rng());

      {
      auto constrains = req_opts1(sig_algo).constraints;
      result.test_eq("user1 key usage", (user1_cert.constraints() & constrains) == constrains, true);
      }

   /* Copy, assign and compare */
   Botan::X509_Certificate user1_cert_copy(user1_cert);
   result.test_eq("certificate copy", user1_cert == user1_cert_copy, true);

   user1_cert_copy = user2_cert;
   result.test_eq("certificate assignment", user2_cert == user1_cert_copy, true);

   Botan::X509_Certificate user1_cert_differ =
      ca.sign_request(user1_req, Test::rng(),
                      from_date(-1, 01, 01),
                      from_date(2, 01, 01));

   result.test_eq("certificate differs", user1_cert == user1_cert_differ, false);

   /* Get cert data */
   result.test_eq("x509 version", user1_cert.x509_version(), size_t(3));

   const Botan::X509_DN& user1_issuer_dn = user1_cert.issuer_dn();
   result.test_eq("issuer info CN", user1_issuer_dn.get_first_attribute("CN"), ca_opts().common_name);
   result.test_eq("issuer info Country", user1_issuer_dn.get_first_attribute("C"), ca_opts().country);
   result.test_eq("issuer info Orga", user1_issuer_dn.get_first_attribute("O"), ca_opts().organization);
   result.test_eq("issuer info OrgaUnit", user1_issuer_dn.get_first_attribute("OU"), ca_opts().org_unit);

   const Botan::X509_DN& user3_subject_dn = user3_cert.subject_dn();
   result.test_eq("subject OrgaUnit count", user3_subject_dn.get_attribute("OU").size(), req_opts3(sig_algo).more_org_units.size() + 1);
   result.test_eq("subject OrgaUnit #2", user3_subject_dn.get_attribute("OU").at(1), req_opts3(sig_algo).more_org_units.at(0));

   const Botan::AlternativeName& user1_altname = user1_cert.subject_alt_name();
   result.test_eq("subject alt email", user1_altname.get_first_attribute("RFC822"), "testing@randombit.net");
   result.test_eq("subject alt dns", user1_altname.get_first_attribute("DNS"), "botan.randombit.net");
   result.test_eq("subject alt uri", user1_altname.get_first_attribute("URI"), "https://botan.randombit.net");

   const Botan::AlternativeName& user3_altname = user3_cert.subject_alt_name();
   result.test_eq("subject alt dns count", user3_altname.get_attribute("DNS").size(), req_opts3(sig_algo).more_dns.size() + 1);
   result.test_eq("subject alt dns #2", user3_altname.get_attribute("DNS").at(1), req_opts3(sig_algo).more_dns.at(0));

   const Botan::X509_CRL crl1 = ca.new_crl(Test::rng());

   /* Verify the certs */
   Botan::Path_Validation_Restrictions restrictions(false, 80);
   Botan::Certificate_Store_In_Memory store;

   // First try with an empty store
   Botan::Path_Validation_Result result_no_issuer = Botan::x509_path_validate(user1_cert, restrictions, store);
   result.test_eq("user 1 issuer not found",
                  result_no_issuer.result_string(),
                  Botan::Path_Validation_Result::status_string(Botan::Certificate_Status_Code::CERT_ISSUER_NOT_FOUND));

   store.add_certificate(ca.ca_certificate());

   Botan::Path_Validation_Result result_u1 = Botan::x509_path_validate(user1_cert, restrictions, store);
   if(!result.confirm("user 1 validates", result_u1.successful_validation()))
      {
      result.test_note("user 1 validation result was " + result_u1.result_string());
      }
   else
      {
      const std::set<std::string> u1_hashes = result_u1.trusted_hashes();

      if(result.test_eq("Single trusted hash", u1_hashes.size(), 1))
         {
         result.test_eq("Hash matches test", *u1_hashes.begin(), hash_fn);
         }
      }

   Botan::Path_Validation_Result result_u2 = Botan::x509_path_validate(user2_cert, restrictions, store);
   if(!result.confirm("user 2 validates", result_u2.successful_validation()))
      {
      result.test_note("user 2 validation result was " + result_u2.result_string());
      }

   Botan::Path_Validation_Result result_self_signed = Botan::x509_path_validate(user1_ss_cert, restrictions, store);
   result.test_eq("user 1 issuer not found",
                  result_no_issuer.result_string(),
                  Botan::Path_Validation_Result::status_string(Botan::Certificate_Status_Code::CERT_ISSUER_NOT_FOUND));
   store.add_crl(crl1);

   std::vector<Botan::CRL_Entry> revoked;
   revoked.push_back(Botan::CRL_Entry(user1_cert, Botan::CESSATION_OF_OPERATION));
   revoked.push_back(user2_cert);

   const Botan::X509_CRL crl2 = ca.update_crl(crl1, revoked, Test::rng());

   store.add_crl(crl2);

   const std::string revoked_str =
      Botan::Path_Validation_Result::status_string(Botan::Certificate_Status_Code::CERT_IS_REVOKED);

   result_u1 = Botan::x509_path_validate(user1_cert, restrictions, store);
   result.test_eq("user 1 revoked", result_u1.result_string(), revoked_str);

   result_u2 = Botan::x509_path_validate(user2_cert, restrictions, store);
   result.test_eq("user 1 revoked", result_u2.result_string(), revoked_str);

   revoked.clear();
   revoked.push_back(Botan::CRL_Entry(user1_cert, Botan::REMOVE_FROM_CRL));
   Botan::X509_CRL crl3 = ca.update_crl(crl2, revoked, Test::rng());

   store.add_crl(crl3);

   result_u1 = Botan::x509_path_validate(user1_cert, restrictions, store);
   if(!result.confirm("user 1 validates", result_u1.successful_validation()))
      {
      result.test_note("user 1 validation result was " + result_u1.result_string());
      }

   result_u2 = Botan::x509_path_validate(user2_cert, restrictions, store);
   result.test_eq("user 2 still revoked", result_u2.result_string(), revoked_str);

   return result;
   }

Test::Result test_usage(const Botan::Private_Key& ca_key,
                        const std::string& sig_algo,
                        const std::string& hash_fn = "SHA-256")
   {
   using Botan::Key_Constraints;
   using Botan::Usage_Type;

   Test::Result result("X509 Usage");

   /* Create the self-signed cert */
   const Botan::X509_Certificate ca_cert = Botan::X509::create_self_signed_cert(
         ca_opts(),
         ca_key,
         hash_fn,
         Test::rng());

   /* Create the CA object */
   const Botan::X509_CA ca(ca_cert, ca_key, hash_fn, Test::rng());

   std::unique_ptr<Botan::Private_Key> user1_key(make_a_private_key(sig_algo));

   Botan::X509_Cert_Options opts("Test User 1/US/Botan Project/Testing");
   opts.constraints = Key_Constraints::DIGITAL_SIGNATURE;

   const Botan::PKCS10_Request user1_req = Botan::X509::create_cert_req(
         opts,
         *user1_key,
         hash_fn,
         Test::rng());

   const Botan::X509_Certificate user1_cert = ca.sign_request(
            user1_req,
            Test::rng(),
            from_date(-1, 01, 01),
            from_date(2, 01, 01));

   // cert only allows digitalSignature, but we check for both digitalSignature and cRLSign
   result.test_eq("key usage cRLSign not allowed",
                  user1_cert.allowed_usage(
                     Key_Constraints(Key_Constraints::DIGITAL_SIGNATURE | Key_Constraints::CRL_SIGN)), false);
   result.test_eq("encryption is not allowed",
                  user1_cert.allowed_usage(Usage_Type::ENCRYPTION), false);

   // cert only allows digitalSignature, so checking for only that should be ok
   result.confirm("key usage digitalSignature allowed", user1_cert.allowed_usage(Key_Constraints::DIGITAL_SIGNATURE));

   opts.constraints = Key_Constraints(Key_Constraints::DIGITAL_SIGNATURE | Key_Constraints::CRL_SIGN);

   const Botan::PKCS10_Request mult_usage_req = Botan::X509::create_cert_req(
            opts,
            *user1_key,
            hash_fn,
            Test::rng());

   const Botan::X509_Certificate mult_usage_cert = ca.sign_request(
            mult_usage_req,
            Test::rng(),
            from_date(-1, 01, 01),
            from_date(2, 01, 01));

   // cert allows multiple usages, so each one of them as well as both together should be allowed
   result.confirm("key usage multiple digitalSignature allowed",
                  mult_usage_cert.allowed_usage(Key_Constraints::DIGITAL_SIGNATURE));
   result.confirm("key usage multiple cRLSign allowed", mult_usage_cert.allowed_usage(Key_Constraints::CRL_SIGN));
   result.confirm("key usage multiple digitalSignature and cRLSign allowed", mult_usage_cert.allowed_usage(
                     Key_Constraints(Key_Constraints::DIGITAL_SIGNATURE | Key_Constraints::CRL_SIGN)));
   result.test_eq("encryption is not allowed",
                  mult_usage_cert.allowed_usage(Usage_Type::ENCRYPTION), false);


   opts.constraints = Key_Constraints::NO_CONSTRAINTS;

   const Botan::PKCS10_Request no_usage_req = Botan::X509::create_cert_req(opts, *user1_key, hash_fn, Test::rng());

   const Botan::X509_Certificate no_usage_cert =
      ca.sign_request(no_usage_req, Test::rng(),
                      from_date(-1, 01, 01),
                      from_date(2, 01, 01));

   // cert allows every usage
   result.confirm("key usage digitalSignature allowed", no_usage_cert.allowed_usage(Key_Constraints::DIGITAL_SIGNATURE));
   result.confirm("key usage cRLSign allowed", no_usage_cert.allowed_usage(Key_Constraints::CRL_SIGN));
   result.confirm("key usage encryption allowed", no_usage_cert.allowed_usage(Usage_Type::ENCRYPTION));

   if (sig_algo == "RSA")
      {
      // cert allows data encryption
       opts.constraints = Key_Constraints(Key_Constraints::KEY_ENCIPHERMENT | Key_Constraints::DATA_ENCIPHERMENT);

      const Botan::PKCS10_Request enc_req = Botan::X509::create_cert_req(
               opts,
               *user1_key,
               hash_fn,
               Test::rng());

      const Botan::X509_Certificate enc_cert = ca.sign_request(
               enc_req,
               Test::rng(),
               from_date(-1, 01, 01),
               from_date(2, 01, 01));

      result.confirm("cert allows encryption", enc_cert.allowed_usage(Usage_Type::ENCRYPTION));
      result.confirm("cert does not allow TLS client auth", !enc_cert.allowed_usage(Usage_Type::TLS_CLIENT_AUTH));
      }

   return result;
   }

Test::Result test_self_issued(const Botan::Private_Key& ca_key,
                              const std::string& sig_algo,
                              const std::string& sig_padding = "",
                              const std::string& hash_fn = "SHA-256")
   {
   using Botan::Key_Constraints;

   Test::Result result("X509 Self Issued");

   // create the self-signed cert
   const Botan::X509_Certificate ca_cert = Botan::X509::create_self_signed_cert(
         ca_opts(sig_padding), ca_key, hash_fn, Test::rng());

   /* Create the CA object */
   const Botan::X509_CA ca(ca_cert, ca_key, {{"padding",sig_padding}}, hash_fn, Test::rng());

   std::unique_ptr<Botan::Private_Key> user_key(make_a_private_key(sig_algo));

   // create a self-issued certificate, that is, a certificate with subject dn == issuer dn,
   // but signed by a CA, not signed by it's own private key
   Botan::X509_Cert_Options opts = ca_opts();
   opts.constraints = Key_Constraints::DIGITAL_SIGNATURE;
   opts.set_padding_scheme(sig_padding);

   const Botan::PKCS10_Request self_issued_req = Botan::X509::create_cert_req(opts, *user_key, hash_fn, Test::rng());

   const Botan::X509_Certificate self_issued_cert = ca.sign_request(
            self_issued_req, Test::rng(), from_date(-1, 01, 01), from_date(2, 01, 01));

   // check that this chain can can be verified successfully
   const Botan::Certificate_Store_In_Memory trusted(ca.ca_certificate());

   const Botan::Path_Validation_Restrictions restrictions(false, 80);

   const Botan::Path_Validation_Result validation_result = Botan::x509_path_validate(
            self_issued_cert, restrictions, trusted);

   result.confirm("chain with self-issued cert validates", validation_result.successful_validation());

   return result;
   }

Test::Result test_x509_uninit()
   {
   Test::Result result("X509 object uninitialized access");

   Botan::X509_Certificate cert;
   result.test_throws("uninitialized cert access causes exception",
                      "X509_Certificate uninitialized",
                      [&cert]() { cert.x509_version(); });

   Botan::X509_CRL crl;
   result.test_throws("uninitialized crl access causes exception",
                      "X509_CRL uninitialized",
                      [&crl]() { crl.crl_number(); });

   return result;
   }


using Botan::Key_Constraints;

/**
* @brief Some typical key usage scenarios (taken from RFC 5280, sec. 4.2.1.3)
*/
struct typical_usage_constraints
   {
   // ALL constraints are not typical at all, but we use them for a negative test
   Key_Constraints all = Key_Constraints(
                            Key_Constraints::DIGITAL_SIGNATURE |
                            Key_Constraints::NON_REPUDIATION |
                            Key_Constraints::KEY_ENCIPHERMENT |
                            Key_Constraints::DATA_ENCIPHERMENT |
                            Key_Constraints::KEY_AGREEMENT |
                            Key_Constraints::KEY_CERT_SIGN |
                            Key_Constraints::CRL_SIGN |
                            Key_Constraints::ENCIPHER_ONLY |
                            Key_Constraints::DECIPHER_ONLY);

   Key_Constraints ca = Key_Constraints(Key_Constraints::KEY_CERT_SIGN);
   Key_Constraints sign_data = Key_Constraints(Key_Constraints::DIGITAL_SIGNATURE);
   Key_Constraints non_repudiation = Key_Constraints(
                                        Key_Constraints::NON_REPUDIATION |
                                        Key_Constraints::DIGITAL_SIGNATURE);
   Key_Constraints key_encipherment = Key_Constraints(Key_Constraints::KEY_ENCIPHERMENT);
   Key_Constraints data_encipherment = Key_Constraints(Key_Constraints::DATA_ENCIPHERMENT);
   Key_Constraints key_agreement = Key_Constraints(Key_Constraints::KEY_AGREEMENT);
   Key_Constraints key_agreement_encipher_only = Key_Constraints(
            Key_Constraints::KEY_AGREEMENT |
            Key_Constraints::ENCIPHER_ONLY);
   Key_Constraints key_agreement_decipher_only = Key_Constraints(
            Key_Constraints::KEY_AGREEMENT |
            Key_Constraints::DECIPHER_ONLY);
   Key_Constraints crl_sign = Key_Constraints::CRL_SIGN;
   Key_Constraints sign_everything = Key_Constraints(
                                        Key_Constraints::DIGITAL_SIGNATURE |
                                        Key_Constraints::KEY_CERT_SIGN |
                                        Key_Constraints::CRL_SIGN);
   };


Test::Result test_valid_constraints(const Botan::Private_Key& key,
                                    const std::string& pk_algo)
   {
   Test::Result result("X509 Valid Constraints");

   // should not throw on empty constraints
   verify_cert_constraints_valid_for_key_type(key, Key_Constraints(Key_Constraints::NO_CONSTRAINTS));

   // now check some typical usage scenarios for the given key type
   typical_usage_constraints typical_usage;

   if(pk_algo == "DH" || pk_algo == "ECDH")
      {
      // DH and ECDH only for key agreement
      result.test_throws("all constraints not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.all);
         });
      result.test_throws("cert sign not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.ca);
         });
      result.test_throws("signature not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.sign_data);
         });
      result.test_throws("non repudiation not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.non_repudiation);
         });
      result.test_throws("key encipherment not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.key_encipherment);
         });
      result.test_throws("data encipherment not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.data_encipherment);
         });

      verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement);
      verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement_encipher_only);
      verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement_decipher_only);

      result.test_throws("crl sign not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.crl_sign);
         });
      result.test_throws("sign, cert sign, crl sign not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.sign_everything);
         });
      }
   else if(pk_algo == "RSA")
      {
      // RSA can do everything except key agreement
      result.test_throws("all constraints not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.all);
         });

      verify_cert_constraints_valid_for_key_type(key, typical_usage.ca);
      verify_cert_constraints_valid_for_key_type(key, typical_usage.sign_data);
      verify_cert_constraints_valid_for_key_type(key, typical_usage.non_repudiation);
      verify_cert_constraints_valid_for_key_type(key, typical_usage.key_encipherment);
      verify_cert_constraints_valid_for_key_type(key, typical_usage.data_encipherment);

      result.test_throws("key agreement not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement);
         });
      result.test_throws("key agreement, encipher only not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement_encipher_only);
         });
      result.test_throws("key agreement, decipher only not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement_decipher_only);
         });

      verify_cert_constraints_valid_for_key_type(key, typical_usage.crl_sign);
      verify_cert_constraints_valid_for_key_type(key, typical_usage.sign_everything);
      }
   else if(pk_algo == "ElGamal")
      {
      // only ElGamal encryption is currently implemented
      result.test_throws("all constraints not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.all);
         });
      result.test_throws("cert sign not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.ca);
         });

      verify_cert_constraints_valid_for_key_type(key, typical_usage.data_encipherment);
      verify_cert_constraints_valid_for_key_type(key, typical_usage.key_encipherment);

      result.test_throws("key agreement not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement);
         });
      result.test_throws("key agreement, encipher only not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement_encipher_only);
         });
      result.test_throws("key agreement, decipher only not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement_decipher_only);
         });
      result.test_throws("crl sign not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.crl_sign);
         });
      result.test_throws("sign, cert sign, crl sign not permitted not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.sign_everything);
         });
      }
   else if(pk_algo == "DSA" || pk_algo == "ECDSA" || pk_algo == "ECGDSA" || pk_algo == "ECKCDSA" ||
           pk_algo == "GOST-34.10")
      {
      // these are signature algorithms only
      result.test_throws("all constraints not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.all);
         });

      verify_cert_constraints_valid_for_key_type(key, typical_usage.ca);
      verify_cert_constraints_valid_for_key_type(key, typical_usage.sign_data);
      verify_cert_constraints_valid_for_key_type(key, typical_usage.non_repudiation);

      result.test_throws("key encipherment not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.key_encipherment);
         });
      result.test_throws("data encipherment not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.data_encipherment);
         });
      result.test_throws("key agreement not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement);
         });
      result.test_throws("key agreement, encipher only not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement_encipher_only);
         });
      result.test_throws("key agreement, decipher only not permitted", [&key, &typical_usage]()
         {
         verify_cert_constraints_valid_for_key_type(key, typical_usage.key_agreement_decipher_only);
         });

      verify_cert_constraints_valid_for_key_type(key, typical_usage.crl_sign);
      verify_cert_constraints_valid_for_key_type(key, typical_usage.sign_everything);
      }

   return result;
   }

/**
 * @brief X.509v3 extension that encodes a given string
 */
class String_Extension final : public Botan::Certificate_Extension
   {
   public:
      String_Extension() = default;
      String_Extension(const std::string& val) : m_contents(val) {}

      std::string value() const
         {
         return m_contents;
         }

      String_Extension* copy() const override
         {
         return new String_Extension(m_contents);
         }

      Botan::OID oid_of() const override
         {
         return Botan::OID("1.2.3.4.5.6.7.8.9.1");
         }

      bool should_encode() const override
         {
         return true;
         }

      std::string oid_name() const override
         {
         return "String Extension";
         }

      void contents_to(Botan::Data_Store&, Botan::Data_Store&) const override {}

      std::vector<uint8_t> encode_inner() const override
         {
         std::vector<uint8_t> bits;
         Botan::DER_Encoder(bits).encode(Botan::ASN1_String(m_contents, Botan::UTF8_STRING));
         return bits;
         }

      void decode_inner(const std::vector<uint8_t>& in) override
         {
         Botan::ASN1_String str;
         Botan::BER_Decoder(in).decode(str, Botan::UTF8_STRING).verify_end();
         m_contents = str.value();
         }

   private:
      std::string m_contents;
   };

Test::Result test_custom_dn_attr(const Botan::Private_Key& ca_key,
                                  const std::string& sig_algo,
                                  const std::string& sig_padding = "",
                                  const std::string& hash_fn = "SHA-256")
   {
   Test::Result result("X509 Custom DN");

   /* Create the self-signed cert */
   Botan::X509_Certificate ca_cert =
      Botan::X509::create_self_signed_cert(ca_opts(sig_padding), ca_key, hash_fn, Test::rng());

   /* Create the CA object */
   Botan::X509_CA ca(ca_cert, ca_key, {{"padding",sig_padding}}, hash_fn, Test::rng());

   std::unique_ptr<Botan::Private_Key> user_key(make_a_private_key(sig_algo));

   Botan::X509_DN subject_dn;

   const Botan::OID attr1(Botan::OID("1.3.6.1.4.1.25258.9.1.1"));
   const Botan::OID attr2(Botan::OID("1.3.6.1.4.1.25258.9.1.2"));
   const Botan::ASN1_String val1("Custom Attr 1", Botan::PRINTABLE_STRING);
   const Botan::ASN1_String val2("12345", Botan::UTF8_STRING);

   subject_dn.add_attribute(attr1, val1);
   subject_dn.add_attribute(attr2, val2);

   Botan::Extensions extensions;

   Botan::PKCS10_Request req =
      Botan::PKCS10_Request::create(*user_key,
                                    subject_dn,
                                    extensions,
                                    hash_fn,
                                    Test::rng(),
                                    sig_padding);

   Botan::X509_DN req_dn = req.subject_dn();

   result.test_eq("Expected number of DN entries", req_dn.dn_info().size(), 2);

   Botan::ASN1_String req_val1 = req_dn.get_first_attribute(attr1);
   Botan::ASN1_String req_val2 = req_dn.get_first_attribute(attr2);
   result.confirm("Attr1 matches encoded", req_val1 == val1);
   result.confirm("Attr2 matches encoded", req_val2 == val2);
   result.confirm("Attr1 tag matches encoded", req_val1.tagging() == val1.tagging());
   result.confirm("Attr2 tag matches encoded", req_val2.tagging() == val2.tagging());

   Botan::X509_Time not_before("100301123001Z", Botan::UTC_TIME);
   Botan::X509_Time not_after("300301123001Z", Botan::UTC_TIME);

   auto cert = ca.sign_request(req, Test::rng(), not_before, not_after);

   Botan::X509_DN cert_dn = cert.subject_dn();

   result.test_eq("Expected number of DN entries", cert_dn.dn_info().size(), 2);

   Botan::ASN1_String cert_val1 = cert_dn.get_first_attribute(attr1);
   Botan::ASN1_String cert_val2 = cert_dn.get_first_attribute(attr2);
   result.confirm("Attr1 matches encoded", cert_val1 == val1);
   result.confirm("Attr2 matches encoded", cert_val2 == val2);
   result.confirm("Attr1 tag matches encoded", cert_val1.tagging() == val1.tagging());
   result.confirm("Attr2 tag matches encoded", cert_val2.tagging() == val2.tagging());

   return result;
   }


Test::Result test_x509_extensions(const Botan::Private_Key& ca_key,
                                  const std::string& sig_algo,
                                  const std::string& sig_padding = "",
                                  const std::string& hash_fn = "SHA-256")
   {
   using Botan::Key_Constraints;

   Test::Result result("X509 Extensions");

   /* Create the self-signed cert */
   Botan::X509_Certificate ca_cert =
      Botan::X509::create_self_signed_cert(ca_opts(sig_padding), ca_key, hash_fn, Test::rng());

   /* Create the CA object */
   Botan::X509_CA ca(ca_cert, ca_key, {{"padding",sig_padding}}, hash_fn, Test::rng());

   std::unique_ptr<Botan::Private_Key> user_key(make_a_private_key(sig_algo));

   Botan::X509_Cert_Options opts("Test User 1/US/Botan Project/Testing");
   opts.constraints = Key_Constraints::DIGITAL_SIGNATURE;

   // include a custom extension in the request
   Botan::Extensions req_extensions;
   const Botan::OID oid("1.2.3.4.5.6.7.8.9.1");
   const Botan::OID ku_oid = Botan::OID::from_string("X509v3.KeyUsage");
   req_extensions.add(new String_Extension("AAAAAAAAAAAAAABCDEF"), false);
   opts.extensions = req_extensions;
   opts.set_padding_scheme(sig_padding);

   /* Create a self-signed certificate */
   const Botan::X509_Certificate self_signed_cert = Botan::X509::create_self_signed_cert(
            opts, *user_key, hash_fn, Test::rng());

   result.confirm("Extensions::extension_set true for Key_Usage", self_signed_cert.v3_extensions().extension_set(ku_oid));

   // check if known Key_Usage extension is present in self-signed cert
   auto key_usage_ext = self_signed_cert.v3_extensions().get(ku_oid);
   if(result.confirm("Key_Usage extension present in self-signed certificate", key_usage_ext != nullptr))
      {
      result.confirm("Key_Usage extension value matches in self-signed certificate",
                     dynamic_cast<Botan::Cert_Extension::Key_Usage&>(*key_usage_ext).get_constraints() == opts.constraints);
      }

   // check if custom extension is present in self-signed cert
   auto string_ext = self_signed_cert.v3_extensions().get_raw<String_Extension>(oid);
   if(result.confirm("Custom extension present in self-signed certificate", string_ext != nullptr))
      {
      result.test_eq("Custom extension value matches in self-signed certificate", string_ext->value(), "AAAAAAAAAAAAAABCDEF");
      }


   const Botan::PKCS10_Request user_req = Botan::X509::create_cert_req(opts, *user_key, hash_fn, Test::rng());

   /* Create a CA-signed certificate */
   const Botan::X509_Certificate ca_signed_cert =
      ca.sign_request(user_req, Test::rng(),
                      from_date(-1, 01, 01),
                      from_date(2, 01, 01));

   // check if known Key_Usage extension is present in CA-signed cert
   result.confirm("Extensions::extension_set true for Key_Usage", ca_signed_cert.v3_extensions().extension_set(ku_oid));

   key_usage_ext = ca_signed_cert.v3_extensions().get(ku_oid);
   if(result.confirm("Key_Usage extension present in CA-signed certificate", key_usage_ext != nullptr))
      {
      result.confirm("Key_Usage extension value matches in user certificate",
                     dynamic_cast<Botan::Cert_Extension::Key_Usage&>(*key_usage_ext).get_constraints() == Botan::DIGITAL_SIGNATURE);
      }

   // check if custom extension is present in CA-signed cert
   result.confirm("Extensions::extension_set true for String_Extension", ca_signed_cert.v3_extensions().extension_set(oid));
   string_ext = ca_signed_cert.v3_extensions().get_raw<String_Extension>(oid);
   if(result.confirm("Custom extension present in CA-signed certificate", string_ext != nullptr))
      {
      result.test_eq("Custom extension value matches in CA-signed certificate", string_ext->value(), "AAAAAAAAAAAAAABCDEF");
      }

   return result;
   }

Test::Result test_hashes(const Botan::Private_Key& key,
                         const std::string& hash_fn = "SHA-256")
   {
   Test::Result result("X509 Hashes");

   struct TestData
      {
      const std::string issuer, subject, issuer_hash, subject_hash;
      } const cases[]
      {
         {
         "",
         "",
         "E4F60D0AA6D7F3D3B6A6494B1C861B99F649C6F9EC51ABAF201B20F297327C95",
         "E4F60D0AA6D7F3D3B6A6494B1C861B99F649C6F9EC51ABAF201B20F297327C95"
         },
         {
         "a",
         "b",
         "BC2E013472F39AC579964880E422737C82BA812CB8BC2FD17E013060D71E6E19",
         "5E31CFAA3FAFB1A5BA296A0D2BAB9CA44D7936E9BF0BBC54637D0C53DBC4A432"
         },
         {
         "A",
         "B",
         "4B3206201C4BC9B6CD6C36532A97687DF9238155D99ADB60C66BF2B2220643D8",
         "FFF635A52A16618B4A0E9CD26B5E5A2FA573D343C051E6DE8B0811B1ACC89B86"
         },
         {
         "Test Issuer/US/Botan Project/Testing",
         "Test Subject/US/Botan Project/Testing",
         "ACB4F373004A56A983A23EB8F60FA4706312B5DB90FD978574FE7ACC84E093A5",
         "87039231C2205B74B6F1F3830A66272C0B41F71894B03AC3150221766D95267B",
         },
         {
         "Test Subject/US/Botan Project/Testing",
         "Test Issuer/US/Botan Project/Testing",
         "87039231C2205B74B6F1F3830A66272C0B41F71894B03AC3150221766D95267B",
         "ACB4F373004A56A983A23EB8F60FA4706312B5DB90FD978574FE7ACC84E093A5",
         }
      };

   for(const auto& a : cases)
      {
      Botan::X509_Cert_Options opts{a.issuer};
      opts.CA_key();

      const Botan::X509_Certificate issuer_cert =
         Botan::X509::create_self_signed_cert(opts, key, hash_fn, Test::rng());

      result.test_eq(a.issuer, Botan::hex_encode(issuer_cert.raw_issuer_dn_sha256()), a.issuer_hash);
      result.test_eq(a.issuer, Botan::hex_encode(issuer_cert.raw_subject_dn_sha256()), a.issuer_hash);

      const Botan::X509_CA ca(issuer_cert, key, hash_fn, Test::rng());
      const Botan::PKCS10_Request req =
         Botan::X509::create_cert_req(a.subject, key, hash_fn, Test::rng());
      const Botan::X509_Certificate subject_cert =
         ca.sign_request(req, Test::rng(), from_date(-1, 01, 01), from_date(2, 01, 01));

      result.test_eq(a.subject, Botan::hex_encode(subject_cert.raw_issuer_dn_sha256()), a.issuer_hash);
      result.test_eq(a.subject, Botan::hex_encode(subject_cert.raw_subject_dn_sha256()), a.subject_hash);
      }
   return result;
   }

class X509_Cert_Unit_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         const std::string sig_algos[] { "RSA", "DSA", "ECDSA", "ECGDSA", "ECKCDSA", "GOST-34.10", "Ed25519" };

         for(const std::string& algo : sig_algos)
            {
#if !defined(BOTAN_HAS_EMSA_PKCS1)
            if(algo == "RSA")
               continue;
#endif

#if !defined(BOTAN_HAS_EMSA1)
            if(algo != "RSA" && algo != "Ed25519")
               continue;
#endif

            std::unique_ptr<Botan::Private_Key> key = make_a_private_key(algo);

            if(key == nullptr)
               continue;

            results.push_back(test_hashes(*key));
            results.push_back(test_valid_constraints(*key, algo));

            Test::Result usage_result("X509 Usage");
            try
               {
               usage_result.merge(test_usage(*key, algo));
               }
            catch(std::exception& e)
               {
               usage_result.test_failure("test_usage " + algo, e.what());
               }
            results.push_back(usage_result);

            for(auto padding_scheme : Botan::get_sig_paddings(algo))
               {
               Test::Result cert_result("X509 Unit");
               try
                  {
                  cert_result.merge(test_x509_cert(*key, algo, padding_scheme));
                  }
               catch(std::exception& e)
                  {
                  cert_result.test_failure("test_x509_cert " + algo, e.what());
                  }
               results.push_back(cert_result);

               Test::Result pkcs10_result("PKCS10 extensions");
               try
                  {
                  pkcs10_result.merge(test_pkcs10_ext(*key, padding_scheme));
                  }
               catch(std::exception& e)
                  {
                  pkcs10_result.test_failure("test_pkcs10_ext " + algo, e.what());
                  }
               results.push_back(pkcs10_result);

               Test::Result self_issued_result("X509 Self Issued");
               try
                  {
                  self_issued_result.merge(test_self_issued(*key, algo, padding_scheme));
                  }
               catch(std::exception& e)
                  {
                  self_issued_result.test_failure("test_self_issued " + algo, e.what());
                  }
               results.push_back(self_issued_result);

               Test::Result extensions_result("X509 Extensions");
               try
                  {
                  extensions_result.merge(test_x509_extensions(*key, algo, padding_scheme));
                  }
               catch(std::exception& e)
                  {
                  extensions_result.test_failure("test_extensions " + algo, e.what());
                  }
               results.push_back(extensions_result);

               Test::Result custom_dn_result("X509 Custom DN");
               try
                  {
                  custom_dn_result.merge(test_custom_dn_attr(*key, algo, padding_scheme));
                  }
               catch(std::exception& e)
                  {
                  custom_dn_result.test_failure("test_custom_dn_attr " + algo, e.what());
                  }
               results.push_back(custom_dn_result);
               }

            }

         /*
         These are algos which cannot sign but can be included in certs
         */
         const std::vector<std::string> enc_algos = { "DH", "ECDH", "ElGamal" };

         for(std::string algo : enc_algos)
            {
            std::unique_ptr<Botan::Private_Key> key = make_a_private_key(algo);

            if(key)
               {
               results.push_back(test_valid_constraints(*key, algo));
               }
            }


#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM) && defined(BOTAN_HAS_EMSA_PKCS1) && defined(BOTAN_HAS_EMSA_PSSR) && defined(BOTAN_HAS_RSA)
         Test::Result pad_config_result("X509 Padding Config");
         try
            {
            pad_config_result.merge(test_padding_config());
            }
         catch(const std::exception& e)
            {
            pad_config_result.test_failure("test_padding_config", e.what());
            }
         results.push_back(pad_config_result);
#endif

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
         results.push_back(test_x509_utf8());
         results.push_back(test_x509_bmpstring());
         results.push_back(test_crl_dn_name());
         results.push_back(test_x509_decode_list());
         results.push_back(test_rsa_oaep());
         results.push_back(test_x509_authority_info_access_extension());
         results.push_back(test_verify_gost2012_cert());
#endif

         results.push_back(test_x509_extension());
         results.push_back(test_x509_dates());
         results.push_back(test_cert_status_strings());
         results.push_back(test_x509_uninit());

         return results;
         }
   };

BOTAN_REGISTER_TEST("x509", "x509_unit", X509_Cert_Unit_Tests);

#endif

}

}
