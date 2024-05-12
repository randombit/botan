/*
* (C) 2016 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "botan/types.h"

#if defined(BOTAN_HAS_OCSP)
   #include <botan/certstor.h>
   #include <botan/ocsp.h>
   #include <botan/x509path.h>
   #include <botan/internal/calendar.h>
   #include <fstream>
#endif

#include "tests.h"

namespace Botan_Tests {

#if defined(BOTAN_HAS_OCSP) && defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EMSA_PKCS1) && \
   defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

class OCSP_Tests final : public Test {
   private:
      static Botan::X509_Certificate load_test_X509_cert(const std::string& path) {
         return Botan::X509_Certificate(Test::data_file(path));
      }

      static Botan::OCSP::Response load_test_OCSP_resp(const std::string& path) {
         return Botan::OCSP::Response(Test::read_binary_data_file(path));
      }

      static Test::Result test_response_parsing() {
         Test::Result result("OCSP response parsing");

         // Simple parsing tests
         const std::vector<std::string> ocsp_input_paths = {
            "x509/ocsp/resp1.der", "x509/ocsp/resp2.der", "x509/ocsp/resp3.der"};

         for(const std::string& ocsp_input_path : ocsp_input_paths) {
            try {
               Botan::OCSP::Response resp(Test::read_binary_data_file(ocsp_input_path));
               result.confirm("parsing was successful", resp.status() == Botan::OCSP::Response_Status_Code::Successful);
               result.test_success("Parsed input " + ocsp_input_path);
            } catch(Botan::Exception& e) {
               result.test_failure("Parsing failed", e.what());
            }
         }

         Botan::OCSP::Response resp(
            Test::read_binary_data_file("x509/ocsp/patrickschmidt_ocsp_try_later_wrong_sig.der"));
         result.confirm("parsing exposes correct status code",
                        resp.status() == Botan::OCSP::Response_Status_Code::Try_Later);

         return result;
      }

      static Test::Result test_response_certificate_access() {
         Test::Result result("OCSP response certificate access");

         try {
            Botan::OCSP::Response resp1(Test::read_binary_data_file("x509/ocsp/resp1.der"));
            const auto& certs1 = resp1.certificates();
            if(result.test_eq("Expected count of certificates", certs1.size(), 1)) {
               const auto& cert = certs1.front();
               const Botan::X509_DN expected_dn(
                  {std::make_pair("X520.CommonName", "Symantec Class 3 EV SSL CA - G3 OCSP Responder")});
               const bool matches = cert.subject_dn() == expected_dn;
               result.test_eq("CN matches expected", matches, true);
            }

            Botan::OCSP::Response resp2(Test::read_binary_data_file("x509/ocsp/resp2.der"));
            const auto& certs2 = resp2.certificates();
            result.test_eq("Expect no certificates", certs2.size(), 0);
         } catch(Botan::Exception& e) {
            result.test_failure("Parsing failed", e.what());
         }

         return result;
      }

      static Test::Result test_request_encoding() {
         Test::Result result("OCSP request encoding");

         const Botan::X509_Certificate end_entity(Test::data_file("x509/ocsp/gmail.pem"));
         const Botan::X509_Certificate issuer(Test::data_file("x509/ocsp/google_g2.pem"));

         try {
            const Botan::OCSP::Request bogus(end_entity, issuer);
            result.test_failure("Bad arguments (swapped end entity, issuer) accepted");
         } catch(Botan::Invalid_Argument&) {
            result.test_success("Bad arguments rejected");
         }

         const std::string expected_request =
            "ME4wTKADAgEAMEUwQzBBMAkGBSsOAwIaBQAEFPLgavmFih2NcJtJGSN6qbUaKH5kBBRK3QYWG7z2aLV29YG2u2IaulqBLwIIQkg+DF+RYMY=";

         const Botan::OCSP::Request req1(issuer, end_entity);
         result.test_eq("Encoded OCSP request", req1.base64_encode(), expected_request);

         const Botan::OCSP::Request req2(issuer, BigInt::from_bytes(end_entity.serial_number()));
         result.test_eq("Encoded OCSP request", req2.base64_encode(), expected_request);

         return result;
      }

      static Test::Result test_response_find_signing_certificate() {
         Test::Result result("OCSP response finding signature certificates");

         const std::optional<Botan::X509_Certificate> nullopt_cert;

         // OCSP response is signed by the issuing CA itself
         auto randombit_ocsp = load_test_OCSP_resp("x509/ocsp/randombit_ocsp.der");
         auto randombit_ca = load_test_X509_cert("x509/ocsp/letsencrypt.pem");

         // OCSP response is signed by an authorized responder certificate
         // issued by the issuing CA and embedded in the response
         auto bdr_ocsp = load_test_OCSP_resp("x509/ocsp/bdr-ocsp-resp.der");
         auto bdr_responder = load_test_X509_cert("x509/ocsp/bdr-ocsp-responder.pem");
         auto bdr_ca = load_test_X509_cert("x509/ocsp/bdr-int.pem");

         // Dummy OCSP response is not signed at all
         auto dummy_ocsp = Botan::OCSP::Response(Botan::Certificate_Status_Code::OCSP_SERVER_NOT_AVAILABLE);

         // OCSP response is signed by 3rd party responder certificate that is
         // not included in the OCSP response itself
         // See `src/scripts/randombit_ocsp_forger.sh` for a helper script to recreate those.
         auto randombit_alt_resp_ocsp = load_test_OCSP_resp("x509/ocsp/randombit_ocsp_forged_valid_nocerts.der");
         auto randombit_alt_resp_cert = load_test_X509_cert("x509/ocsp/randombit_ocsp_forged_responder.pem");

         result.test_is_eq("Dummy has no signing certificate",
                           dummy_ocsp.find_signing_certificate(Botan::X509_Certificate()),
                           nullopt_cert);

         result.test_is_eq("CA is returned as signing certificate",
                           randombit_ocsp.find_signing_certificate(randombit_ca),
                           std::optional(randombit_ca));
         result.test_is_eq("No signer certificate is returned when signer couldn't be determined",
                           randombit_ocsp.find_signing_certificate(bdr_ca),
                           nullopt_cert);

         result.test_is_eq("Delegated responder certificate is returned for further validation",
                           bdr_ocsp.find_signing_certificate(bdr_ca),
                           std::optional(bdr_responder));

         result.test_is_eq("Delegated responder without stapled certs does not find signer without user-provided certs",
                           randombit_alt_resp_ocsp.find_signing_certificate(randombit_ca),
                           nullopt_cert);
         auto trusted_responders = std::make_unique<Botan::Certificate_Store_In_Memory>(randombit_alt_resp_cert);
         result.test_is_eq("Delegated responder returns user-provided cert",
                           randombit_alt_resp_ocsp.find_signing_certificate(randombit_ca, trusted_responders.get()),
                           std::optional(randombit_alt_resp_cert));

         return result;
      }

      static Test::Result test_response_verification_with_next_update_without_max_age() {
         Test::Result result("OCSP request check with next_update w/o max_age");

         auto ee = load_test_X509_cert("x509/ocsp/randombit.pem");
         auto ca = load_test_X509_cert("x509/ocsp/letsencrypt.pem");
         auto trust_root = load_test_X509_cert("x509/ocsp/geotrust.pem");

         const std::vector<Botan::X509_Certificate> cert_path = {ee, ca, trust_root};

         auto ocsp = load_test_OCSP_resp("x509/ocsp/randombit_ocsp.der");

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         auto check_ocsp = [&](const std::chrono::system_clock::time_point valid_time,
                               const Botan::Certificate_Status_Code expected) {
            const auto ocsp_status = Botan::PKIX::check_ocsp(
               cert_path, {ocsp}, {&certstore}, valid_time, Botan::Path_Validation_Restrictions());

            return result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1) &&
                   result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1) &&
                   result.confirm(std::string("Status: '") + Botan::to_string(expected) + "'",
                                  ocsp_status[0].contains(expected));
         };

         check_ocsp(Botan::calendar_point(2016, 11, 11, 12, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_NOT_YET_VALID);
         check_ocsp(Botan::calendar_point(2016, 11, 18, 12, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD);
         check_ocsp(Botan::calendar_point(2016, 11, 20, 8, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD);
         check_ocsp(Botan::calendar_point(2016, 11, 28, 8, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_HAS_EXPIRED);

         return result;
      }

      static Test::Result test_response_verification_with_next_update_with_max_age() {
         Test::Result result("OCSP request check with next_update with max_age");

         auto ee = load_test_X509_cert("x509/ocsp/randombit.pem");
         auto ca = load_test_X509_cert("x509/ocsp/letsencrypt.pem");
         auto trust_root = load_test_X509_cert("x509/ocsp/geotrust.pem");

         const std::vector<Botan::X509_Certificate> cert_path = {ee, ca, trust_root};

         auto ocsp = load_test_OCSP_resp("x509/ocsp/randombit_ocsp.der");

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         // Some arbitrary time within the validity period of the test certs
         const auto max_age = std::chrono::minutes(59);

         auto check_ocsp = [&](const std::chrono::system_clock::time_point valid_time,
                               const Botan::Certificate_Status_Code expected) {
            Botan::Path_Validation_Restrictions pvr(false, 110, false, max_age);
            const auto ocsp_status = Botan::PKIX::check_ocsp(cert_path, {ocsp}, {&certstore}, valid_time, pvr);

            return result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1) &&
                   result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1) &&
                   result.confirm(std::string("Status: '") + Botan::to_string(expected) + "'",
                                  ocsp_status[0].contains(expected));
         };

         check_ocsp(Botan::calendar_point(2016, 11, 11, 12, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_NOT_YET_VALID);
         check_ocsp(Botan::calendar_point(2016, 11, 18, 12, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD);
         check_ocsp(Botan::calendar_point(2016, 11, 20, 8, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD);
         check_ocsp(Botan::calendar_point(2016, 11, 28, 8, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_HAS_EXPIRED);

         return result;
      }

      static Test::Result test_response_verification_without_next_update_with_max_age() {
         Test::Result result("OCSP request check w/o next_update with max_age");

         auto ee = load_test_X509_cert("x509/ocsp/patrickschmidt.pem");
         auto ca = load_test_X509_cert("x509/ocsp/bdrive_encryption.pem");
         auto trust_root = load_test_X509_cert("x509/ocsp/bdrive_root.pem");

         const std::vector<Botan::X509_Certificate> cert_path = {ee, ca, trust_root};

         auto ocsp = load_test_OCSP_resp("x509/ocsp/patrickschmidt_ocsp.der");

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         // Some arbitrary time within the validity period of the test certs
         const auto max_age = std::chrono::minutes(59);

         auto check_ocsp = [&](const std::chrono::system_clock::time_point valid_time,
                               const Botan::Certificate_Status_Code expected) {
            Botan::Path_Validation_Restrictions pvr(false, 110, false, max_age);
            const auto ocsp_status = Botan::PKIX::check_ocsp(cert_path, {ocsp}, {&certstore}, valid_time, pvr);

            return result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1) &&
                   result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1) &&
                   result.confirm(std::string("Status: '") + Botan::to_string(expected) + "'",
                                  ocsp_status[0].contains(expected));
         };

         check_ocsp(Botan::calendar_point(2019, 5, 28, 7, 0, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_NOT_YET_VALID);
         check_ocsp(Botan::calendar_point(2019, 5, 28, 7, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD);
         check_ocsp(Botan::calendar_point(2019, 5, 28, 8, 0, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_IS_TOO_OLD);

         return result;
      }

      static Test::Result test_response_verification_without_next_update_without_max_age() {
         Test::Result result("OCSP request check w/o next_update w/o max_age");

         auto ee = load_test_X509_cert("x509/ocsp/patrickschmidt.pem");
         auto ca = load_test_X509_cert("x509/ocsp/bdrive_encryption.pem");
         auto trust_root = load_test_X509_cert("x509/ocsp/bdrive_root.pem");

         const std::vector<Botan::X509_Certificate> cert_path = {ee, ca, trust_root};

         auto ocsp = load_test_OCSP_resp("x509/ocsp/patrickschmidt_ocsp.der");

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         auto check_ocsp = [&](const std::chrono::system_clock::time_point valid_time,
                               const Botan::Certificate_Status_Code expected) {
            const auto ocsp_status = Botan::PKIX::check_ocsp(
               cert_path, {ocsp}, {&certstore}, valid_time, Botan::Path_Validation_Restrictions());

            return result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1) &&
                   result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1) &&
                   result.confirm(std::string("Status: '") + Botan::to_string(expected) + "'",
                                  ocsp_status[0].contains(expected));
         };

         check_ocsp(Botan::calendar_point(2019, 5, 28, 7, 0, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_NOT_YET_VALID);
         check_ocsp(Botan::calendar_point(2019, 5, 28, 7, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD);
         check_ocsp(Botan::calendar_point(2019, 5, 28, 8, 0, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD);

         return result;
      }

      static Test::Result test_response_verification_softfail() {
         Test::Result result("OCSP request softfail check");

         auto ee = load_test_X509_cert("x509/ocsp/randombit.pem");
         auto ca = load_test_X509_cert("x509/ocsp/letsencrypt.pem");
         auto trust_root = load_test_X509_cert("x509/ocsp/geotrust.pem");

         const std::vector<Botan::X509_Certificate> cert_path = {ee, ca, trust_root};

         Botan::OCSP::Response ocsp(Botan::Certificate_Status_Code::OCSP_NO_REVOCATION_URL);

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         // Some arbitrary time within the validity period of the test certs
         const auto valid_time = Botan::calendar_point(2016, 11, 20, 8, 30, 0).to_std_timepoint();
         const auto ocsp_status =
            Botan::PKIX::check_ocsp(cert_path, {ocsp}, {&certstore}, valid_time, Botan::Path_Validation_Restrictions());

         if(result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1)) {
            if(result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1)) {
               result.test_gt(
                  "Status warning", ocsp_status[0].count(Botan::Certificate_Status_Code::OCSP_NO_REVOCATION_URL), 0);
            }
         }

         return result;
      }

   #if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)
      static Test::Result test_online_request() {
         Test::Result result("OCSP online check");

         auto cert = load_test_X509_cert("x509/ocsp/digicert-ecdsa-int.pem");
         auto trust_root = load_test_X509_cert("x509/ocsp/digicert-root.pem");

         const std::vector<Botan::X509_Certificate> cert_path = {cert, trust_root};

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         const auto ocsp_timeout = std::chrono::milliseconds(3000);
         const auto now = std::chrono::system_clock::now();
         auto ocsp_status = Botan::PKIX::check_ocsp_online(
            cert_path, {&certstore}, now, ocsp_timeout, Botan::Path_Validation_Restrictions());

         if(result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1)) {
            if(result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1)) {
               const bool status_good = ocsp_status[0].contains(Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD);
               const bool server_not_found =
                  ocsp_status[0].contains(Botan::Certificate_Status_Code::OCSP_SERVER_NOT_AVAILABLE);
               result.confirm("Expected status", status_good || server_not_found);
            }
         }

         return result;
      }
   #endif

      static Test::Result test_response_verification_with_additionally_trusted_responder() {
         Test::Result result("OCSP response with user-defined (additional) responder certificate");

         // OCSP response is signed by 3rd party responder certificate that is
         // not included in the OCSP response itself
         // See `src/scripts/randombit_ocsp_forger.sh` for a helper script to recreate those.
         auto ocsp = load_test_OCSP_resp("x509/ocsp/randombit_ocsp_forged_valid_nocerts.der");
         auto responder = load_test_X509_cert("x509/ocsp/randombit_ocsp_forged_responder.pem");
         auto ca = load_test_X509_cert("x509/ocsp/letsencrypt.pem");

         std::optional<Botan::X509_Certificate> nullopt_cert;

         Botan::Certificate_Store_In_Memory trusted_responders;

         // without providing the 3rd party responder certificate no issuer will be found
         result.test_is_eq("cannot find signing certificate without trusted responders",
                           ocsp.find_signing_certificate(ca),
                           nullopt_cert);
         result.test_is_eq("cannot find signing certificate without additional help",
                           ocsp.find_signing_certificate(ca, &trusted_responders),
                           nullopt_cert);

         // add the 3rd party responder certificate to the list of trusted OCSP responder certs
         // to find the issuer certificate of this response
         trusted_responders.add_certificate(responder);
         result.test_is_eq("the responder certificate is returned when it is trusted",
                           ocsp.find_signing_certificate(ca, &trusted_responders),
                           std::optional(responder));

         result.test_is_eq("the responder's signature checks out",
                           ocsp.verify_signature(responder),
                           Botan::Certificate_Status_Code::OCSP_SIGNATURE_OK);

         return result;
      }

      static Test::Result test_responder_cert_with_nocheck_extension() {
         Test::Result result("BDr's OCSP response contains certificate featuring NoCheck extension");

         auto ocsp = load_test_OCSP_resp("x509/ocsp/bdr-ocsp-resp.der");
         const bool contains_cert_with_nocheck =
            std::find_if(ocsp.certificates().cbegin(), ocsp.certificates().cend(), [](const auto& cert) {
               return cert.v3_extensions().extension_set(Botan::OID::from_string("PKIX.OCSP.NoCheck"));
            }) != ocsp.certificates().end();

         result.confirm("Contains NoCheck extension", contains_cert_with_nocheck);

         return result;
      }

   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_request_encoding());
         results.push_back(test_response_parsing());
         results.push_back(test_response_certificate_access());
         results.push_back(test_response_find_signing_certificate());
         results.push_back(test_response_verification_with_next_update_without_max_age());
         results.push_back(test_response_verification_with_next_update_with_max_age());
         results.push_back(test_response_verification_without_next_update_with_max_age());
         results.push_back(test_response_verification_without_next_update_without_max_age());
         results.push_back(test_response_verification_softfail());
         results.push_back(test_response_verification_with_additionally_trusted_responder());
         results.push_back(test_responder_cert_with_nocheck_extension());

   #if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)
         if(Test::options().run_online_tests()) {
            results.push_back(test_online_request());
         }
   #endif

         return results;
      }
};

BOTAN_REGISTER_TEST("x509", "ocsp", OCSP_Tests);

#endif

}  // namespace Botan_Tests
