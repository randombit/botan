/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_OCSP)
   #include <botan/ocsp.h>
   #include <botan/x509path.h>
   #include <botan/certstor.h>
   #include <botan/calendar.h>
   #include <fstream>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_OCSP) && defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EMSA_PKCS1) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

class OCSP_Tests final : public Test
   {
   private:
      std::shared_ptr<const Botan::X509_Certificate> load_test_X509_cert(const std::string& path)
         {
         return std::make_shared<const Botan::X509_Certificate>(Test::data_file(path));
         }

      std::shared_ptr<const Botan::OCSP::Response> load_test_OCSP_resp(const std::string& path)
         {
         return std::make_shared<const Botan::OCSP::Response>(Test::read_binary_data_file(path));
         }

      Test::Result test_response_parsing()
         {
         Test::Result result("OCSP response parsing");

         // Simple parsing tests
         const std::vector<std::string> ocsp_input_paths =
            {
            "x509/ocsp/resp1.der",
            "x509/ocsp/resp2.der",
            "x509/ocsp/resp3.der"
            };

         for(std::string ocsp_input_path : ocsp_input_paths)
            {
            try
               {
               Botan::OCSP::Response resp(Test::read_binary_data_file(ocsp_input_path));
               result.confirm("parsing was successful", resp.status() == Botan::OCSP::Response_Status_Code::Successful);
               result.test_success("Parsed input " + ocsp_input_path);
               }
            catch(Botan::Exception& e)
               {
               result.test_failure("Parsing failed", e.what());
               }
            }

         Botan::OCSP::Response resp(Test::read_binary_data_file("x509/ocsp/patrickschmidt_ocsp_try_later_wrong_sig.der"));
         result.confirm("parsing exposes correct status code", resp.status() == Botan::OCSP::Response_Status_Code::Try_Later);

         return result;
         }

      Test::Result test_response_certificate_access()
         {
         Test::Result result("OCSP response certificate access");

         try
            {
            Botan::OCSP::Response resp1(Test::read_binary_data_file("x509/ocsp/resp1.der"));
            const auto &certs1 = resp1.certificates();
            if(result.test_eq("Expected count of certificates", certs1.size(), 1))
               {
               const auto cert = certs1.front();
               const Botan::X509_DN expected_dn({std::make_pair(
                  "X520.CommonName",
                  "Symantec Class 3 EV SSL CA - G3 OCSP Responder")});
               const bool matches = cert.subject_dn() == expected_dn;
               result.test_eq("CN matches expected", matches, true);
               }

            Botan::OCSP::Response resp2(Test::read_binary_data_file("x509/ocsp/resp2.der"));
            const auto &certs2 = resp2.certificates();
            result.test_eq("Expect no certificates", certs2.size(), 0);
            }
         catch(Botan::Exception& e)
            {
            result.test_failure("Parsing failed", e.what());
            }

         return result;
         }

      Test::Result test_request_encoding()
         {
         Test::Result result("OCSP request encoding");

         const Botan::X509_Certificate end_entity(Test::data_file("x509/ocsp/gmail.pem"));
         const Botan::X509_Certificate issuer(Test::data_file("x509/ocsp/google_g2.pem"));

         try
            {
            const Botan::OCSP::Request bogus(end_entity, issuer);
            result.test_failure("Bad arguments (swapped end entity, issuer) accepted");
            }
         catch(Botan::Invalid_Argument&)
            {
            result.test_success("Bad arguments rejected");
            }


         const std::string expected_request =
            "ME4wTKADAgEAMEUwQzBBMAkGBSsOAwIaBQAEFPLgavmFih2NcJtJGSN6qbUaKH5kBBRK3QYWG7z2aLV29YG2u2IaulqBLwIIQkg+DF+RYMY=";

         const Botan::OCSP::Request req1(issuer, end_entity);
         result.test_eq("Encoded OCSP request",
                        req1.base64_encode(),
                        expected_request);

         const Botan::OCSP::Request req2(issuer, BigInt::decode(end_entity.serial_number()));
         result.test_eq("Encoded OCSP request",
                        req2.base64_encode(),
                        expected_request);

         return result;
         }

      Test::Result test_response_verification_with_next_update_without_max_age()
         {
         Test::Result result("OCSP request check with next_update w/o max_age");

         std::shared_ptr<const Botan::X509_Certificate> ee = load_test_X509_cert("x509/ocsp/randombit.pem");
         std::shared_ptr<const Botan::X509_Certificate> ca = load_test_X509_cert("x509/ocsp/letsencrypt.pem");
         std::shared_ptr<const Botan::X509_Certificate> trust_root = load_test_X509_cert("x509/ocsp/geotrust.pem");

         const std::vector<std::shared_ptr<const Botan::X509_Certificate>> cert_path = { ee, ca, trust_root };

         std::shared_ptr<const Botan::OCSP::Response> ocsp = load_test_OCSP_resp("x509/ocsp/randombit_ocsp.der");

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         auto check_ocsp = [&](const std::chrono::system_clock::time_point valid_time,
                               const Botan::Certificate_Status_Code expected)
            {
            const auto ocsp_status = Botan::PKIX::check_ocsp(cert_path, { ocsp }, { &certstore }, valid_time);

            return result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1) &&
                   result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1) &&
                   result.confirm(std::string("Status: '") + Botan::to_string(expected) + "'",
                                  ocsp_status[0].count(expected) > 0);
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

      Test::Result test_response_verification_with_next_update_with_max_age()
         {
         Test::Result result("OCSP request check with next_update with max_age");

         std::shared_ptr<const Botan::X509_Certificate> ee = load_test_X509_cert("x509/ocsp/randombit.pem");
         std::shared_ptr<const Botan::X509_Certificate> ca = load_test_X509_cert("x509/ocsp/letsencrypt.pem");
         std::shared_ptr<const Botan::X509_Certificate> trust_root = load_test_X509_cert("x509/ocsp/geotrust.pem");

         const std::vector<std::shared_ptr<const Botan::X509_Certificate>> cert_path = { ee, ca, trust_root };

         std::shared_ptr<const Botan::OCSP::Response> ocsp = load_test_OCSP_resp("x509/ocsp/randombit_ocsp.der");

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         // Some arbitrary time within the validity period of the test certs
         const auto max_age = std::chrono::minutes(59);

         auto check_ocsp = [&](const std::chrono::system_clock::time_point valid_time,
                               const Botan::Certificate_Status_Code expected)
            {
            const auto ocsp_status = Botan::PKIX::check_ocsp(cert_path, { ocsp }, { &certstore }, valid_time, max_age);

            return result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1) &&
                   result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1) &&
                   result.confirm(std::string("Status: '") + Botan::to_string(expected) + "'",
                                  ocsp_status[0].count(expected) > 0);
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

      Test::Result test_response_verification_without_next_update_with_max_age()
         {
         Test::Result result("OCSP request check w/o next_update with max_age");

         std::shared_ptr<const Botan::X509_Certificate> ee = load_test_X509_cert("x509/ocsp/patrickschmidt.pem");
         std::shared_ptr<const Botan::X509_Certificate> ca = load_test_X509_cert("x509/ocsp/bdrive_encryption.pem");
         std::shared_ptr<const Botan::X509_Certificate> trust_root = load_test_X509_cert("x509/ocsp/bdrive_root.pem");

         const std::vector<std::shared_ptr<const Botan::X509_Certificate>> cert_path = { ee, ca, trust_root };

         std::shared_ptr<const Botan::OCSP::Response> ocsp = load_test_OCSP_resp("x509/ocsp/patrickschmidt_ocsp.der");

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         // Some arbitrary time within the validity period of the test certs
         const auto max_age = std::chrono::minutes(59);

         auto check_ocsp = [&](const std::chrono::system_clock::time_point valid_time,
                               const Botan::Certificate_Status_Code expected)
            {
            const auto ocsp_status = Botan::PKIX::check_ocsp(cert_path, { ocsp }, { &certstore }, valid_time, max_age);

            return result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1) &&
                   result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1) &&
                   result.confirm(std::string("Status: '") + Botan::to_string(expected) + "'",
                                  ocsp_status[0].count(expected) > 0);
            };

         check_ocsp(Botan::calendar_point(2019, 5, 28, 7, 0, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_NOT_YET_VALID);
         check_ocsp(Botan::calendar_point(2019, 5, 28, 7, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD);
         check_ocsp(Botan::calendar_point(2019, 5, 28, 8, 0, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_IS_TOO_OLD);

         return result;
         }

      Test::Result test_response_verification_without_next_update_without_max_age()
         {
         Test::Result result("OCSP request check w/o next_update w/o max_age");

         std::shared_ptr<const Botan::X509_Certificate> ee = load_test_X509_cert("x509/ocsp/patrickschmidt.pem");
         std::shared_ptr<const Botan::X509_Certificate> ca = load_test_X509_cert("x509/ocsp/bdrive_encryption.pem");
         std::shared_ptr<const Botan::X509_Certificate> trust_root = load_test_X509_cert("x509/ocsp/bdrive_root.pem");

         const std::vector<std::shared_ptr<const Botan::X509_Certificate>> cert_path = { ee, ca, trust_root };

         std::shared_ptr<const Botan::OCSP::Response> ocsp = load_test_OCSP_resp("x509/ocsp/patrickschmidt_ocsp.der");

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         auto check_ocsp = [&](const std::chrono::system_clock::time_point valid_time,
                               const Botan::Certificate_Status_Code expected)
            {
            const auto ocsp_status = Botan::PKIX::check_ocsp(cert_path, { ocsp }, { &certstore }, valid_time);

            return result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1) &&
                   result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1) &&
                   result.confirm(std::string("Status: '") + Botan::to_string(expected) + "'",
                                  ocsp_status[0].count(expected) > 0);
            };

         check_ocsp(Botan::calendar_point(2019, 5, 28, 7, 0, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_NOT_YET_VALID);
         check_ocsp(Botan::calendar_point(2019, 5, 28, 7, 30, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD);
         check_ocsp(Botan::calendar_point(2019, 5, 28, 8, 0, 0).to_std_timepoint(),
                    Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD);

         return result;
         }

      Test::Result test_response_verification_softfail()
         {
         Test::Result result("OCSP request softfail check");

         std::shared_ptr<const Botan::X509_Certificate> ee = load_test_X509_cert("x509/ocsp/randombit.pem");
         std::shared_ptr<const Botan::X509_Certificate> ca = load_test_X509_cert("x509/ocsp/letsencrypt.pem");
         std::shared_ptr<const Botan::X509_Certificate> trust_root = load_test_X509_cert("x509/ocsp/geotrust.pem");

         const std::vector<std::shared_ptr<const Botan::X509_Certificate>> cert_path = { ee, ca, trust_root };

         std::shared_ptr<const Botan::OCSP::Response> ocsp =
            std::make_shared<const Botan::OCSP::Response>(Botan::Certificate_Status_Code::OCSP_NO_REVOCATION_URL);

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         // Some arbitrary time within the validity period of the test certs
         const auto valid_time = Botan::calendar_point(2016, 11, 20, 8, 30, 0).to_std_timepoint();
         const auto ocsp_status = Botan::PKIX::check_ocsp(cert_path, { ocsp }, { &certstore }, valid_time);

         if(result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1))
            {
            if(result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1))
               {
               result.confirm("Status warning", ocsp_status[0].count(Botan::Certificate_Status_Code::OCSP_NO_REVOCATION_URL) > 0);
               }
            }

         return result;
         }

#if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)
      Test::Result test_online_request()
         {
         Test::Result result("OCSP online check");

         // Expired end-entity certificate:
         std::shared_ptr<const Botan::X509_Certificate> ca = load_test_X509_cert("x509/ocsp/letsencrypt.pem");
         std::shared_ptr<const Botan::X509_Certificate> trust_root = load_test_X509_cert("x509/ocsp/identrust.pem");

         const std::vector<std::shared_ptr<const Botan::X509_Certificate>> cert_path = { ca, trust_root };

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         typedef std::chrono::system_clock Clock;
         const auto ocspTimeout = std::chrono::milliseconds(3000);
         auto ocsp_status = Botan::PKIX::check_ocsp_online(cert_path, { &certstore }, Clock::now(), ocspTimeout, false);

         if(result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1))
            {
            if(result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1))
               {
               const bool status_good = ocsp_status[0].count(Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD) > 0;
               const bool server_not_found = ocsp_status[0].count(Botan::Certificate_Status_Code::OCSP_SERVER_NOT_AVAILABLE) > 0;
               result.confirm("Expected status", status_good || server_not_found);
               }
            }

         return result;
         }
#endif

   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_request_encoding());
         results.push_back(test_response_parsing());
         results.push_back(test_response_certificate_access());
         results.push_back(test_response_verification_with_next_update_without_max_age());
         results.push_back(test_response_verification_with_next_update_with_max_age());
         results.push_back(test_response_verification_without_next_update_with_max_age());
         results.push_back(test_response_verification_without_next_update_without_max_age());
         results.push_back(test_response_verification_softfail());

#if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)
         if(Test::options().run_online_tests())
            {
            results.push_back(test_online_request());
            }
#endif

         return results;
         }
   };

BOTAN_REGISTER_TEST("x509", "ocsp", OCSP_Tests);

#endif

}
