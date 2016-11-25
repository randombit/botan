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
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_OCSP)

class OCSP_Tests : public Test
   {
   private:
      std::vector<uint8_t> slurp_data_file(const std::string& path)
         {
         const std::string fsname = Test::data_file(path);
         std::ifstream file(fsname.c_str(), std::ios::binary);
         if(!file.good())
            throw Test_Error("Error reading from " + fsname);

         std::vector<uint8_t> contents;

         while(file.good())
            {
            std::vector<uint8_t> buf(4096);
            file.read(reinterpret_cast<char*>(buf.data()), buf.size());
            size_t got = file.gcount();

            if(got == 0 && file.eof())
               break;

            contents.insert(contents.end(), buf.data(), buf.data() + got);
            }

         return contents;
         }

      std::shared_ptr<const Botan::X509_Certificate> load_test_X509_cert(const std::string& path)
         {
         return std::make_shared<const Botan::X509_Certificate>(Test::data_file(path));
         }

      std::shared_ptr<const Botan::OCSP::Response> load_test_OCSP_resp(const std::string& path)
         {
         return std::make_shared<const Botan::OCSP::Response>(slurp_data_file(path));
         }

      Test::Result test_response_parsing()
         {
         Test::Result result("OCSP response parsing");

         // Simple parsing tests
         const std::vector<std::string> ocsp_input_paths = {
            "ocsp/resp1.der",
            "ocsp/resp2.der",
            "ocsp/resp3.der"
         };

         for(std::string ocsp_input_path : ocsp_input_paths)
            {
            try
               {
               Botan::OCSP::Response resp(slurp_data_file(ocsp_input_path));
               result.test_success("Parsed input " + ocsp_input_path);
               }
            catch(Botan::Exception& e)
               {
               result.test_failure("Parsing failed", e.what());
               }
            }

         return result;
         }

      Test::Result test_request_encoding()
         {
         Test::Result result("OCSP request encoding");

         const Botan::X509_Certificate end_entity(Test::data_file("ocsp/gmail.pem"));
         const Botan::X509_Certificate issuer(Test::data_file("ocsp/google_g2.pem"));

         try
            {
            const Botan::OCSP::Request bogus(end_entity, issuer);
            result.test_failure("Bad arguments (swapped end entity, issuer) accepted");
            }
         catch(Botan::Invalid_Argument&)
            {
            result.test_success("Bad arguments rejected");
            }

         const Botan::OCSP::Request req(issuer, end_entity);
         const std::string expected_request = "ME4wTKADAgEAMEUwQzBBMAkGBSsOAwIaBQAEFPLgavmFih2NcJtJGSN6qbUaKH5kBBRK3QYWG7z2aLV29YG2u2IaulqBLwIIQkg+DF+RYMY=";

         result.test_eq("Encoded OCSP request",
                        req.base64_encode(),
                        expected_request);

         return result;
         }

      Test::Result test_response_verification()
         {
         Test::Result result("OCSP request check");

         std::shared_ptr<const Botan::X509_Certificate> ee = load_test_X509_cert("ocsp/randombit.pem");
         std::shared_ptr<const Botan::X509_Certificate> ca = load_test_X509_cert("ocsp/letsencrypt.pem");
         std::shared_ptr<const Botan::X509_Certificate> trust_root = load_test_X509_cert("ocsp/geotrust.pem");

         const std::vector<std::shared_ptr<const Botan::X509_Certificate>> cert_path = { ee, ca, trust_root };

         std::shared_ptr<const Botan::OCSP::Response> ocsp = load_test_OCSP_resp("ocsp/randombit_ocsp.der");

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         // Some arbitrary time within the validity period of the test certs
         const auto valid_time = Botan::calendar_point(2016,11,20,8,30,0).to_std_timepoint();

         std::vector<std::set<Botan::Certificate_Status_Code>> ocsp_status = Botan::PKIX::check_ocsp(
            cert_path,
            { ocsp },
            { &certstore },
            valid_time);

         if(result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 1))
            {
            if(result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1))
               {
               result.confirm("Status good", ocsp_status[0].count(Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD));
               }
            }

         return result;
         }

#if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)
      Test::Result test_online_request()
         {
         Test::Result result("OCSP online check");

         std::shared_ptr<const Botan::X509_Certificate> ee = load_test_X509_cert("ocsp/randombit.pem");
         std::shared_ptr<const Botan::X509_Certificate> ca = load_test_X509_cert("ocsp/letsencrypt.pem");
         std::shared_ptr<const Botan::X509_Certificate> trust_root = load_test_X509_cert("ocsp/identrust.pem");

         const std::vector<std::shared_ptr<const Botan::X509_Certificate>> cert_path = { ee, ca, trust_root };

         Botan::Certificate_Store_In_Memory certstore;
         certstore.add_certificate(trust_root);

         std::vector<std::set<Botan::Certificate_Status_Code>> ocsp_status = Botan::PKIX::check_ocsp_online(
            cert_path,
            { &certstore },
            std::chrono::system_clock::now(),
            std::chrono::milliseconds(3000),
            true);

         if(result.test_eq("Expected size of ocsp_status", ocsp_status.size(), 2))
            {
            if(result.test_eq("Expected size of ocsp_status[0]", ocsp_status[0].size(), 1))
               {
               result.confirm("Status good", ocsp_status[0].count(Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD));
               }
            if(result.test_eq("Expected size of ocsp_status[1]", ocsp_status[1].size(), 1))
               {
               result.confirm("Status good", ocsp_status[1].count(Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD));
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
         results.push_back(test_response_verification());

#if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)
         if(Test::run_online_tests())
            results.push_back(test_online_request());
#endif

         return results;
         }
   };

BOTAN_REGISTER_TEST("ocsp", OCSP_Tests);

#endif

}
