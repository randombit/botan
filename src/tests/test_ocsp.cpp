/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_OCSP)
  #include <botan/ocsp.h>
  #include <sstream>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_OCSP)

class OCSP_Tests : public Test
   {
   private:
      std::vector<byte> slurp_data_file(const std::string& path)
         {
         const std::string fsname = Test::data_file(path);
         std::ifstream file(fsname.c_str());
         if(!file.good())
            throw Test_Error("Error reading from " + fsname);

         std::vector<byte> contents;

         while(file.good())
            {
            std::vector<byte> buf(4096);
            file.read(reinterpret_cast<char*>(buf.data()), buf.size());
            size_t got = file.gcount();

            if(got == 0 && file.eof())
               break;

            contents.insert(contents.end(), buf.data(), buf.data() + got);
            }

         return contents;
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
         Test::Result result("OCSP encoding");

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

   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_request_encoding());
         results.push_back(test_response_parsing());

         return results;
         }
   };

BOTAN_REGISTER_TEST("ocsp", OCSP_Tests);

#endif

}
