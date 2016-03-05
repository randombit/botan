/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <chrono>
#include <botan/internal/filesystem.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
  #include <botan/x509cert.h>
  #include <botan/x509_crl.h>
  #include <botan/base64.h>
#endif

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
  #include <botan/pkcs8.h>
#endif

namespace Botan_Tests {

namespace {

class Fuzzer_Input_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;
#if defined(BOTAN_HAS_X509_CERTIFICATES)
         results.push_back(test_x509_fuzz());
#endif

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
         results.push_back(test_pkcs8());
#endif
         return results;
         }

   private:

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
      Test::Result test_pkcs8()
         {
         std::vector<std::string> files;

         Test::Result result("PKCS #8 fuzzing");

         try
            {
            files = Botan::get_files_recursive(Test::data_dir() + "/fuzz/pkcs8");
            }
         catch(Botan::No_Filesystem_Access)
            {
            result.note_missing("Filesystem readdir wrapper not implemented");
            return result;
            }

         for(auto vec_file: files)
            {
            try
               {
               std::unique_ptr<Botan::Private_Key> key(
                  Botan::PKCS8::load_key(vec_file, Test::rng()));
               }
            catch(std::exception&) {}

            result.test_success();
            }

         return result;
         }
#endif

#if defined(BOTAN_HAS_X509_CERTIFICATES)
      Test::Result test_x509_fuzz()
         {
         Test::Result result("X.509 fuzzing");

         std::vector<std::string> files;

         try
            {
            files = Botan::get_files_recursive(Test::data_dir() + "/fuzz/x509");
            }
         catch(Botan::No_Filesystem_Access)
            {
            result.note_missing("Filesystem access");
            return result;
            }

         for(auto vec_file: files)
            {
            auto start = std::chrono::steady_clock::now();

            try
               {
               // TODO: check for memory consumption?
               Botan::X509_Certificate cert(vec_file);
               }
            catch(std::exception&)
               {
               }

            result.test_success();

            auto end = std::chrono::steady_clock::now();

            uint64_t duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

            if(duration > 100)
               {
               result.test_note("Fuzzer test " + vec_file + " took " + std::to_string(duration) + " ms");
               }
            }

         return result;
         }
#endif
   };

BOTAN_REGISTER_TEST("fuzzer", Fuzzer_Input_Tests);


}

}
