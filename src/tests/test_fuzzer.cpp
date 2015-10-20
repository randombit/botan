/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <chrono>
#include <iostream>

#include <botan/internal/filesystem.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
#include <botan/x509cert.h>
#include <botan/x509_crl.h>
#include <botan/base64.h>
#endif

using namespace Botan;

namespace {

const std::string TEST_DATA_DIR_FUZZ_X509 = TEST_DATA_DIR "/fuzz/x509";

#if defined(BOTAN_HAS_X509_CERTIFICATES)
size_t test_x509_fuzz()
   {
   size_t fails = 0;
   size_t tests = 0;

   try
      {
      for(auto vec_file: get_files_recursive(TEST_DATA_DIR_FUZZ_X509))
         {
         ++tests;

         auto start = std::chrono::steady_clock::now();
         try
            {
            // TODO: check for memory consumption?
            X509_Certificate cert(vec_file);
            }
         catch(std::exception& e)
            {
            //std::cout << e.what() << "\n";
            }
         auto end = std::chrono::steady_clock::now();

         uint64_t duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

         if(duration > 100)
            {
            std::cout << "Fuzzer test " << vec_file << " took " << duration << " ms" << std::endl;
            }
         }

         test_report("Fuzzer checks", tests, fails);
      }
   catch(No_Filesystem_Access)
      {
      std::cout << "Warning: No filesystem access available to read test files in '"
                << TEST_DATA_DIR_FUZZ_X509 << "'" << std::endl;
      return 0;
      }

   return fails;
   }
#endif

}

size_t test_fuzzer()
   {
   size_t fails = 0;
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   fails += test_x509_fuzz();
#endif
   return fails;
   }
