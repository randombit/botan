/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <chrono>
#include <iostream>

#if defined(BOTAN_HAS_X509_CERTIFICATES)

#include <botan/x509cert.h>
#include <botan/x509_crl.h>
#include <botan/internal/filesystem.h>
#include <botan/base64.h>

#endif

namespace {

size_t test_x509_fuzz()
   {
   size_t fails = 0;

#if defined(BOTAN_HAS_X509_CERTIFICATES)

   size_t tests = 0;
   const std::string fuzz_data = TEST_DATA_DIR "/fuzz";

   for(auto vec: Botan::get_files_recursive(fuzz_data + "/x509"))
      {
      ++tests;

      auto start = std::chrono::system_clock::now();
      try
         {
         // TODO: check for memory consumption?
         Botan::X509_Certificate cert(vec);
         }
      catch(std::exception& e)
         {
         //std::cout << e.what() << "\n";
         }
      auto end = std::chrono::system_clock::now();

      uint64_t duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

      if(duration > 100)
         {
         std::cout << "Fuzzer test " << vec << " took " << duration << " ms" << std::endl;
         }
      }

   test_report("Fuzzer checks", tests, fails);
#endif

   return fails;
   }

}

size_t test_fuzzer()
   {
   size_t fails = 0;
   fails += test_x509_fuzz();
   return fails;
   }
