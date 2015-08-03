/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/x509cert.h>
#include <botan/x509_crl.h>
#include <botan/internal/filesystem.h>
#include <botan/base64.h>
#include <chrono>
#include <iostream>

namespace {

size_t test_x509_fuzz()
   {
   const std::string fuzz_data = TEST_DATA_DIR "/fuzz";

   size_t tests = 0, fails = 0;

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
         std::cout << "Fuzz test " << vec << " took " << duration << " ms\n";
         }
      }

   test_report("Fuzz Checks", tests, fails);

   return fails;
   }

}

size_t test_fuzzer()
   {
   size_t fails = 0;
   fails += test_x509_fuzz();
   return fails;
   }
