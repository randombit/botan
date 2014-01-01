/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
 * Test Driver for Botan
 */

#include <vector>
#include <string>

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>

#include <botan/botan.h>
#include <botan/libstate.h>

#if defined(BOTAN_HAS_DYNAMICALLY_LOADED_ENGINE)
  #include <botan/dyn_engine.h>
#endif

using namespace Botan;

#include "getopt.h"
#include "bench.h"
#include "common.h"
#include "tests.h"

namespace {

template<typename T>
bool test(const char* type, int digits, bool is_signed)
   {
   if(std::numeric_limits<T>::is_specialized == false)
      {
      std::cout << "Warning: Could not check parameters of " << type
                << " in std::numeric_limits" << std::endl;

      // assume it's OK (full tests will catch it later)
      return true;
      }

   // continue checking after failures
   bool passed = true;

   if(std::numeric_limits<T>::is_integer == false)
      {
      std::cout << "Warning: std::numeric_limits<> says " << type
                << " is not an integer" << std::endl;
      passed = false;
      }

   if(std::numeric_limits<T>::is_signed != is_signed)
      {
      std::cout << "Warning: numeric_limits<" << type << ">::is_signed == "
                << std::boolalpha << std::numeric_limits<T>::is_signed
                << std::endl;
      passed = false;
      }

   if(std::numeric_limits<T>::digits != digits && digits != 0)
      {
      std::cout << "Warning: numeric_limits<" << type << ">::digits == "
                << std::numeric_limits<T>::digits
                << " expected " << digits << std::endl;
      passed = false;
      }

   return passed;
   }

void test_types()
   {
   bool passed = true;

   passed = passed && test<Botan::byte  >("byte",    8, false);
   passed = passed && test<Botan::u16bit>("u16bit", 16, false);
   passed = passed && test<Botan::u32bit>("u32bit", 32, false);
   passed = passed && test<Botan::u64bit>("u64bit", 64, false);
   passed = passed && test<Botan::s32bit>("s32bit", 31,  true);

   if(!passed)
      std::cout << "Typedefs in include/types.h may be incorrect!\n";
   }

int run_tests()
   {
   size_t errors = 0;

   try
      {
      errors += run_all_tests();
      }
   catch(std::exception& e)
      {
      std::cout << "Exception in test suite " << e.what() << std::endl;
      ++errors;
      }
   catch(...)
      {
      std::cout << "Unknown exception caught\n";
      ++errors;
      }

   if(errors)
      {
      std::cout << errors << " test failures\n";
      return 1;
      }

   return 0;
   }

}

int main(int argc, char* argv[])
   {
   if(BOTAN_VERSION_MAJOR != version_major() ||
      BOTAN_VERSION_MINOR != version_minor() ||
      BOTAN_VERSION_PATCH != version_patch())
      {
      std::cout << "Warning: linked version ("
                << version_major() << '.'
                << version_minor() << '.'
                << version_patch()
                << ") does not match version built against ("
                << BOTAN_VERSION_MAJOR << '.'
                << BOTAN_VERSION_MINOR << '.'
                << BOTAN_VERSION_PATCH << ")\n";
      }

   try
      {
      OptionParser opts("help|test|validate|"
                        "algo=|seconds=|buf-size=");
      opts.parse(argv);

      test_types(); // do this always

      Botan::LibraryInitializer init;

      if(opts.is_set("help") || argc < 2)
         {
         std::cout << "Commands: test version time\n";
         return 1;
         }

      const std::string cmd = argv[1];

      if(cmd == "version")
         {
         std::cout << Botan::version_string() << "\n";
         return 0;
         }

      if(cmd == "test")
         {
         return run_tests();
         }

      if(cmd == "speed")
         {
         double seconds = 5;
         u32bit buf_size = 16;

         if(opts.is_set("seconds"))
            {
            seconds = std::atof(opts.value("seconds").c_str());
            if(seconds < 0.1 || seconds > (5 * 60))
               {
               std::cout << "Invalid argument to --seconds\n";
               return 2;
               }
            }

         if(opts.is_set("buf-size"))
            {
            buf_size = std::atoi(opts.value("buf-size").c_str());
            if(buf_size == 0 || buf_size > 1024)
               {
               std::cout << "Invalid argument to --buf-size\n";
               return 2;
               }
            }

         if(opts.is_set("--algo"))
            {
            AutoSeeded_RNG rng;
            for(auto alg: Botan::split_on(opts.value("algo"), ','))
               bench_algo(alg, rng, seconds, buf_size);
            }
         /*
         else
            benchmark(seconds, buf_size);
         */
         }
      }
   catch(std::exception& e)
      {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
      }
   catch(...)
      {
      std::cerr << "Unknown (...) exception caught" << std::endl;
      return 1;
      }

   return 0;
   }

