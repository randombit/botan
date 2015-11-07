/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <iostream>
#include <sstream>
#include <string>
#include <set>

#define CATCH_CONFIG_RUNNER
#define CATCH_CONFIG_CONSOLE_WIDTH 60
#define CATCH_CONFIG_COLOUR_NONE
#include "catchy/catch.hpp"

namespace {

int help(std::ostream& out, char* argv0)
   {
   std::ostringstream err;

   err << "Usage:\n"
       << argv0 << " test1 test2 ...\n"
       << "Available tests: ";

   for(auto&& test : Botan_Tests::Test::registered_tests())
      {
      err << test << " ";
      }
   err << "\n";

   out << err.str();
   return 1;
   }

template<typename T, typename R>
bool vector_remove(std::vector<T>& v,  const R& r)
   {
   auto i = std::find(v.begin(), v.end(), r);

   if(i == v.end())
      return false;

   v.erase(i);
   return true;
   }

}

int main(int argc, char* argv[])
   {
   if(argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1])== "help"))
      {
      return help(std::cout, argv[0]);
      }

   std::vector<std::string> req(argv + 1, argv + argc);

   bool run_catch = false;
   bool run_all = false;

   if(req.empty())
      {
      req = {"block", "stream", "hash", "mac", "modes", "aead", "kdf", "pbkdf", "hmac_drbg", "x931_rng"};
      run_all = true;
      run_catch = true;
      }

   run_catch = run_catch || vector_remove(req, "catch");

   size_t failed = Botan_Tests::Test::run_tests(req, run_all, std::cout);

   if(run_catch)
      {
      std::cout << "CATCH unit test results:\n";
      failed += Catch::Session().run();
      }

   if(failed)
      return 2;

   return 0;
   }
