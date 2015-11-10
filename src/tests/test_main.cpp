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

}

int main(int argc, char* argv[])
   {
   if(argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1])== "help"))
      {
      return help(std::cout, argv[0]);
      }

   std::vector<std::string> req(argv + 1, argv + argc);

   bool run_all = false;

   if(req.empty())
      {
      req = {"block", "stream", "hash", "mac", "modes", "aead", "kdf", "pbkdf", "hmac_drbg", "x931_rng"};
      run_all = true;
      }

   size_t failed = Botan_Tests::Test::run_tests(req, run_all, std::cout);

   if(failed)
      return 2;

   return 0;
   }
