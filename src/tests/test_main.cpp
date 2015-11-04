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

int help(std::ostream& out, const std::set<std::string>& all_tests, char* argv0)
   {
   std::ostringstream err;

   err << "Usage:\n"
       << argv0 << " test1 test2 ...\n"
       << "Available tests: ";

   for(auto&& test : all_tests)
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
   const std::set<std::string> all_tests = Botan_Tests::Test::registered_tests();

   std::set<std::string> req(argv + 1, argv + argc);

   if(req.count("help") || req.count("--help") || req.count("-h"))
      {
      return help(std::cout, all_tests, argv[0]);
      }

   if(req.empty())
      {
      req = all_tests;
      }

   const size_t failed = Botan_Tests::Test::run_tests(req, std::cout);

   std::cout << "Botan test suite complete ";

   if(failed)
      {
      std::cout << failed << " tests failed\n";
      }
   else
      {
      std::cout << "all tests ok\n";
      }

   if(failed)
      return 2;
   return 0;
   }
