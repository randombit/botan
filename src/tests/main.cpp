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
#include <deque>
#include <thread>
#include <future>

#include <botan/version.h>
#include <botan/auto_rng.h>
#include <botan/loadstor.h>

#if defined(BOTAN_HAS_HMAC_DRBG)
#include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
#include <botan/system_rng.h>
#endif

namespace {

using Botan_Tests::Test;

int help(std::ostream& out, const std::string binary_name)
   {
   std::ostringstream err;

   err << "Usage:\n"
       << binary_name << " test1 test2 ...\n"
       << "Available tests: ";

   for(auto&& test : Test::registered_tests())
      {
      err << test << " ";
      }

   out << err.str() << std::endl;
   return 1;
   }

std::string report_out(const std::vector<Test::Result>& results,
                       size_t& tests_failed,
                       size_t& tests_ran)
   {
   std::ostringstream out;

   std::map<std::string, Test::Result> combined;
   for(auto&& result : results)
      {
      const std::string who = result.who();
      auto i = combined.find(who);
      if(i == combined.end())
         {
         combined[who] = Test::Result(who);
         i = combined.find(who);
         }

      i->second.merge(result);
      }

   for(auto&& result : combined)
      {
      out << result.second.result_string();
      tests_failed += result.second.tests_failed();
      tests_ran += result.second.tests_run();
      }

   return out.str();
   }

size_t run_tests(const std::vector<std::string>& tests_to_run,
                 std::ostream& out,
                 size_t threads)
   {
   size_t tests_ran = 0, tests_failed = 0;

   if(threads <= 1)
      {
      for(auto&& test_name : tests_to_run)
         {
         std::vector<Test::Result> results = Test::run_test(test_name, false);
         out << report_out(results, tests_failed, tests_ran) << std::flush;
         }
      }
   else
      {

      /*
      We're not doing this in a particularly nice way, and variance in time is
      high so commonly we'll 'run dry' by blocking on the first future. But
      plain C++11 <thread> is missing a lot of tools we'd need (like
      wait_for_any on a set of futures) and there is no point pulling in an
      additional dependency just for this. In any case it helps somewhat
      (50-100% speedup) and provides a proof of concept for parallel testing.
      */

      typedef std::future<std::vector<Test::Result>> FutureResults;
      std::deque<FutureResults> fut_results;

      for(auto&& test_name : tests_to_run)
         {
         fut_results.push_back(std::async(std::launch::async,
                                          [test_name]() { return Test::run_test(test_name, false); }));

         while(fut_results.size() > threads)
            {
            out << report_out(fut_results[0].get(), tests_failed, tests_ran) << std::flush;
            fut_results.pop_front();
            }
         }

      while(fut_results.size() > 0)
         {
         out << report_out(fut_results[0].get(), tests_failed, tests_ran) << std::flush;
         fut_results.pop_front();
         }
      }

   out << "Tests complete ran " << tests_ran << " tests ";

   if(tests_failed > 0)
      {
      out << tests_failed << " tests failed";
      }
   else if(tests_ran > 0)
      {
      out << "all tests ok";
      }

   out << std::endl;

   return tests_failed;
   }

std::unique_ptr<Botan::RandomNumberGenerator>
setup_tests(std::ostream& out, size_t threads, size_t soak_level, bool log_success, std::string drbg_seed)
   {
   out << "Testing " << Botan::version_string() << "\n";
   out << "Starting tests";

   if(threads > 1)
      out << " threads:" << threads;

   out << " soak level:" << soak_level;

   std::unique_ptr<Botan::RandomNumberGenerator> rng;

#if defined(BOTAN_HAS_HMAC_DRBG)
   if(drbg_seed == "")
      {
      const uint64_t ts = Test::timestamp();
      std::vector<uint8_t> ts8(8);
      Botan::store_be(ts, ts8.data());
      drbg_seed = Botan::hex_encode(ts8);
      }

   out << " rng:HMAC_DRBG with seed '" << drbg_seed << "'";
   rng.reset(new Botan::Serialized_RNG(new Botan::HMAC_DRBG("HMAC(SHA-384)")));
   const std::vector<uint8_t> seed = Botan::hex_decode(drbg_seed);
   rng->add_entropy(seed.data(), seed.size());

#else

   if(drbg_seed != "")
      throw Botan_Tests::Test_Error("HMAC_DRBG disabled in build, cannot specify DRBG seed");

#if defined(BOTAN_HAS_SYSTEM_RNG)
   out << " rng:system";
   rng.reset(new Botan::System_RNG);
#else
   // AutoSeeded_RNG always available
   out << " rng:autoseeded";
   rng.reset(new Botan::Serialized_RNG(new Botan::AutoSeeded_RNG));
#endif

#endif

   out << std::endl;

   Botan_Tests::Test::setup_tests(soak_level, log_success, rng.get());

   return rng;
   }

int cpp_main(const std::vector<std::string> args)
   {
   try
      {
      if(args.size() == 2 && (args[1] == "--help" || args[1] == "help"))
         {
         return help(std::cout, args[0]);
         }

      size_t threads = 0;//std::thread::hardware_concurrency();
      size_t soak = 5;
      const std::string drbg_seed = "";
      bool log_success = false;

      std::vector<std::string> req(args.begin()+1, args.end());

      if(req.empty())
         {
         req = {"block", "stream", "hash", "mac", "modes", "aead", "kdf", "pbkdf", "hmac_drbg", "x931_rng", "util"};

         std::set<std::string> all_others = Botan_Tests::Test::registered_tests();

         for(auto f : req)
            all_others.erase(f);

         req.insert(req.end(), all_others.begin(), all_others.end());
         }

      std::unique_ptr<Botan::RandomNumberGenerator> rng =
         setup_tests(std::cout, threads, soak, log_success, drbg_seed);

      size_t failed = run_tests(req, std::cout, threads);

      if(failed)
         return 2;

      return 0;
      }
   catch(std::exception& e)
      {
      std::cout << "Exception caused test abort: " << e.what() << std::endl;
      return 3;
      }
   catch(...)
      {
      std::cout << "Unknown exception caused test abort" << std::endl;
      return 3;
      }
   }

}

int main(int argc, char* argv[])
   {
   std::vector<std::string> args(argv, argv + argc);
   return cpp_main(args);
   }
